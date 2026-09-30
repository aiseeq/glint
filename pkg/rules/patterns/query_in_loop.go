package patterns

import (
	"go/ast"
	"go/types"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewQueryInLoopRule())
}

// isDataAccessReceiver распознаёт имена receiver'ов, почти всегда означающих доступ к БД
// (поля/переменные-репозитории/БД). Вызов их методов в цикле — классический N+1.
// Точные короткие имена + camelCase-суффиксы; ctx исключён явно (чтобы ctx.Done/Err не ловить).
func isDataAccessReceiver(name string) bool {
	if name == "" {
		return false
	}
	lower := strings.ToLower(name)
	if lower == "ctx" {
		return false
	}
	switch lower { // короткие well-known data-access переменные
	case "db", "dbx", "repo", "store", "dao", "querier":
		return true
	}
	for _, suf := range []string{"repository", "repo", "store", "dao", "querier"} {
		if strings.HasSuffix(lower, suf) { // userRepo, txReqRepo, walletStore, fooRepository
			return true
		}
	}
	// *DB / *Db поля (camelCase-граница), напр. ledgerDB — но не случайные слова на "db".
	if strings.HasSuffix(name, "DB") || strings.HasSuffix(name, "Db") {
		return true
	}
	return false
}

// storagePackages are the packages a database or remote store is reached
// through. "net" stands for every networked client (pgx, Redis, Mongo, HTTP APIs
// all dial through it); database/sql covers the SQL drivers and the ORMs built
// on it. The client modules are listed as well because a dependency is loaded
// from export data, whose import list may omit packages its API never mentions.
var storagePackages = []string{
	"database/sql",
	"net",
	"github.com/jackc/pgx",
	"github.com/lib/pq",
	"gorm.io/gorm",
	"github.com/jmoiron/sqlx",
	"go.mongodb.org/mongo-driver",
	"github.com/redis/go-redis",
	"go.etcd.io/bbolt",
	"github.com/dgraph-io/badger",
}

func isStoragePackage(path string) bool {
	for _, root := range storagePackages {
		if path == root || strings.HasPrefix(path, root+"/") {
			return true
		}
	}
	return false
}

// storageReach answers, once per package, whether the package can reach a
// storage client through its imports.
type storageReach map[*types.Package]bool

func (reach storageReach) reaches(pkg *types.Package) bool {
	if known, ok := reach[pkg]; ok {
		return known
	}
	reach[pkg] = false // import graphs are acyclic; this only guards the walk
	result := isStoragePackage(pkg.Path())
	for _, imported := range pkg.Imports() {
		if result {
			break
		}
		result = reach.reaches(imported)
	}
	reach[pkg] = result
	return result
}

// QueryInLoopRule detects repository/DB method calls inside loops (N+1 query anti-pattern).
// Per-iteration SQL calls in a list endpoint turned one request into thousands of
// round-trips and seconds of latency.
//
// A receiver is a candidate by its name (repo, store, db, …). The name is not
// enough on its own: a git repository wrapper is a "repo" and an in-memory map is
// a "store". When the receiver's type is concrete, the call is reported only if
// the package that defines the type can reach a storage client (database/sql, a
// network client) through its imports. An interface keeps the name heuristic: its
// implementation is not known at the call site.
type QueryInLoopRule struct {
	*rules.BaseRule
}

// NewQueryInLoopRule creates the rule.
func NewQueryInLoopRule() *QueryInLoopRule {
	return &QueryInLoopRule{
		BaseRule: rules.NewBaseRule(
			"query-in-loop",
			"patterns",
			"Detects repository/DB method calls inside loops (N+1 query anti-pattern)",
			core.SeverityMedium,
		),
	}
}

// AnalyzeFile is a no-op: whether a "repo" talks to a database is a question
// about its type, answered in AnalyzeGoProject.
func (r *QueryInLoopRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *QueryInLoopRule) RequiresSSA() bool { return false }

// AnalyzeGoProject walks the loops of every loaded file.
func (r *QueryInLoopRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	reach := storageReach{}
	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(file *core.FileContext, info *types.Info) []*core.Violation {
		return r.analyzeFile(file, info, reach)
	})
}

// analyzeFile walks loops and flags data-access calls directly inside them.
func (r *QueryInLoopRule) analyzeFile(ctx *core.FileContext, info *types.Info, reach storageReach) []*core.Violation {
	var violations []*core.Violation
	loopDepth := 0
	currentFunc := ""

	var inspect func(n ast.Node) bool
	inspect = func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncDecl:
			prevFunc := currentFunc
			currentFunc = node.Name.Name
			if node.Body != nil {
				ast.Inspect(node.Body, func(child ast.Node) bool {
					return inspect(child)
				})
			}
			currentFunc = prevFunc
			return false

		case *ast.ForStmt:
			// Init runs once, before the first iteration; Cond, Post and
			// Body run on every iteration.
			visitLoopPart(node.Init, inspect)
			loopDepth++
			for _, part := range []ast.Node{node.Cond, node.Post, node.Body} {
				visitLoopPart(part, inspect)
			}
			loopDepth--
			return false

		case *ast.RangeStmt:
			// The range operand is evaluated once; only the body repeats.
			visitLoopPart(node.X, inspect)
			loopDepth++
			visitLoopPart(node.Body, inspect)
			loopDepth--
			return false

		case *ast.CallExpr:
			if loopDepth > 0 {
				if recv, method, ok := dataAccessCall(node, info, reach); ok {
					line := lineFromNode(ctx, node)
					v := r.CreateViolation(ctx.RelPath, line,
						"data-access call '"+recv+"."+method+"' inside loop — likely N+1 (one DB round-trip per iteration)")
					v.WithCode(ctx.GetLine(line))
					v.WithSuggestion("Load data in a single batch query before the loop (e.g. WHERE id IN (...) / one query + in-memory join), or cache per-request")
					v.WithContext("pattern", "query_in_loop")
					if currentFunc != "" {
						v.WithContext("function", currentFunc)
					}
					violations = append(violations, v)
				}
			}

		case *ast.FuncLit:
			return false
		}
		return true
	}

	ast.Inspect(ctx.GoAST, inspect)
	return violations
}

// visitLoopPart runs inspect over one part of a loop statement. A nested
// function literal has its own scope: calls there may run async or batched.
func visitLoopPart(part ast.Node, inspect func(ast.Node) bool) {
	if part == nil {
		return
	}
	ast.Inspect(part, func(child ast.Node) bool {
		if _, ok := child.(*ast.FuncLit); ok {
			return false
		}
		return inspect(child)
	})
}

// dataAccessCall returns (receiver, method, true) if call is recv.Method(...) where recv looks
// like a data-access object (field или переменная-репозиторий/БД). Извлекает имя ближайшего
// receiver'а: для s.repo.Get → "repo", для groupRepo.List → "groupRepo".
func dataAccessCall(call *ast.CallExpr, info *types.Info, reach storageReach) (string, string, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return "", "", false
	}
	method := sel.Sel.Name
	recvName := ""
	switch x := sel.X.(type) {
	case *ast.Ident: // groupRepo.List(...)
		recvName = x.Name
	case *ast.SelectorExpr: // s.repo.Get(...) → ближайшее поле "repo"
		recvName = x.Sel.Name
	default:
		return "", "", false
	}
	if !isDataAccessReceiver(recvName) {
		return "", "", false
	}
	if pkg, ok := concreteReceiverPackage(sel.X, info); ok && !reach.reaches(pkg) {
		return "", "", false
	}
	return recvName, method, true
}

// concreteReceiverPackage returns the package whose code runs for a call on
// expr: the package defining expr's concrete named type, or the imported
// package when expr names one. ok is false when that code is not known at the
// call site - an interface, a type parameter, or no type information.
func concreteReceiverPackage(expr ast.Expr, info *types.Info) (*types.Package, bool) {
	if info == nil {
		return nil, false
	}
	if ident, isIdent := expr.(*ast.Ident); isIdent {
		if pkgName, isPkg := info.Uses[ident].(*types.PkgName); isPkg {
			return pkgName.Imported(), true
		}
	}
	t := info.TypeOf(expr)
	for t != nil {
		switch v := types.Unalias(t).(type) {
		case *types.Pointer:
			t = v.Elem()
		case *types.Named:
			if types.IsInterface(v) || v.Obj().Pkg() == nil {
				return nil, false
			}
			return v.Obj().Pkg(), true
		default:
			return nil, false
		}
	}
	return nil, false
}

// lineFromNode resolves a node's source line through the file set. Counting
// newlines in ctx.Content instead was wrong as soon as several files shared a
// file set: positions are offsets into the set, not into one file.
func lineFromNode(ctx *core.FileContext, node ast.Node) int {
	return ctx.LineFor(node)
}
