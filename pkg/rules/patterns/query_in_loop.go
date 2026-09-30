package patterns

import (
	"go/ast"
	"go/types"
	"path/filepath"
	"regexp"
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
	helpers := queryHelpers(ctx, reach)
	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(file *core.FileContext, info *types.Info) []*core.Violation {
		return r.analyzeFile(file, info, reach, helpers)
	})
}

// queryHelpers maps the functions of the project that read through a
// data-access call themselves (outside a function literal) to that call,
// "repo.Get". A loop calling one of them from its own package queries on
// every iteration as much as a loop calling the repository. A helper that
// only writes is left out: storing each item's own result (a pipeline
// persisting what it fetched) is no read to batch.
func queryHelpers(ctx *core.GoProjectContext, reach storageReach) map[*types.Func]queryHelper {
	helpers := make(map[*types.Func]queryHelper)
	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil || pkg.Package.TypesInfo == nil {
			continue
		}
		info := pkg.Package.TypesInfo
		for _, file := range pkg.Files {
			if file.GoAST == nil || file.IsTestFile() {
				continue
			}
			for _, decl := range file.GoAST.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				obj, ok := info.Defs[fn.Name].(*types.Func)
				if !ok {
					continue
				}
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					if _, nested := n.(*ast.FuncLit); nested || helpers[obj].call != "" {
						return false
					}
					if call, ok := n.(*ast.CallExpr); ok {
						if recv, method, ok := dataAccessCall(call, info, reach); ok && readMethod.MatchString(method) {
							helpers[obj] = queryHelper{call: recv + "." + method, dir: filepath.Dir(file.Path)}
						}
					}
					return true
				})
			}
		}
	}
	return helpers
}

var readMethod = regexp.MustCompile(`^(?:Get|Find|List|Load|Select|Query|Count|Read|Lookup|Search|Exists|Sum)`)

// queryHelper is a function making a data-access call: the call, and the
// directory of the file declaring the function.
type queryHelper struct {
	call, dir string
}

// calledFunc returns the function or method a call names, nil for a call
// through a value (a func variable, an interface).
func calledFunc(call *ast.CallExpr, info *types.Info) *types.Func {
	var id *ast.Ident
	switch fun := ast.Unparen(call.Fun).(type) {
	case *ast.Ident:
		id = fun
	case *ast.SelectorExpr:
		id = fun.Sel
	default:
		return nil
	}
	fn, _ := info.Uses[id].(*types.Func)
	if fn == nil {
		return nil
	}
	if sig, ok := fn.Type().(*types.Signature); ok && sig.Recv() != nil && types.IsInterface(sig.Recv().Type()) {
		return nil
	}
	return fn
}

// analyzeFile walks loops and flags data-access calls directly inside them.
func (r *QueryInLoopRule) analyzeFile(ctx *core.FileContext, info *types.Info, reach storageReach, helpers map[*types.Func]queryHelper) []*core.Violation {
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
			if node.Cond == nil || retryLoop(node.Init, node.Cond) {
				// A worker's loop, a page walk, the attempts of one
				// operation: not one query per item.
				visitNestedLoops(node.Body, inspect)
				return false
			}
			loopDepth++
			for _, part := range []ast.Node{node.Cond, node.Post, node.Body} {
				visitLoopPart(part, inspect)
			}
			loopDepth--
			return false

		case *ast.RangeStmt:
			// The range operand is evaluated once; only the body repeats.
			visitLoopPart(node.X, inspect)
			if _, events := types.Unalias(typeUnder(info, node.X)).(*types.Chan); events {
				// A worker taking events or ticks: one query per event.
				visitNestedLoops(node.Body, inspect)
				return false
			}
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
				} else if fn := calledFunc(node, info); fn != nil && helpers[fn].dir == filepath.Dir(ctx.Path) {
					line := lineFromNode(ctx, node)
					v := r.CreateViolation(ctx.RelPath, line,
						"call to '"+fn.Name()+"' inside loop — it queries through '"+helpers[fn].call+"' on every iteration (N+1)")
					v.WithCode(ctx.GetLine(line))
					v.WithSuggestion("Load what the helper reads in one batch query before the loop and pass it in, or cache per-request")
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

// visitNestedLoops runs inspect over the loops inside a body that is not
// itself a loop over items.
func visitNestedLoops(body ast.Node, inspect func(ast.Node) bool) {
	visitLoopPart(body, func(n ast.Node) bool {
		switch n.(type) {
		case *ast.ForStmt, *ast.RangeStmt:
			return inspect(n)
		}
		return true
	})
}

// typeUnder returns the underlying type of an expression, nil without type
// information.
func typeUnder(info *types.Info, expr ast.Expr) types.Type {
	if info == nil {
		return nil
	}
	if t := info.TypeOf(expr); t != nil {
		return t.Underlying()
	}
	return nil
}

var retryCounter = regexp.MustCompile(`(?i)attempt|retr|tries`)

// retryLoop reports a loop counting attempts: its init or condition names
// a variable or a limit like attempt, retry, maxTries.
func retryLoop(init ast.Stmt, cond ast.Expr) bool {
	found := false
	for _, part := range []ast.Node{init, cond} {
		if part == nil {
			continue
		}
		ast.Inspect(part, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok && retryCounter.MatchString(id.Name) {
				found = true
			}
			return !found
		})
	}
	return found
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
	if pureRepositoryFunc(sel, info) {
		return "", "", false
	}
	return recvName, method, true
}

// pureRepositoryFunc reports a package-level function of a repository
// package that takes neither a context nor a database handle - an error
// classifier, a key builder: it has nothing to query with.
func pureRepositoryFunc(sel *ast.SelectorExpr, info *types.Info) bool {
	if info == nil {
		return false
	}
	if _, isPkg := info.Uses[identOf(sel.X)].(*types.PkgName); !isPkg {
		return false
	}
	fn, ok := info.Uses[sel.Sel].(*types.Func)
	if !ok {
		return false
	}
	sig, ok := fn.Type().(*types.Signature)
	if !ok {
		return false
	}
	params := sig.Params()
	for i := range params.Len() {
		switch t := types.Unalias(params.At(i).Type()).(type) {
		case *types.Named:
			if name := t.Obj().Name(); name == "Context" || strings.HasSuffix(name, "DB") || strings.HasSuffix(name, "Tx") || name == "Conn" || name == "Pool" {
				return false
			}
		case *types.Pointer, *types.Interface:
			return false
		}
	}
	return true
}

// identOf returns the identifier an expression is, nil otherwise.
func identOf(expr ast.Expr) *ast.Ident {
	id, _ := expr.(*ast.Ident)
	return id
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
