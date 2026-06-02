package patterns

import (
	"go/ast"
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

// QueryInLoopRule detects repository/DB method calls inside loops (N+1 query anti-pattern).
// Это правило родилось из SI-312: per-итерационные SQL-вызовы (config_timeline.Resolve,
// GetNetFundTransfersToVault) давали ~9000 запросов и 9.5s на список клиентов.
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

// AnalyzeFile walks loops and flags data-access calls directly inside them.
func (r *QueryInLoopRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || ctx.IsTestFile() || ctx.GoAST == nil {
		return nil
	}

	var violations []*core.Violation
	loopDepth := 0

	var inspect func(n ast.Node) bool
	inspect = func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.ForStmt, *ast.RangeStmt:
			loopDepth++
			ast.Inspect(n, func(child ast.Node) bool {
				if child == n {
					return true
				}
				if _, ok := child.(*ast.FuncLit); ok {
					return false // nested func has its own scope; calls there may run async/batched
				}
				return inspect(child)
			})
			loopDepth--
			return false

		case *ast.CallExpr:
			if loopDepth > 0 {
				if recv, method, ok := dataAccessCall(node); ok {
					line := lineFromNode(ctx, node)
					v := r.CreateViolation(ctx.RelPath, line,
						"data-access call '"+recv+"."+method+"' inside loop — likely N+1 (one DB round-trip per iteration)")
					v.WithCode(ctx.GetLine(line))
					v.WithSuggestion("Load data in a single batch query before the loop (e.g. WHERE id IN (...) / one query + in-memory join), or cache per-request")
					v.WithContext("pattern", "query_in_loop")
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

// dataAccessCall returns (receiver, method, true) if call is recv.Method(...) where recv looks
// like a data-access object (field или переменная-репозиторий/БД). Извлекает имя ближайшего
// receiver'а: для s.repo.Get → "repo", для groupRepo.List → "groupRepo".
func dataAccessCall(call *ast.CallExpr) (string, string, bool) {
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
	return recvName, method, true
}

func lineFromNode(ctx *core.FileContext, node ast.Node) int {
	if node == nil {
		return 1
	}
	offset := int(node.Pos()) - 1
	if offset < 0 || offset >= len(ctx.Content) {
		return 1
	}
	line := 1
	for i := 0; i < offset; i++ {
		if ctx.Content[i] == '\n' {
			line++
		}
	}
	return line
}
