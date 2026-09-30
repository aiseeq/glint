package patterns

import (
	"go/ast"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewPerKeyMutexMapRule())
}

// PerKeyMutexMapRule detects a map of mutexes by key serializing the
// operations on one entity in a package that talks to a database:
//
//	var userLocks = make(map[string]*sync.Mutex)
//
//	lock := userLock(req.UserID)
//	lock.Lock()
//	defer lock.Unlock()
//	balance, err := s.repo.Balance(ctx, req.UserID)
//
// The lock holds inside one process only: a second instance, a worker or a
// restart runs the same operation on the same user at once, and the check
// before the write passes twice. The map also keeps a mutex for every key
// it ever saw. The database is what the processes share: lock the row
// (SELECT ... FOR UPDATE) or take an advisory lock.
type PerKeyMutexMapRule struct {
	*rules.BaseRule
}

// NewPerKeyMutexMapRule creates the rule
func NewPerKeyMutexMapRule() *PerKeyMutexMapRule {
	return &PerKeyMutexMapRule{BaseRule: rules.NewBaseRule(
		"per-key-mutex-map",
		"patterns",
		"Detects a map of mutexes by key guarding database operations — the lock holds in one process only",
		core.SeverityMedium,
	)}
}

// AnalyzeFile reports the mutex maps of a file that also queries a database.
func (r *PerKeyMutexMapRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !productionGoFile(ctx) || !queriesDatabase(ctx.GoAST) {
		return nil
	}
	var violations []*core.Violation
	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		mapType, ok := n.(*ast.MapType)
		if !ok || !isSyncMutexExpr(mapType.Value) {
			return true
		}
		line := ctx.LineFor(mapType)
		if ctx.IsSuppressed(line, r.Name()) {
			return true
		}
		v := r.CreateViolation(ctx.RelPath, line, "Map of mutexes by key guards database operations — the lock holds in this process only, another instance or a worker runs the same operation at once")
		v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
		v.WithSuggestion("Lock in the database the processes share: SELECT ... FOR UPDATE on the entity's row, or pg_advisory_xact_lock on its key")
		violations = append(violations, v)
		return true
	})
	return violations
}

// isSyncMutexExpr reports sync.Mutex, sync.RWMutex or a pointer to one.
func isSyncMutexExpr(expr ast.Expr) bool {
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = star.X
	}
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "sync" && (sel.Sel.Name == "Mutex" || sel.Sel.Name == "RWMutex")
}

// queriesDatabase reports a file passing SQL text or calling a
// repository: the operations its locks guard reach a database.
func queriesDatabase(file *ast.File) bool {
	if len(sqlCalls(file)) > 0 {
		return true
	}
	found := false
	ast.Inspect(file, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return !found
		}
		if inner, ok := sel.X.(*ast.SelectorExpr); ok && strings.Contains(strings.ToLower(inner.Sel.Name), "repo") {
			found = true
		}
		return !found
	})
	return found
}
