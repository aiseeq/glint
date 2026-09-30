package patterns

import (
	"go/ast"
	"go/types"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewMutexLockRule())
}

// MutexLockRule detects mutex Lock() without corresponding Unlock()
type MutexLockRule struct {
	*rules.BaseRule
}

// NewMutexLockRule creates the rule
func NewMutexLockRule() *MutexLockRule {
	return &MutexLockRule{
		BaseRule: rules.NewBaseRule(
			"mutex-lock",
			"patterns",
			"Detects mutex Lock() without corresponding Unlock() (potential deadlock)",
			core.SeverityHigh,
		),
	}
}

// AnalyzeFile checks one file without type information: Lock/Unlock are
// recognized by name.
func (r *MutexLockRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	return r.analyze(ctx, nil)
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *MutexLockRule) RequiresSSA() bool { return false }

// AnalyzeGoProject checks every file; with type information only methods of
// sync.Mutex and sync.RWMutex open and close a critical section.
func (r *MutexLockRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	return rules.AnalyzeGoFiles(ctx, r.Name(), r.analyze)
}

func (r *MutexLockRule) analyze(ctx *core.FileContext, info *types.Info) []*core.Violation {
	if !ctx.IsGoFile() || ctx.IsTestFile() {
		return nil
	}
	return helpers.AnalyzeFuncBodies(ctx, func(ctx *core.FileContext, body *ast.BlockStmt, violations *[]*core.Violation) {
		r.checkFunction(ctx, info, body, violations)
	})
}

func (r *MutexLockRule) checkFunction(ctx *core.FileContext, info *types.Info, body *ast.BlockStmt, violations *[]*core.Violation) {
	// Find all Lock/RLock calls
	var lockCalls []*lockInfo

	ast.Inspect(body, func(n ast.Node) bool {
		// Skip nested function literals
		if _, ok := n.(*ast.FuncLit); ok {
			return false
		}

		exprStmt, ok := n.(*ast.ExprStmt)
		if !ok {
			return true
		}

		call, ok := exprStmt.X.(*ast.CallExpr)
		if !ok {
			return true
		}

		if found, ok := lockCall(call, info); ok {
			lockCalls = append(lockCalls, &lockInfo{
				receiver:     found.receiver,
				method:       found.method,
				unlockMethod: lockMethods[found.method],
				line:         ctx.LineFor(exprStmt),
			})
		}

		return true
	})

	// Find every release of a lock: a deferred or a plain Unlock/RUnlock call,
	// or the method value itself (`return s.mu.Unlock`), handed to whoever
	// calls it. If there's ANY unlock for the same mutex, it's likely an
	// intentional early-unlock pattern.
	unlocks := make(map[string]bool)

	ast.Inspect(body, func(n ast.Node) bool {
		// Skip nested function literals
		if _, ok := n.(*ast.FuncLit); ok {
			return false
		}

		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}

		if found, ok := unlockRef(sel, info); ok {
			unlocks[found.receiver+found.method] = true
		}

		return true
	})

	// Check for locks without any unlock (defer or regular)
	for _, lock := range lockCalls {
		expectedUnlock := lock.receiver + lock.unlockMethod
		// If there's defer unlock OR regular unlock, it's fine
		if !unlocks[expectedUnlock] {
			v := r.CreateViolation(ctx.RelPath, lock.line, lock.method+"() without corresponding "+lock.unlockMethod+"()")
			v.WithCode(ctx.GetLine(lock.line))
			v.WithSuggestion("Add defer " + lock.receiver + "." + lock.unlockMethod + "() after Lock() or ensure Unlock() is called on all code paths")
			v.WithContext("pattern", "mutex_no_unlock")
			v.WithContext("lock_method", lock.method)
			*violations = append(*violations, v)
		}
	}
}

type lockInfo struct {
	receiver     string
	method       string
	unlockMethod string
	line         int
}
