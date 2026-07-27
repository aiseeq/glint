package patterns

import (
	"go/ast"

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

// AnalyzeFile checks for mutex lock without defer unlock
func (r *MutexLockRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || ctx.IsTestFile() {
		return nil
	}
	return helpers.AnalyzeFuncBodies(ctx, r.checkFunction)
}

func (r *MutexLockRule) checkFunction(ctx *core.FileContext, body *ast.BlockStmt, violations *[]*core.Violation) {
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

		if info, ok := lockCall(call); ok {
			lockCalls = append(lockCalls, &lockInfo{
				receiver:     info.receiver,
				method:       info.method,
				unlockMethod: lockMethods[info.method],
				line:         ctx.LineFor(exprStmt),
			})
		}

		return true
	})

	// Find all defer Unlock/RUnlock calls
	deferUnlocks := make(map[string]bool)

	ast.Inspect(body, func(n ast.Node) bool {
		// Skip nested function literals
		if _, ok := n.(*ast.FuncLit); ok {
			return false
		}

		deferStmt, ok := n.(*ast.DeferStmt)
		if !ok {
			return true
		}

		if info, ok := unlockCall(deferStmt.Call); ok {
			deferUnlocks[info.receiver+info.method] = true
		}

		return true
	})

	// Find all regular Unlock/RUnlock calls (not defer)
	// If there's ANY unlock for the same mutex, it's likely intentional early-unlock pattern
	regularUnlocks := make(map[string]bool)

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

		if info, ok := unlockCall(call); ok {
			regularUnlocks[info.receiver+info.method] = true
		}

		return true
	})

	// Check for locks without any unlock (defer or regular)
	for _, lock := range lockCalls {
		expectedUnlock := lock.receiver + lock.unlockMethod
		// If there's defer unlock OR regular unlock, it's fine
		if !deferUnlocks[expectedUnlock] && !regularUnlocks[expectedUnlock] {
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
