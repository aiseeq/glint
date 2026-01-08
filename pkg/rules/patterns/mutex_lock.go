package patterns

import (
	"go/ast"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewMutexLockRule())
}

// MutexLockRule detects mutex Lock() without corresponding defer Unlock()
type MutexLockRule struct {
	*rules.BaseRule
}

// NewMutexLockRule creates the rule
func NewMutexLockRule() *MutexLockRule {
	return &MutexLockRule{
		BaseRule: rules.NewBaseRule(
			"mutex-lock",
			"patterns",
			"Detects mutex Lock() without defer Unlock() (potential deadlock)",
			core.SeverityHigh,
		),
	}
}

// AnalyzeFile checks for mutex lock without defer unlock
func (r *MutexLockRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || ctx.IsTestFile() {
		return nil
	}

	if ctx.GoAST == nil {
		return nil
	}

	var violations []*core.Violation

	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			return true
		}

		// Find all Lock() calls and check for corresponding defer Unlock()
		r.checkFunction(ctx, fn.Body, &violations)

		return true
	})

	return violations
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

		if info := r.getLockInfo(call); info != nil {
			info.line = r.getLineFromNode(ctx, exprStmt)
			lockCalls = append(lockCalls, info)
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

		if info := r.getUnlockInfo(deferStmt.Call); info != nil {
			deferUnlocks[info.receiver+info.method] = true
		}

		return true
	})

	// Check for locks without defer unlock
	for _, lock := range lockCalls {
		expectedUnlock := lock.receiver + lock.unlockMethod
		if !deferUnlocks[expectedUnlock] {
			v := r.CreateViolation(ctx.RelPath, lock.line, lock.method+"() without defer "+lock.unlockMethod+"()")
			v.WithCode(ctx.GetLine(lock.line))
			v.WithSuggestion("Add defer " + lock.receiver + "." + lock.unlockMethod + "() after Lock()")
			v.WithContext("pattern", "mutex_no_defer")
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

func (r *MutexLockRule) getLockInfo(call *ast.CallExpr) *lockInfo {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return nil
	}

	method := sel.Sel.Name
	if method != "Lock" && method != "RLock" {
		return nil
	}

	receiver := r.getReceiverName(sel.X)
	if receiver == "" {
		return nil
	}

	unlockMethod := "Unlock"
	if method == "RLock" {
		unlockMethod = "RUnlock"
	}

	return &lockInfo{
		receiver:     receiver,
		method:       method,
		unlockMethod: unlockMethod,
	}
}

func (r *MutexLockRule) getUnlockInfo(call *ast.CallExpr) *lockInfo {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return nil
	}

	method := sel.Sel.Name
	if method != "Unlock" && method != "RUnlock" {
		return nil
	}

	receiver := r.getReceiverName(sel.X)
	if receiver == "" {
		return nil
	}

	return &lockInfo{
		receiver: receiver,
		method:   method,
	}
}

func (r *MutexLockRule) getReceiverName(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		// Handle cases like s.mu.Lock()
		base := r.getReceiverName(e.X)
		if base != "" {
			return base + "." + e.Sel.Name
		}
		return e.Sel.Name
	case *ast.UnaryExpr:
		// Handle &mu case
		return r.getReceiverName(e.X)
	}
	return ""
}

func (r *MutexLockRule) getLineFromNode(ctx *core.FileContext, node ast.Node) int {
	if node == nil {
		return 1
	}

	pos := node.Pos()
	if pos == 0 {
		return 1
	}

	offset := int(pos) - 1
	if offset < 0 || offset >= len(ctx.Content) {
		return 1
	}

	line := 1
	for i := 0; i < offset && i < len(ctx.Content); i++ {
		if ctx.Content[i] == '\n' {
			line++
		}
	}
	return line
}
