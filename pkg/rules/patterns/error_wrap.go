package patterns

import (
	"go/ast"
	"go/types"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewErrorWrapRule())
}

// ErrorWrapRule detects errors returned without context wrapping
type ErrorWrapRule struct {
	*rules.BaseRule
}

// NewErrorWrapRule creates the rule
func NewErrorWrapRule() *ErrorWrapRule {
	return &ErrorWrapRule{
		BaseRule: rules.NewBaseRule(
			"error-wrap",
			"patterns",
			"Detects errors returned without adding context (should use fmt.Errorf with %w)",
			core.SeverityLow,
		),
	}
}

// AnalyzeFile checks one file without type information: the fallback the
// project analysis uses for files no type-checked package covers.
func (r *ErrorWrapRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	return r.analyze(ctx, nil)
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *ErrorWrapRule) RequiresSSA() bool { return false }

// AnalyzeGoProject checks every file, test files included; parameter types
// are resolved wherever the project declares them.
func (r *ErrorWrapRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	return rules.AnalyzeGoFiles(ctx, r.Name(), r.analyze)
}

// analyze checks for unwrapped error returns. info is nil for a file without
// type information.
func (r *ErrorWrapRule) analyze(ctx *core.FileContext, info *types.Info) []*core.Violation {
	if !ctx.IsGoFile() || ctx.GoAST == nil {
		return nil
	}
	if strings.HasPrefix(ctx.RelPath, "internal/") || strings.HasPrefix(ctx.RelPath, "cmd/") {
		return nil
	}

	var violations []*core.Violation

	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			return true
		}

		// Check if function returns error
		if !r.returnsError(fn) {
			return true
		}

		// Find if-err-return patterns
		for i, stmt := range fn.Body.List {
			ifStmt, ok := stmt.(*ast.IfStmt)
			if !ok {
				continue
			}

			// Check for if err != nil pattern
			if !r.isErrCheck(ifStmt.Cond) {
				continue
			}

			// Delegating to the same method on an embedded type is a pass
			// through, not a lost context: the caller of this method adds the
			// context, and wrapping here would duplicate it.
			call := errorSourceCall(ifStmt, fn.Body.List[:i])
			if callee := callName(call); callee != "" && callee == fn.Name.Name {
				continue
			}
			// Closure-runners (RunInTx-style calls taking a func literal) and
			// caller-supplied callback parameters are transparent pass-throughs:
			// context is added inside the closure/callback, and wrapping outside
			// would prefix every propagated error and obscure sentinel errors.
			if isClosureRunnerCall(call) || callsCallbackParam(call, fn, info) {
				continue
			}

			// Check body for bare return err
			for _, bodyStmt := range ifStmt.Body.List {
				retStmt, ok := bodyStmt.(*ast.ReturnStmt)
				if !ok {
					continue
				}

				if r.isBareErrorReturn(retStmt) {
					pos := ctx.PositionFor(retStmt)
					v := r.CreateViolation(ctx.RelPath, pos.Line,
						"Error returned without context; consider wrapping with fmt.Errorf")
					v.WithCode(ctx.GetLine(pos.Line))
					v.WithSuggestion("Use fmt.Errorf(\"context: %w\", err) to add context")
					violations = append(violations, v)
				}
			}
		}

		return true
	})

	return violations
}

// returnsError checks if function has error in return types
func (r *ErrorWrapRule) returnsError(fn *ast.FuncDecl) bool {
	if fn.Type.Results == nil {
		return false
	}

	for _, result := range fn.Type.Results.List {
		if ident, ok := result.Type.(*ast.Ident); ok {
			if ident.Name == "error" {
				return true
			}
		}
	}

	return false
}

// isErrCheck checks for err != nil
func (r *ErrorWrapRule) isErrCheck(cond ast.Expr) bool {
	binExpr, ok := cond.(*ast.BinaryExpr)
	if !ok {
		return false
	}

	// Check for err != nil
	ident, ok := binExpr.X.(*ast.Ident)
	if !ok {
		return false
	}

	if ident.Name != "err" {
		return false
	}

	nilIdent, ok := binExpr.Y.(*ast.Ident)
	if !ok {
		return false
	}

	return nilIdent.Name == "nil"
}

// isBareErrorReturn checks if return statement just returns err without wrapping
func (r *ErrorWrapRule) isBareErrorReturn(ret *ast.ReturnStmt) bool {
	if len(ret.Results) == 0 {
		return false
	}

	// Check last result (error is usually last)
	lastResult := ret.Results[len(ret.Results)-1]

	// Check for bare err identifier
	ident, ok := lastResult.(*ast.Ident)
	if !ok {
		return false
	}

	return ident.Name == "err"
}

// errorSourceCall returns the call that produced the error the if-statement
// checks, looking at the statement's own initializer first and then at the
// preceding statements. It returns nil when the source cannot be identified.
func errorSourceCall(ifStmt *ast.IfStmt, before []ast.Stmt) *ast.CallExpr {
	if init, ok := ifStmt.Init.(*ast.AssignStmt); ok {
		if call := assignedCall(init); call != nil {
			return call
		}
	}
	for i := len(before) - 1; i >= 0; i-- {
		previous, ok := before[i].(*ast.AssignStmt)
		if !ok || !assignsError(previous) {
			continue
		}
		return assignedCall(previous)
	}
	return nil
}

// callName returns the (selector) name of the called function, "" if unknown.
func callName(call *ast.CallExpr) string {
	if call == nil {
		return ""
	}
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		return fun.Name
	case *ast.SelectorExpr:
		return fun.Sel.Name
	}
	return ""
}

// isClosureRunnerCall reports whether the call takes a func literal argument
// (RunInTx-style runner executing caller-provided code).
func isClosureRunnerCall(call *ast.CallExpr) bool {
	if call == nil {
		return false
	}
	for _, arg := range call.Args {
		if _, ok := arg.(*ast.FuncLit); ok {
			return true
		}
	}
	return false
}

// callsCallbackParam reports whether the call invokes a parameter of the
// enclosing function (the callback owns its error context). A parameter that
// is called is func-typed whatever its type is named or wherever that type is
// declared, so a named func type needs no resolution. Type information only
// tells a parameter from a local variable that shadows it.
func callsCallbackParam(call *ast.CallExpr, fn *ast.FuncDecl, info *types.Info) bool {
	if call == nil || fn.Type.Params == nil {
		return false
	}
	ident, ok := call.Fun.(*ast.Ident)
	if !ok {
		return false
	}
	if info != nil {
		param, ok := info.Uses[ident].(*types.Var)
		return ok && param.Pos() >= fn.Type.Params.Pos() && param.Pos() < fn.Type.Params.End()
	}
	for _, param := range fn.Type.Params.List {
		for _, name := range param.Names {
			if name.Name == ident.Name {
				return true
			}
		}
	}
	return false
}

// assignsError reports whether the assignment binds a variable named "err".
func assignsError(assign *ast.AssignStmt) bool {
	for _, lhs := range assign.Lhs {
		if ident, ok := lhs.(*ast.Ident); ok && ident.Name == "err" {
			return true
		}
	}
	return false
}

// assignedCall returns the call on the right-hand side of an assignment.
func assignedCall(assign *ast.AssignStmt) *ast.CallExpr {
	if len(assign.Rhs) != 1 {
		return nil
	}
	call, ok := assign.Rhs[0].(*ast.CallExpr)
	if !ok {
		return nil
	}
	return call
}
