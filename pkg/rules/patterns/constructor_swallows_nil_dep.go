package patterns

import (
	"go/ast"
	"go/token"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewConstructorSwallowsNilDepRule())
}

// ConstructorSwallowsNilDepRule detects constructors that notice a nil
// dependency, log it — and build the object anyway:
//
//	func NewPermissionManager(repo Repository) *PermissionManager {
//	    if repo == nil {
//	        logger.Error("Critical: repo is nil") // and continues!
//	    }
//	    return &PermissionManager{repo: repo}
//	}
//
// This is the "graceful degradation" anti-pattern forbidden by CLAUDE.md:
// the caller receives a half-alive object and the failure surfaces far from
// its cause. A nil dependency must abort construction with an error.
//
// Not flagged: returning an error, panicking, or assigning a default to the
// parameter (options-defaulting), and Debug/Info-level notes.
type ConstructorSwallowsNilDepRule struct {
	*rules.BaseRule
}

// NewConstructorSwallowsNilDepRule creates the rule
func NewConstructorSwallowsNilDepRule() *ConstructorSwallowsNilDepRule {
	return &ConstructorSwallowsNilDepRule{
		BaseRule: rules.NewBaseRule(
			"constructor-swallows-nil-dep",
			"patterns",
			"Detects constructors that log a nil dependency and continue building the object",
			core.SeverityHigh,
		),
	}
}

// AnalyzeFile checks Go constructors for swallowed nil dependencies
func (r *ConstructorSwallowsNilDepRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.HasGoAST() || ctx.IsTestFile() {
		return nil
	}

	var violations []*core.Violation

	for _, decl := range ctx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || !isPlainConstructor(fn) {
			continue
		}
		params := paramNames(fn)
		if len(params) == 0 {
			continue
		}

		forEachOwnStatement(fn.Body, func(stmt ast.Stmt) {
			ifStmt, ok := stmt.(*ast.IfStmt)
			if !ok {
				return
			}
			checked := nilCheckedParams(ifStmt.Cond, params)
			if len(checked) == 0 {
				return
			}
			if !r.bodySwallows(ifStmt.Body, checked) {
				return
			}
			pos := ctx.PositionFor(ifStmt)
			v := r.CreateViolation(ctx.RelPath, pos.Line,
				"Constructor "+fn.Name.Name+" logs nil dependency ("+strings.Join(checked, ", ")+") and continues — the object is built half-alive")
			v.WithCode(strings.TrimSpace(ctx.GetLine(pos.Line)))
			v.WithSuggestion("Abort construction: change the signature to (T, error) and return an explicit error for the nil dependency")
			violations = append(violations, v)
		})
	}

	return violations
}

// bodySwallows reports whether the nil-check body only logs at Error/Warn
// level and neither aborts (return/panic/exit) nor assigns a default to one
// of the checked parameters.
func (r *ConstructorSwallowsNilDepRule) bodySwallows(body *ast.BlockStmt, checked []string) bool {
	checkedSet := make(map[string]bool, len(checked))
	for _, name := range checked {
		checkedSet[name] = true
	}

	hasErrorLog := false
	aborts := false

	forEachOwnStatement(body, func(stmt ast.Stmt) {
		switch s := stmt.(type) {
		case *ast.ReturnStmt:
			aborts = true
		case *ast.ExprStmt:
			if call, ok := s.X.(*ast.CallExpr); ok {
				switch {
				case isPanicOrExitCall(call):
					aborts = true
				case isErrorOrWarnLogCall(call):
					hasErrorLog = true
				}
			}
		case *ast.AssignStmt:
			// Defaulting the checked parameter is the options pattern.
			for _, lhs := range s.Lhs {
				if ident, ok := lhs.(*ast.Ident); ok && checkedSet[ident.Name] {
					aborts = true
				}
			}
		}
	})

	return hasErrorLog && !aborts
}

// paramNames collects parameter names of the function.
func paramNames(fn *ast.FuncDecl) map[string]bool {
	names := make(map[string]bool)
	if fn.Type.Params == nil {
		return names
	}
	for _, field := range fn.Type.Params.List {
		for _, name := range field.Names {
			names[name.Name] = true
		}
	}
	return names
}

// nilCheckedParams returns the constructor parameters compared to nil via ==
// in the condition (single check or ||-chain).
func nilCheckedParams(cond ast.Expr, params map[string]bool) []string {
	var checked []string
	for _, operand := range flattenOr(cond) {
		be, ok := operand.(*ast.BinaryExpr)
		if !ok || be.Op != token.EQL {
			continue
		}
		for _, pair := range [][2]ast.Expr{{be.X, be.Y}, {be.Y, be.X}} {
			if !isNilIdent(pair[1]) {
				continue
			}
			if ident, ok := pair[0].(*ast.Ident); ok && params[ident.Name] {
				checked = append(checked, ident.Name)
			}
		}
	}
	return checked
}

// isPanicOrExitCall matches panic(...), os.Exit(...), log.Fatal*(...).
func isPanicOrExitCall(call *ast.CallExpr) bool {
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		return fun.Name == "panic"
	case *ast.SelectorExpr:
		name := fun.Sel.Name
		return name == "Exit" || strings.HasPrefix(name, "Fatal")
	}
	return false
}

// isErrorOrWarnLogCall matches logger calls at Error/Warn level, including
// structured variants (ErrorStructured, Warnf, Warnw, ...).
func isErrorOrWarnLogCall(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	name := sel.Sel.Name
	return strings.HasPrefix(name, "Error") || strings.HasPrefix(name, "Warn")
}
