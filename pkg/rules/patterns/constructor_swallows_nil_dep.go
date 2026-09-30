package patterns

import (
	"go/ast"
	"go/token"
	"go/types"
	"slices"
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
// The caller receives a half-alive object and the failure surfaces far from
// its cause. A nil dependency must abort construction with an error.
//
// A constructor that silently replaces a nil dependency (a logger, a client,
// a repository) with a package default or a no-op hides the same wiring
// mistake: `if logger == nil { logger = slog.Default() }` with no log.
//
// Not flagged: returning an error, panicking, a default for a parameter that
// is not a dependency (options-defaulting), a replacement that is logged, and
// Debug/Info-level notes.
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
			pos := ctx.PositionFor(ifStmt)
			if param, value := silentDefault(ifStmt.Body, checked); param != "" {
				v := r.CreateViolation(ctx.RelPath, pos.Line,
					"Constructor "+fn.Name.Name+" silently replaces a nil "+param+" with "+value+" — the caller that passed nil is never told")
				v.WithCode(strings.TrimSpace(ctx.GetLine(pos.Line)))
				v.WithSuggestion("Return an error for the nil dependency, or pass the default at the call site")
				violations = append(violations, v)
				return
			}
			if !r.bodySwallows(ifStmt.Body, checked) {
				return
			}
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
				case isErrorLevelLogCall(call):
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

// silentDefault returns the dependency parameter a nil-check body replaces
// with a package default or a no-op and the value, when the body does
// nothing else: slog.Default(), http.DefaultClient, zap.NewNop().
func silentDefault(body *ast.BlockStmt, checked []string) (string, string) {
	if len(body.List) != 1 {
		return "", ""
	}
	assign, ok := body.List[0].(*ast.AssignStmt)
	if !ok || assign.Tok != token.ASSIGN || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
		return "", ""
	}
	ident, ok := assign.Lhs[0].(*ast.Ident)
	if !ok || !slices.Contains(checked, ident.Name) || !isDependencyName(ident.Name) {
		return "", ""
	}
	if !isPackageDefault(assign.Rhs[0]) {
		return "", ""
	}
	return ident.Name, types.ExprString(assign.Rhs[0])
}

// isPackageDefault reports a package-level default or no-op value: pkg.Default(),
// pkg.DefaultClient, pkg.NewNop(), pkg.Discard.
func isPackageDefault(expr ast.Expr) bool {
	expr = ast.Unparen(expr)
	if call, ok := expr.(*ast.CallExpr); ok {
		if len(call.Args) != 0 {
			return false
		}
		expr = call.Fun
	}
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	if _, ok := sel.X.(*ast.Ident); !ok {
		return false
	}
	name := sel.Sel.Name
	for _, prefix := range []string{"Default", "Nop", "NewNop", "Noop", "NewNoop", "Discard"} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
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
