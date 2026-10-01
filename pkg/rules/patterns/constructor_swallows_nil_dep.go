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
// mistake: `if logger == nil { logger = slog.Default() }` with no log. So
// does a function or a method that makes the swap where it uses the
// dependency: a parameter, a local copy of a receiver field, the field itself.
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
		if !ok || fn.Body == nil {
			continue
		}
		if !isPlainConstructor(fn) {
			violations = append(violations, r.useSiteDefaults(ctx, fn)...)
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

// useSiteDefaults reports a function or a method that replaces a nil
// dependency with a package default where it uses it: a parameter, a local
// copy of a receiver field, or the receiver field itself.
func (r *ConstructorSwallowsNilDepRule) useSiteDefaults(ctx *core.FileContext, fn *ast.FuncDecl) []*core.Violation {
	names := paramNames(fn)
	recv := ""
	if fn.Recv != nil {
		recv, _ = receiverName(fn)
	}
	if recv != "" {
		forEachOwnStatement(fn.Body, func(stmt ast.Stmt) {
			assign, ok := stmt.(*ast.AssignStmt)
			if !ok || assign.Tok != token.DEFINE || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
				return
			}
			ident, isIdent := assign.Lhs[0].(*ast.Ident)
			if sel, ok := assign.Rhs[0].(*ast.SelectorExpr); ok && isIdent && isIdentNamed(sel.X, recv) {
				names[ident.Name] = true
			}
		})
	}
	var violations []*core.Violation
	forEachOwnStatement(fn.Body, func(stmt ast.Stmt) {
		ifStmt, ok := stmt.(*ast.IfStmt)
		if !ok {
			return
		}
		name, value := silentDefault(ifStmt.Body, nilCheckedParams(ifStmt.Cond, names))
		if name == "" {
			name, value = silentFieldDefault(ifStmt, recv)
		}
		if name == "" {
			return
		}
		line := ctx.PositionFor(ifStmt).Line
		v := r.CreateViolation(ctx.RelPath, line,
			fn.Name.Name+" silently replaces a nil "+name+" with "+value+" — the code that left it nil is never told")
		v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
		v.WithSuggestion("Require the dependency where the value is built (the constructor returns an error for nil) and use it as is")
		violations = append(violations, v)
	})
	return violations
}

// silentFieldDefault matches if c.logger == nil { c.logger = slog.Default() }
// on the receiver and returns the field and the value.
func silentFieldDefault(ifStmt *ast.IfStmt, recv string) (string, string) {
	cond, ok := ast.Unparen(ifStmt.Cond).(*ast.BinaryExpr)
	if !ok || cond.Op != token.EQL || !isNilIdent(cond.Y) || len(ifStmt.Body.List) != 1 {
		return "", ""
	}
	field, ok := cond.X.(*ast.SelectorExpr)
	if !ok || !isIdentNamed(field.X, recv) || !isDependencyName(field.Sel.Name) {
		return "", ""
	}
	assign, ok := ifStmt.Body.List[0].(*ast.AssignStmt)
	if !ok || assign.Tok != token.ASSIGN || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
		return "", ""
	}
	target, ok := assign.Lhs[0].(*ast.SelectorExpr)
	if !ok || !isIdentNamed(target.X, recv) || target.Sel.Name != field.Sel.Name || !isPackageDefault(assign.Rhs[0]) {
		return "", ""
	}
	return field.Sel.Name, types.ExprString(assign.Rhs[0])
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
	if ret, ok := body.List[0].(*ast.ReturnStmt); ok {
		return freshInstanceReturn(ret, checked)
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

// freshInstanceReturn matches `if cache == nil { return NewCache() }`: the only
// checked dependency is answered with a new instance built without arguments
// (or a package default), so the caller that left it nil gets a private,
// unconfigured copy and is never told. A constructor given arguments makes a
// configured value and is left alone.
func freshInstanceReturn(ret *ast.ReturnStmt, checked []string) (string, string) {
	if len(ret.Results) != 1 || len(checked) != 1 || !isDependencyName(checked[0]) {
		return "", ""
	}
	value := ast.Unparen(ret.Results[0])
	if assert, ok := value.(*ast.TypeAssertExpr); ok {
		value = ast.Unparen(assert.X)
	}
	if !isPackageDefault(value) && !isNoArgConstructorCall(value) {
		return "", ""
	}
	return checked[0], types.ExprString(ret.Results[0])
}

// isNoArgConstructorCall reports New...() or pkg.New...() called without arguments.
func isNoArgConstructorCall(expr ast.Expr) bool {
	call, ok := expr.(*ast.CallExpr)
	if !ok || len(call.Args) != 0 {
		return false
	}
	name := ""
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		name = fun.Name
	case *ast.SelectorExpr:
		name = fun.Sel.Name
	}
	return strings.HasPrefix(name, "New")
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
