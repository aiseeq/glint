package patterns

import (
	"go/ast"
	"go/token"
	"path/filepath"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewErrVariableHoldsNonErrorRule())
}

// ErrVariableHoldsNonErrorRule detects a variable named as an error that
// receives a result of another type, and is then tested against nil:
//
//	func setupAdmin(t *testing.T) (*Client, *LoginResponse)
//
//	client, err := setupAdmin(t)
//	if err != nil || client == nil {
//		t.Skipf("no admin: %v", err)   // the response is never nil: always skips
//	}
//
// The name says "the call failed", the value is a response, a record or a
// flag. Usually the function's signature changed under its callers: the
// check that guarded a failure now tests whether something came back, and
// the branch runs on every success. Only functions declared in the same
// directory are resolved, and a result whose type may be an error (error, an
// interface, a type named …Error or with an Error method) is left out.
type ErrVariableHoldsNonErrorRule struct {
	*rules.BaseRule
	// funcs maps a directory to its plain functions' signatures.
	funcs map[string]map[string]*ast.FuncType
	// errorTypes maps a directory to the types that may hold an error: those
	// with an Error method, and interfaces.
	errorTypes map[string]map[string]bool
}

// NewErrVariableHoldsNonErrorRule creates the rule
func NewErrVariableHoldsNonErrorRule() *ErrVariableHoldsNonErrorRule {
	return &ErrVariableHoldsNonErrorRule{BaseRule: rules.NewBaseRule(
		"err-variable-holds-non-error",
		"patterns",
		"Detects a variable named err that receives a non-error result and is compared with nil — the check tests whether a value came back, not whether the call failed",
		core.SeverityHigh,
	)}
}

// UseProjectFiles collects the functions and the error types of each
// directory.
func (r *ErrVariableHoldsNonErrorRule) UseProjectFiles(files []*core.FileContext) {
	r.funcs = make(map[string]map[string]*ast.FuncType)
	r.errorTypes = make(map[string]map[string]bool)
	for _, ctx := range files {
		if !ctx.IsGoFile() || !ctx.HasGoAST() {
			continue
		}
		dir := filepath.Dir(ctx.Path)
		if r.funcs[dir] == nil {
			r.funcs[dir] = make(map[string]*ast.FuncType)
			r.errorTypes[dir] = make(map[string]bool)
		}
		for _, decl := range ctx.GoAST.Decls {
			if gen, ok := decl.(*ast.GenDecl); ok {
				for _, name := range interfaceTypeNames(gen) {
					r.errorTypes[dir][name] = true
				}
				continue
			}
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			if fn.Recv == nil {
				r.funcs[dir][fn.Name.Name] = fn.Type
				continue
			}
			if fn.Name.Name == "Error" {
				r.errorTypes[dir][receiverTypeName(fn.Recv)] = true
			}
		}
	}
}

// interfaceTypeNames returns the interface types a declaration declares.
func interfaceTypeNames(gen *ast.GenDecl) []string {
	var names []string
	for _, spec := range gen.Specs {
		typeSpec, ok := spec.(*ast.TypeSpec)
		if !ok {
			continue
		}
		if _, isInterface := typeSpec.Type.(*ast.InterfaceType); isInterface {
			names = append(names, typeSpec.Name.Name)
		}
	}
	return names
}

// ResetState drops the declarations of the previous root.
func (r *ErrVariableHoldsNonErrorRule) ResetState() {
	r.funcs = nil
	r.errorTypes = nil
}

// AnalyzeFile reports the nil checks of err-named variables that hold a
// non-error result.
func (r *ErrVariableHoldsNonErrorRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || !ctx.HasGoAST() {
		return nil
	}
	dir := filepath.Dir(ctx.Path)
	funcs := r.funcs[dir]
	if len(funcs) == 0 {
		return nil
	}
	var violations []*core.Violation
	forEachFunction(ctx.GoAST, func(_ string, _ *ast.FuncType, body *ast.BlockStmt) {
		ast.Inspect(body, func(n ast.Node) bool {
			if _, nested := n.(*ast.FuncLit); nested {
				return false // its own function
			}
			assign, ok := n.(*ast.AssignStmt)
			if !ok || len(assign.Rhs) != 1 || len(assign.Lhs) < 2 {
				return true
			}
			call, ok := ast.Unparen(assign.Rhs[0]).(*ast.CallExpr)
			if !ok {
				return true
			}
			callee, ok := call.Fun.(*ast.Ident)
			if !ok {
				return true
			}
			signature := funcs[callee.Name]
			if signature == nil {
				return true
			}
			results := resultTypes(signature)
			if len(results) != len(assign.Lhs) {
				return true
			}
			for i, lhs := range assign.Lhs {
				id, ok := lhs.(*ast.Ident)
				if !ok || id.Name != "err" && !strings.HasSuffix(id.Name, "Err") || r.mayBeError(dir, results[i]) {
					continue
				}
				if check := nilCheckAfter(body, id, assign.End()); check != nil {
					line := ctx.LineFor(check)
					if ctx.IsSuppressed(line, r.Name()) {
						continue
					}
					v := r.CreateViolation(ctx.RelPath, line,
						id.Name+" holds "+helpers.ExprText(results[i])+" returned by "+callee.Name+", not an error — the nil check tests whether a value came back, so it holds on every success")
					v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
					v.WithSuggestion("Name the variable after what " + callee.Name + " returns, and check the result the call actually fails with")
					violations = append(violations, v)
				}
			}
			return true
		})
	})
	return violations
}

// resultTypes flattens a signature's results: (a, b T) gives T twice.
func resultTypes(signature *ast.FuncType) []ast.Expr {
	if signature.Results == nil {
		return nil
	}
	var types []ast.Expr
	for _, field := range signature.Results.List {
		count := max(len(field.Names), 1)
		for range count {
			types = append(types, field.Type)
		}
	}
	return types
}

// mayBeError reports a result type that is or may hold an error: error
// itself, an interface, a type named …Error/…Err, or one with an Error method
// in the directory.
func (r *ErrVariableHoldsNonErrorRule) mayBeError(dir string, expr ast.Expr) bool {
	switch t := expr.(type) {
	case *ast.StarExpr:
		return r.mayBeError(dir, t.X)
	case *ast.InterfaceType:
		return true
	case *ast.SelectorExpr:
		return strings.Contains(t.Sel.Name, "Err")
	case *ast.Ident:
		if t.Name == "error" || t.Name == "any" || strings.Contains(t.Name, "Err") || r.errorTypes[dir][t.Name] {
			return true
		}
		return false
	case *ast.ArrayType, *ast.MapType, *ast.ChanType, *ast.FuncType:
		return false
	}
	return true
}

// nilCheckAfter returns the first comparison of the variable with nil after
// pos; a variable of the same name declared in an inner scope is another one.
func nilCheckAfter(body *ast.BlockStmt, variable *ast.Ident, pos token.Pos) *ast.BinaryExpr {
	var found *ast.BinaryExpr
	ast.Inspect(body, func(n ast.Node) bool {
		if found != nil {
			return false
		}
		bin, ok := n.(*ast.BinaryExpr)
		if !ok || bin.Pos() < pos || (bin.Op != token.NEQ && bin.Op != token.EQL) {
			return true
		}
		id, ok := ast.Unparen(bin.X).(*ast.Ident)
		if ok && id.Name == variable.Name && (id.Obj == nil || variable.Obj == nil || id.Obj == variable.Obj) && isNilIdent(bin.Y) {
			found = bin
		}
		return true
	})
	return found
}
