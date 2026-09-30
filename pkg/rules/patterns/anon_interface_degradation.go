package patterns

import (
	"go/ast"
	"go/token"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewAnonInterfaceDegradationRule())
}

// AnonInterfaceDegradationRule detects type assertions on anonymous interfaces
// followed by silent degradation returns. This pattern often indicates dead delegation code.
//
// Catches patterns like:
//
//	if x.(interface{ Method() Type }); ok {
//	    return x.Method()
//	}
//	return zeroValue // Problem: silently degrades
//
// This violates "Fail explicitly, never degrade silently"
type AnonInterfaceDegradationRule struct {
	*rules.BaseRule
}

// NewAnonInterfaceDegradationRule creates the rule
func NewAnonInterfaceDegradationRule() *AnonInterfaceDegradationRule {
	return &AnonInterfaceDegradationRule{
		BaseRule: rules.NewBaseRule(
			"anon-interface-degradation",
			"patterns",
			"Detects type assertions on anonymous interfaces with silent degradation",
			core.SeverityCritical,
		),
	}
}

// AnalyzeFile checks for anonymous interface degradation patterns
func (r *AnonInterfaceDegradationRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.HasGoAST() || ctx.IsTestFile() {
		return nil
	}

	var violations []*core.Violation

	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			return true
		}

		// Look for the pattern in function body
		v := r.checkFunctionBody(ctx, fn)
		violations = append(violations, v...)

		return true
	})

	return violations
}

// checkFunctionBody looks for anonymous interface assertion + degradation pattern
// Pattern: if x != nil { if _, ok := x.(interface{...}); ok { return } } return magicValue
func (r *AnonInterfaceDegradationRule) checkFunctionBody(ctx *core.FileContext, fn *ast.FuncDecl) []*core.Violation {
	var violations []*core.Violation

	stmts := fn.Body.List
	for i, stmt := range stmts {
		// Look for if statement that might contain nested assertion
		ifStmt, ok := stmt.(*ast.IfStmt)
		if !ok {
			continue
		}

		// Check if this if (or nested if) contains anonymous interface type assertion
		if !r.containsAnonymousInterfaceAssertion(ifStmt) {
			continue
		}

		// Check if next statement is a degradation return
		if i+1 < len(stmts) {
			if ret, ok := stmts[i+1].(*ast.ReturnStmt); ok {
				if r.isDegradationReturn(ret) && !isOptionalInterfaceIdiom(fn, ifStmt, ret) {
					pos := ctx.PositionFor(ret)
					lineContent := ctx.GetLine(pos.Line)

					if strings.Contains(lineContent, "nolint") {
						continue
					}

					v := r.CreateViolation(ctx.RelPath, pos.Line,
						"Silent degradation after anonymous interface assertion - likely dead delegation code")
					v.WithCode(lineContent)
					v.WithSuggestion("Remove dead delegation or return explicit error")
					violations = append(violations, v)
				}
			}
		}
	}

	return violations
}

// isOptionalInterfaceIdiom recognises the optional-interface idiom:
//
//	func Flush(w io.Writer) error {
//	    if f, ok := w.(interface{ Flush() error }); ok {
//	        return f.Flush()
//	    }
//	    return nil
//	}
//
// The value the caller handed in may or may not have the capability; the
// branch delegates to the method the assertion checked for, and the tail
// answers with the zero value — "no such capability, nothing to do". A made-up
// non-zero answer in the tail still degrades, and so does a wrapper that
// delegates to its own dependency (d.inner): that is the dead delegation this
// rule is about.
func isOptionalInterfaceIdiom(fn *ast.FuncDecl, ifStmt *ast.IfStmt, tail *ast.ReturnStmt) bool {
	for _, result := range tail.Results {
		if !isZeroValueExpr(result) && !isFalseIdent(result) {
			return false
		}
	}
	delegates := false
	inspectOwnIfTree(ifStmt, func(nested *ast.IfStmt) {
		bound, asserted := assertedInterfaceVar(nested)
		if bound != "" && isParamName(fn, asserted) && returnsMethodCallOn(nested.Body, bound) {
			delegates = true
		}
	})
	return delegates
}

// inspectOwnIfTree visits the if statement and every if nested in it, pruning
// function literals.
func inspectOwnIfTree(ifStmt *ast.IfStmt, visit func(*ast.IfStmt)) {
	ast.Inspect(ifStmt, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.IfStmt:
			visit(node)
		}
		return true
	})
}

// assertedInterfaceVar returns the variable bound by an `if v, ok :=
// x.(interface{...}); ok` initializer and the asserted expression x.
func assertedInterfaceVar(ifStmt *ast.IfStmt) (string, ast.Expr) {
	assign, ok := ifStmt.Init.(*ast.AssignStmt)
	if !ok || len(assign.Lhs) == 0 || len(assign.Rhs) != 1 {
		return "", nil
	}
	typeAssert, ok := assign.Rhs[0].(*ast.TypeAssertExpr)
	if !ok {
		return "", nil
	}
	if _, ok := typeAssert.Type.(*ast.InterfaceType); !ok {
		return "", nil
	}
	ident, ok := assign.Lhs[0].(*ast.Ident)
	if !ok || ident.Name == "_" {
		return "", nil
	}
	return ident.Name, typeAssert.X
}

// isParamName reports whether the expression is a parameter of the function.
func isParamName(fn *ast.FuncDecl, expr ast.Expr) bool {
	ident, ok := expr.(*ast.Ident)
	return ok && fieldListsContainName(ident.Name, fn.Type.Params)
}

// returnsMethodCallOn reports whether the block returns the result of a method
// called on the named variable.
func returnsMethodCallOn(body *ast.BlockStmt, name string) bool {
	for _, stmt := range body.List {
		ret, ok := stmt.(*ast.ReturnStmt)
		if !ok {
			continue
		}
		for _, result := range ret.Results {
			call, ok := result.(*ast.CallExpr)
			if !ok {
				continue
			}
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
				if recv, ok := sel.X.(*ast.Ident); ok && recv.Name == name {
					return true
				}
			}
		}
	}
	return false
}

// isFalseIdent reports whether the expression is the false identifier.
func isFalseIdent(expr ast.Expr) bool {
	ident, ok := expr.(*ast.Ident)
	return ok && ident.Name == "false"
}

// containsAnonymousInterfaceAssertion recursively checks if any nested if has assertion
func (r *AnonInterfaceDegradationRule) containsAnonymousInterfaceAssertion(ifStmt *ast.IfStmt) bool {
	// Check this if's init statement
	if r.hasAnonymousInterfaceAssertion(ifStmt) {
		return true
	}

	// Check nested ifs in body
	if ifStmt.Body != nil {
		for _, stmt := range ifStmt.Body.List {
			if nested, ok := stmt.(*ast.IfStmt); ok {
				if r.containsAnonymousInterfaceAssertion(nested) {
					return true
				}
			}
		}
	}

	// Check else branch
	if ifStmt.Else != nil {
		if elseIf, ok := ifStmt.Else.(*ast.IfStmt); ok {
			if r.containsAnonymousInterfaceAssertion(elseIf) {
				return true
			}
		}
		if elseBlock, ok := ifStmt.Else.(*ast.BlockStmt); ok {
			for _, stmt := range elseBlock.List {
				if nested, ok := stmt.(*ast.IfStmt); ok {
					if r.containsAnonymousInterfaceAssertion(nested) {
						return true
					}
				}
			}
		}
	}

	return false
}

// hasAnonymousInterfaceAssertion checks if ifStmt contains type assertion on anonymous interface
func (r *AnonInterfaceDegradationRule) hasAnonymousInterfaceAssertion(ifStmt *ast.IfStmt) bool {
	// Check init statement: if _, ok := x.(interface{...}); ok
	if ifStmt.Init != nil {
		if assign, ok := ifStmt.Init.(*ast.AssignStmt); ok {
			for _, rhs := range assign.Rhs {
				if r.isAnonymousInterfaceAssertion(rhs) {
					return true
				}
			}
		}
	}

	// Check nested if in body
	if ifStmt.Body != nil {
		for _, stmt := range ifStmt.Body.List {
			if nested, ok := stmt.(*ast.IfStmt); ok {
				if r.hasAnonymousInterfaceAssertion(nested) {
					return true
				}
			}
		}
	}

	return false
}

// isAnonymousInterfaceAssertion checks if expr is x.(interface{...})
func (r *AnonInterfaceDegradationRule) isAnonymousInterfaceAssertion(expr ast.Expr) bool {
	typeAssert, ok := expr.(*ast.TypeAssertExpr)
	if !ok {
		return false
	}

	// Check if asserting to interface type
	_, ok = typeAssert.Type.(*ast.InterfaceType)
	return ok
}

// isDegradationReturn checks if return looks like a silent degradation value
func (r *AnonInterfaceDegradationRule) isDegradationReturn(ret *ast.ReturnStmt) bool {
	if len(ret.Results) == 0 {
		return false
	}

	// Check if any result is an explicit error (fmt.Errorf, errors.New)
	// This is NOT a degradation - it's proper error handling
	for _, result := range ret.Results {
		if exprCarriesError(result) {
			return false
		}
	}

	for _, result := range ret.Results {
		if r.isMagicValue(result) {
			return true
		}
	}

	return false
}

// isMagicValue checks if expression is a magic/zero value (constant, empty struct, nil)
func (r *AnonInterfaceDegradationRule) isMagicValue(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.BasicLit:
		// Literal values like 0, "", 5
		return true

	case *ast.Ident:
		// nil, false, true
		name := e.Name
		return name == "nil" || name == "false" || name == "true"

	case *ast.CompositeLit:
		// Empty struct: SomeType{}, []string{}
		return len(e.Elts) == 0

	case *ast.BinaryExpr:
		// Duration expressions: 5 * time.Second
		if e.Op == token.MUL {
			return r.isMagicValue(e.X) || r.isMagicValue(e.Y)
		}

	case *ast.UnaryExpr:
		// Negative numbers: -1
		return r.isMagicValue(e.X)

	case *ast.SelectorExpr:
		// time.Second, etc - part of duration expression
		if ident, ok := e.X.(*ast.Ident); ok {
			return ident.Name == "time"
		}
	}

	return false
}
