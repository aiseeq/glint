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

	// Skip test utility files
	pathLower := strings.ToLower(ctx.RelPath)
	if strings.Contains(pathLower, "/test") || strings.Contains(pathLower, "test_") {
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
				if r.isDegradationReturn(ret) {
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
