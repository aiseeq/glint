package patterns

import (
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewBigSetStringUncheckedRule())
}

// BigSetStringUncheckedRule detects a SetString on a math/big value whose ok
// result is dropped:
//
//	value := new(big.Int)
//	value.SetString(strings.TrimPrefix(hexValue, "0x"), 16)
//
// On text that does not parse SetString reports false and leaves the value
// undefined (zero in practice): the amount silently becomes 0 instead of the
// call failing. Check the ok result and return an error.
type BigSetStringUncheckedRule struct {
	*rules.BaseRule
}

// NewBigSetStringUncheckedRule creates the rule
func NewBigSetStringUncheckedRule() *BigSetStringUncheckedRule {
	return &BigSetStringUncheckedRule{BaseRule: rules.NewBaseRule(
		"big-setstring-unchecked",
		"patterns",
		"Detects SetString on big.Int/Float/Rat with the ok result dropped — unparsable text silently becomes zero",
		core.SeverityHigh,
	)}
}

// AnalyzeFile is a no-op: the project analysis checks every file.
func (r *BigSetStringUncheckedRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *BigSetStringUncheckedRule) RequiresSSA() bool { return false }

// AnalyzeGoProject checks every file, tests included: a fixture parsed to
// zero makes the test assert on the wrong value.
func (r *BigSetStringUncheckedRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	return rules.AnalyzeGoFiles(ctx, r.Name(), r.analyze)
}

// analyze reports the dropped SetString results of a file. info is nil for a
// file without type information.
func (r *BigSetStringUncheckedRule) analyze(ctx *core.FileContext, info *types.Info) []*core.Violation {
	if !ctx.IsGoFile() || ctx.GoAST == nil {
		return nil
	}
	var violations []*core.Violation
	report := func(call *ast.CallExpr) {
		if !isBigSetString(call, info, ctx.GoAST) {
			return
		}
		line := ctx.LineFor(call)
		if ctx.IsSuppressed(line, r.Name()) {
			return
		}
		v := r.CreateViolation(ctx.RelPath, line, "SetString result is dropped — on text that does not parse the value silently stays zero")
		v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
		v.WithSuggestion("Take the ok result and fail on false: if _, ok := v.SetString(s, 16); !ok { return fmt.Errorf(...) }")
		violations = append(violations, v)
	}
	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.ExprStmt:
			if call, ok := ast.Unparen(node.X).(*ast.CallExpr); ok {
				report(call)
			}
		case *ast.AssignStmt:
			if len(node.Lhs) == 2 && len(node.Rhs) == 1 && isBlank(node.Lhs[1]) {
				if call, ok := ast.Unparen(node.Rhs[0]).(*ast.CallExpr); ok {
					report(call)
				}
			}
		case *ast.ValueSpec:
			if len(node.Names) == 2 && len(node.Values) == 1 && node.Names[1].Name == "_" {
				if call, ok := ast.Unparen(node.Values[0]).(*ast.CallExpr); ok {
					report(call)
				}
			}
		}
		return true
	})
	return violations
}

func isBlank(expr ast.Expr) bool {
	id, ok := expr.(*ast.Ident)
	return ok && id.Name == "_"
}

// isBigSetString reports a call of SetString on a math/big Int, Float or
// Rat. Without type information only the Int form is recognised — two
// arguments, the base an integer literal — in a file importing math/big.
func isBigSetString(call *ast.CallExpr, info *types.Info, file *ast.File) bool {
	sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "SetString" {
		return false
	}
	if info != nil {
		fn, ok := info.Uses[sel.Sel].(*types.Func)
		return ok && fn.Pkg() != nil && fn.Pkg().Path() == "math/big"
	}
	if !importsPackage(file, "math/big") || len(call.Args) != 2 {
		return false
	}
	base, ok := call.Args[1].(*ast.BasicLit)
	return ok && base.Kind == token.INT
}

// importsPackage reports whether the file imports the package path.
func importsPackage(file *ast.File, importPath string) bool {
	for _, spec := range file.Imports {
		if strings.Trim(spec.Path.Value, "\"`") == importPath {
			return true
		}
	}
	return false
}
