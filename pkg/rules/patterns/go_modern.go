package patterns

import (
	"go/ast"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewGoModernRule())
}

// GoModernRule detects uses of reflect.SliceHeader and reflect.StringHeader,
// deprecated since Go 1.20 in favour of unsafe.Slice, unsafe.SliceData,
// unsafe.String and unsafe.StringData. The headers are found wherever they
// appear as a type — a conversion (*reflect.SliceHeader)(unsafe.Pointer(&b)),
// a variable, a field — with reflect resolved through the file's imports.
type GoModernRule struct {
	*rules.BaseRule
}

// NewGoModernRule creates the rule
func NewGoModernRule() *GoModernRule {
	return &GoModernRule{
		BaseRule: rules.NewBaseRule(
			"go-modern",
			"patterns",
			"Detects deprecated reflect.SliceHeader/StringHeader (Go 1.20+: use unsafe.Slice/SliceData/String/StringData)",
			core.SeverityLow,
		),
	}
}

// deprecatedReflectHeaders are the reflect types unsafe.* replaced.
var deprecatedReflectHeaders = map[string]bool{
	"SliceHeader":  true,
	"StringHeader": true,
}

// AnalyzeFile checks for deprecated reflect header types
func (r *GoModernRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || ctx.GoAST == nil {
		return nil
	}
	reflectNames := helpers.PackageAliases(ctx.GoAST, `"reflect"`, "reflect")
	if len(reflectNames) == 0 {
		return nil
	}

	var violations []*core.Violation

	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok || !deprecatedReflectHeaders[sel.Sel.Name] {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok || !reflectNames[pkg.Name] {
			return true
		}
		name := "reflect." + sel.Sel.Name
		pos := ctx.PositionFor(sel)
		v := r.CreateViolation(ctx.RelPath, pos.Line,
			name+" is deprecated, use unsafe.Slice/unsafe.String instead")
		v.WithCode(ctx.GetLine(pos.Line))
		v.WithSuggestion("Use unsafe.Slice, unsafe.SliceData, unsafe.String and unsafe.StringData (Go 1.20+)")
		v.WithContext("pattern", "deprecated-reflect")
		violations = append(violations, v)
		return true
	})

	return violations
}
