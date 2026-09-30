package patterns

import (
	"go/ast"
	"strconv"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewDeprecatedIoutilRule())
}

// ioutilReplacements maps each io/ioutil identifier to the drop-in
// replacement a fixer may substitute. ReadDir has none: os.ReadDir returns
// []fs.DirEntry instead of []fs.FileInfo, so its callers change too.
var ioutilReplacements = map[string]string{
	"ReadAll":   "io.ReadAll",
	"ReadFile":  "os.ReadFile",
	"WriteFile": "os.WriteFile",
	"TempDir":   "os.MkdirTemp",
	"TempFile":  "os.CreateTemp",
	"NopCloser": "io.NopCloser",
	"Discard":   "io.Discard",
}

// DeprecatedIoutilRule detects usage of deprecated io/ioutil package
type DeprecatedIoutilRule struct {
	*rules.BaseRule
}

// NewDeprecatedIoutilRule creates the rule
func NewDeprecatedIoutilRule() *DeprecatedIoutilRule {
	return &DeprecatedIoutilRule{
		BaseRule: rules.NewBaseRule(
			"deprecated-ioutil",
			"patterns",
			"Detects deprecated io/ioutil package usage (use io and os packages instead)",
			core.SeverityMedium,
		),
	}
}

// AnalyzeFile reports the io/ioutil imports of the file and every selector on
// the name they are imported under. The syntax tree decides what is code:
// text in strings and comments is not, and a package that merely ends in
// "ioutil" is another package.
func (r *DeprecatedIoutilRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || ctx.GoAST == nil {
		return nil
	}

	var violations []*core.Violation
	names := make(map[string]bool)
	for _, spec := range ctx.GoAST.Imports {
		importPath, err := strconv.Unquote(spec.Path.Value)
		if err != nil || importPath != "io/ioutil" {
			continue
		}
		name := "ioutil"
		if spec.Name != nil {
			name = spec.Name.Name
		}
		if name != "_" && name != "." {
			names[name] = true
		}
		line := ctx.LineFor(spec)
		v := r.CreateViolation(ctx.RelPath, line, "io/ioutil is deprecated since Go 1.16")
		v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
		v.WithSuggestion("Use io.ReadAll, os.ReadFile, os.WriteFile instead")
		violations = append(violations, v)
	}
	if len(names) == 0 {
		return violations
	}

	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		selector, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		qualifier, ok := selector.X.(*ast.Ident)
		if !ok || !names[qualifier.Name] {
			return true
		}
		violations = append(violations, r.reportUse(ctx, selector))
		return true
	})

	return violations
}

func (r *DeprecatedIoutilRule) reportUse(ctx *core.FileContext, selector *ast.SelectorExpr) *core.Violation {
	pos := ctx.PositionFor(selector)
	v := r.CreateViolation(ctx.RelPath, pos.Line, "ioutil functions are deprecated")
	v.WithColumn(pos.Column)
	v.WithCode(strings.TrimSpace(ctx.GetLine(pos.Line)))
	v.WithContext("ioutil_function", selector.Sel.Name)

	replacement, ok := ioutilReplacements[selector.Sel.Name]
	switch {
	case ok:
		v.WithSuggestion("Replace with " + replacement)
		v.WithContext("replacement", replacement)
	case selector.Sel.Name == "ReadDir":
		v.WithSuggestion("Replace with os.ReadDir, which returns []fs.DirEntry instead of []fs.FileInfo")
	default:
		v.WithSuggestion("Replace with equivalent functions from io or os packages")
	}
	return v
}
