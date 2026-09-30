package typesafety

import (
	"go/ast"
	"go/types"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewInterfaceAnyRule())
}

// InterfaceAnyRule detects interface{} usage that should be replaced with 'any'.
// It reads the syntax tree, so interface{} inside strings and comments is
// data, and it stays silent where 'any' would not compile: in a module older
// than Go 1.18 and where the package declares its own 'any'.
type InterfaceAnyRule struct {
	*rules.BaseRule
}

// NewInterfaceAnyRule creates the rule
func NewInterfaceAnyRule() *InterfaceAnyRule {
	return &InterfaceAnyRule{
		BaseRule: rules.NewBaseRule(
			"interface-any",
			"typesafety",
			"Detects interface{} that should be replaced with 'any' (Go 1.18+ modules only)",
			core.SeverityMedium,
		),
	}
}

// AnalyzeFile reports nothing: whether 'any' compiles depends on the Go version
// of the module, which only the project analysis knows.
func (r *InterfaceAnyRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *InterfaceAnyRule) RequiresSSA() bool { return false }

// AnalyzeGoProject checks every Go file of the project against the Go version
// of the module it belongs to.
func (r *InterfaceAnyRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	versions := helpers.NewGoVersions(ctx)
	return rules.AnalyzeGoFiles(ctx, r.Name(), func(fileCtx *core.FileContext, info *types.Info) []*core.Violation {
		return r.analyze(fileCtx, info, versions)
	})
}

func (r *InterfaceAnyRule) analyze(ctx *core.FileContext, info *types.Info, versions *helpers.GoVersions) []*core.Violation {
	if !ctx.IsGoFile() || ctx.GoAST == nil {
		return nil
	}
	if !versions.AtLeast(ctx, info, "go1.18") || anyIsShadowed(ctx.GoAST, info) {
		return nil
	}

	var violations []*core.Violation
	var stack []ast.Node
	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		var parent ast.Node
		if len(stack) > 0 {
			parent = stack[len(stack)-1]
		}
		stack = append(stack, n)

		iface, ok := n.(*ast.InterfaceType)
		if !ok || iface.Incomplete || (iface.Methods != nil && len(iface.Methods.List) > 0) {
			return true
		}
		pattern := interfaceAnyPattern(iface, parent)
		pos := ctx.PositionFor(iface)
		if r.isAllowedException(ctx, pos.Line, pattern) {
			return true
		}
		v := r.CreateViolation(ctx.RelPath, pos.Line, r.getMessage(pattern))
		v.WithColumn(pos.Column)
		v.WithCode(strings.TrimSpace(ctx.GetLine(pos.Line)))
		v.WithSuggestion(r.getSuggestion(pattern))
		v.WithContext("pattern", pattern)
		violations = append(violations, v)
		return true
	})

	return violations
}

// interfaceAnyPattern names the construct the empty interface is part of, so
// the message can name the replacement the reader sees in the code.
func interfaceAnyPattern(iface *ast.InterfaceType, parent ast.Node) string {
	switch p := parent.(type) {
	case *ast.MapType:
		if key, ok := p.Key.(*ast.Ident); ok && key.Name == "string" && p.Value == iface {
			return "map[string]interface{}"
		}
	case *ast.ArrayType:
		if p.Len == nil && p.Elt == iface {
			return "[]interface{}"
		}
	}
	return "interface{}"
}

// anyIsShadowed reports whether 'any' in this file may mean something other
// than the predeclared alias. With type information the package and file
// scopes answer; without it only the file's own declarations are known.
func anyIsShadowed(file *ast.File, info *types.Info) bool {
	if info != nil {
		fileScope := info.Scopes[file]
		if fileScope == nil {
			return true
		}
		if fileScope.Lookup("any") != nil || (fileScope.Parent() != nil && fileScope.Parent().Lookup("any") != nil) {
			return true
		}
		declared := false
		ast.Inspect(file, func(n ast.Node) bool {
			if ident, ok := n.(*ast.Ident); ok && ident.Name == "any" && info.Defs[ident] != nil {
				declared = true
			}
			return !declared
		})
		return declared
	}
	return helpers.DeclaresName(file, "any")
}

func (r *InterfaceAnyRule) isAllowedException(ctx *core.FileContext, line int, pattern string) bool {
	// Test files: allow map[string]interface{} for flexible test data
	if ctx.IsTestFile() && pattern == "map[string]interface{}" {
		return true
	}

	text := ctx.GetLine(line)
	// JWT library callback signature
	if strings.Contains(text, "func(token *jwt.Token) (interface{}, error)") {
		return true
	}

	// JSON unmarshaling may require interface{}
	return strings.Contains(text, "json.Unmarshal")
}

func (r *InterfaceAnyRule) getMessage(patternName string) string {
	switch patternName {
	case "map[string]interface{}":
		return "Use 'map[string]any' instead of 'map[string]interface{}' (Go 1.18+)"
	case "[]interface{}":
		return "Use '[]any' instead of '[]interface{}' (Go 1.18+)"
	default:
		return "Use 'any' instead of 'interface{}' (Go 1.18+)"
	}
}

func (r *InterfaceAnyRule) getSuggestion(patternName string) string {
	switch patternName {
	case "map[string]interface{}":
		return "Replace with 'map[string]any' or define a typed struct"
	case "[]interface{}":
		return "Replace with '[]any' or use generics for type safety"
	default:
		return "Replace with 'any' type alias"
	}
}
