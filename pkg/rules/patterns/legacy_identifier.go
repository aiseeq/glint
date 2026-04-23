package patterns

import (
	"go/ast"
	"go/token"
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewLegacyIdentifierRule())
}

// LegacyIdentifierRule detects identifiers (func/method/type/const/var) whose
// name contains "Legacy" / "legacy_". Comments are covered by the separate
// `deprecated-comment` rule; this one exists because renaming a symbol to
// include "Legacy" is a common way to ship a parallel implementation that
// never actually gets removed — the mirror of what CLAUDE.md forbids under
// "No legacy, only current code".
//
// Detects:
//   - func (Foo) RegisterLegacyRoutes(...)   — method with Legacy in name
//   - func buildLegacyPayload(...)            — function with Legacy in name
//   - type LegacyUser struct{}                — type with Legacy prefix/suffix
//   - var/const LegacyTimeout = ...           — value identifier
//
// Skips:
//   - Test files
//   - Generated files (*.gen.go, *_gen.go, /generated/)
//   - //nolint:legacy-identifier opt-outs on the declaration line
type LegacyIdentifierRule struct {
	*rules.BaseRule
	legacyPattern *regexp.Regexp
}

// NewLegacyIdentifierRule creates the rule
func NewLegacyIdentifierRule() *LegacyIdentifierRule {
	return &LegacyIdentifierRule{
		BaseRule: rules.NewBaseRule(
			"legacy-identifier",
			"patterns",
			"Detects identifiers named Legacy/legacy_ (functions, types, vars) — rename or remove",
			core.SeverityMedium,
		),
		// "Legacy" as a CamelCase segment (LegacyFoo, FooLegacy, FooLegacyBar,
		// registerLegacyRoutes) or "legacy" as a snake_case segment
		// (legacy_foo, handle_legacy_x). The CamelCase boundary requires the
		// preceding char to be start-of-name, underscore, or *lowercase* (end
		// of previous word — e.g. "register" + "Legacy"); the following char
		// must be start of next word (uppercase) or end.
		// Intentionally does not match incidental substrings like "legally".
		legacyPattern: regexp.MustCompile(`(^|[a-z_])Legacy([A-Z_]|$)|(^|_)legacy(_|$)`),
	}
}

// AnalyzeFile checks for Legacy identifiers
func (r *LegacyIdentifierRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || ctx.IsTestFile() {
		return nil
	}

	if r.shouldSkipFile(ctx) {
		return nil
	}

	if !ctx.HasGoAST() {
		return nil
	}

	var violations []*core.Violation

	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		switch decl := n.(type) {
		case *ast.FuncDecl:
			if r.legacyPattern.MatchString(decl.Name.Name) {
				if v := r.violation(ctx, decl.Name.Pos(), decl.Name.Name, r.funcKind(decl)); v != nil {
					violations = append(violations, v)
				}
			}
		case *ast.TypeSpec:
			if r.legacyPattern.MatchString(decl.Name.Name) {
				if v := r.violation(ctx, decl.Name.Pos(), decl.Name.Name, "type"); v != nil {
					violations = append(violations, v)
				}
			}
		case *ast.ValueSpec:
			for _, name := range decl.Names {
				if r.legacyPattern.MatchString(name.Name) {
					if v := r.violation(ctx, name.Pos(), name.Name, "var/const"); v != nil {
						violations = append(violations, v)
					}
				}
			}
		}
		return true
	})

	return violations
}

// funcKind returns "method" for receiver-bound funcs, "function" otherwise.
func (r *LegacyIdentifierRule) funcKind(fn *ast.FuncDecl) string {
	if fn.Recv != nil && len(fn.Recv.List) > 0 {
		return "method"
	}
	return "function"
}

// violation builds a violation (or nil if opt-out is present on the line).
func (r *LegacyIdentifierRule) violation(ctx *core.FileContext, pos token.Pos, name, kind string) *core.Violation {
	line := ctx.GoFileSet.Position(pos).Line
	lineContent := ctx.GetLine(line)

	if strings.Contains(lineContent, "nolint:legacy-identifier") {
		return nil
	}

	v := r.CreateViolation(ctx.RelPath, line,
		"Legacy identifier: "+kind+" "+name)
	v.WithCode(strings.TrimSpace(lineContent))
	v.WithSuggestion("Rename the " + kind + " to drop the 'Legacy' marker (if it's current code) or delete it " +
		"(if it's dead). CLAUDE.md: 'No legacy, only current code'. Git remembers history.")
	v.WithContext("kind", kind)
	v.WithContext("name", name)
	return v
}

// shouldSkipFile excludes generated files.
func (r *LegacyIdentifierRule) shouldSkipFile(ctx *core.FileContext) bool {
	path := ctx.RelPath
	if strings.HasSuffix(path, ".gen.go") || strings.HasSuffix(path, "_gen.go") {
		return true
	}
	if strings.Contains(path, "/generated/") || strings.Contains(path, "vendor/") {
		return true
	}
	return false
}
