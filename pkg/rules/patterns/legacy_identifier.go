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
// name contains a Legacy/legacy segment. Comments are covered by the separate
// legacy-comment-marker and deprecated-comment rules; this one exists because renaming a symbol to
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
//   - Test files (generated files are dropped by the core for every rule)
//   - //nolint:legacy-identifier opt-outs on the declaration line
type LegacyIdentifierRule struct { // legacy-identifier: safe — named after the marker this rule detects
	*rules.BaseRule
	legacyPattern *regexp.Regexp
}

// NewLegacyIdentifierRule creates the rule
func NewLegacyIdentifierRule() *LegacyIdentifierRule { // legacy-identifier: safe — named after the marker this rule detects
	return &LegacyIdentifierRule{
		BaseRule: rules.NewBaseRule(
			"legacy-identifier",
			"patterns",
			"Detects identifiers named Legacy/legacy_ (functions, types, vars) — rename or remove",
			core.SeverityMedium,
		),
		// "Legacy" as a CamelCase segment (LegacyFoo, FooLegacy, FooLegacyBar,
		// registerLegacyRoutes) or "legacy" as a lowercase segment at a
		// name/underscore boundary (legacyMode, legacy_foo, handle_legacy_x).
		// The CamelCase boundary requires the preceding char to be
		// start-of-name, underscore, or *lowercase* (end of previous word —
		// e.g. "register" + "Legacy"); on both branches the following char
		// must start the next word (uppercase, underscore, digit) or end the
		// name — the same shape as mock-identifier's pattern.
		// Intentionally does not match incidental substrings like "legally".
		legacyPattern: regexp.MustCompile(`(^|[a-z_])Legacy([A-Z_0-9]|$)|(^|_)legacy([A-Z_0-9]|$)`),
	}
}

// AnalyzeFile checks for Legacy identifiers
func (r *LegacyIdentifierRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || ctx.IsTestFile() {
		return nil
	}

	if !ctx.HasGoAST() {
		return nil
	}

	var violations []*core.Violation

	forEachDeclaredName(ctx.GoAST, func(name *ast.Ident, kind string) {
		if !r.legacyPattern.MatchString(name.Name) {
			return
		}
		if v := r.violation(ctx, name.Pos(), name.Name, kind); v != nil {
			violations = append(violations, v)
		}
	})

	return violations
}

// violation builds a violation (or nil if opt-out is present on the line).
func (r *LegacyIdentifierRule) violation(ctx *core.FileContext, pos token.Pos, name, kind string) *core.Violation {
	line := ctx.GoFileSet.Position(pos).Line
	lineContent := ctx.GetLine(line)

	if ctx.LineSuppresses(line, "legacy-identifier") {
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
