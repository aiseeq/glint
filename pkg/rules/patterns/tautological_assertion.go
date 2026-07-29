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
	rules.Register(NewTautologicalAssertionRule())
}

// TautologicalAssertionRule detects tests that cannot fail.
//
// A green suite is trusted, so an assertion that holds no matter what the code does is worse
// than no test at all: it claims coverage of exactly the behaviour nobody is watching.
//
// Three shapes, all seen in production repositories:
//   - both sides of an equality assertion are the same expression;
//   - the asserted value is a literal constant (expect(true).toBe(true));
//   - the assertion sits inside a condition derived from the same value, so it skips itself
//     precisely when the value would have been interesting.
//
// Real case (ProjectA, 2026-07-29): a regression test named "withdrawal and analytics headline
// numbers stay in lockstep" compared displayedBalance with displayedBalance and documented a
// contract the code did not have. It stayed green while the two screens drifted apart and
// started showing different balances.
type TautologicalAssertionRule struct {
	*rules.BaseRule

	tsEquality   *regexp.Regexp
	tsConstant   *regexp.Regexp
	tsCondition  *regexp.Regexp
	tsAssert     *regexp.Regexp
	tsAssignment *regexp.Regexp
	tsPureRead   *regexp.Regexp
}

// NewTautologicalAssertionRule creates the rule
func NewTautologicalAssertionRule() *TautologicalAssertionRule {
	return &TautologicalAssertionRule{
		BaseRule: rules.NewBaseRule(
			"tautological-assertion",
			"patterns",
			"Detects assertions that cannot fail: value compared with itself, constant asserted, or assertion skipped by its own subject",
			core.SeverityHigh,
		),
		tsEquality:  regexp.MustCompile(`expect\s*\(\s*(.+?)\s*\)\s*\.\s*(?:toBe|toEqual|toStrictEqual)\s*\(\s*(.+?)\s*\)\s*;?\s*$`),
		tsConstant:  regexp.MustCompile(`^(?:true|false|null|undefined|-?\d+(?:\.\d+)?|'[^']*'|"[^"]*"|` + "`[^`]*`" + `)$`),
		tsCondition: regexp.MustCompile(`^\s*if\s*\(\s*([A-Za-z_$][\w$.]*)\s*(?:[<>!=]=?|>|<)`),
		tsAssert:    regexp.MustCompile(`expect\s*\(\s*([A-Za-z_$][\w$.]*)\s*\)\s*\.\s*(?:toBe|toEqual|toStrictEqual|toBeGreaterThan|toBeLessThan|toBeGreaterThanOrEqual|toBeLessThanOrEqual|toBeCloseTo)`),
		// Test-local variable declaration: needed to catch a comparison of two names that
		// stand for the very same expression.
		tsAssignment: regexp.MustCompile(`^\s*(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=]+)?=\s*(.+?);?\s*$`),
		// A pure read: a property access, optionally wrapped in a number or string parse.
		// Calls into production code stay out — comparing two calls can be a deliberate
		// idempotence check rather than a tautology.
		tsPureRead: regexp.MustCompile(`^(?:(?:parseFloat|parseInt|Number|String|Boolean)\s*\(\s*)?[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+\s*(?:,\s*\d+\s*)?\)?$`),
	}
}

// AnalyzeFile inspects test files only: an assertion outside a test is not an assertion.
func (r *TautologicalAssertionRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsTestFile() {
		return nil
	}

	if ctx.IsGoFile() {
		return r.analyzeGo(ctx)
	}
	if ctx.IsTypeScriptFile() || ctx.IsJavaScriptFile() {
		return r.analyzeTypeScript(ctx)
	}
	return nil
}

// --- Go ---------------------------------------------------------------------

// goEqualityAsserts are testify calls whose two value arguments must differ to mean anything.
var goEqualityAsserts = map[string]bool{
	"Equal": true, "EqualValues": true, "Same": true, "NotEqual": true, "Exactly": true,
}

// goTruthAsserts are testify calls whose single argument must not be a literal.
var goTruthAsserts = map[string]bool{
	"True": true, "False": true, "Nil": true, "NotNil": true, "Empty": true, "NotEmpty": true,
}

func (r *TautologicalAssertionRule) analyzeGo(ctx *core.FileContext) []*core.Violation {
	if ctx.GoAST == nil {
		return nil
	}

	var violations []*core.Violation

	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok || (pkg.Name != "assert" && pkg.Name != "require") {
			return true
		}

		method := sel.Sel.Name
		args := call.Args
		if len(args) > 0 {
			if ident, ok := args[0].(*ast.Ident); ok && ident.Name == "t" {
				args = args[1:]
			}
		}

		switch {
		case goEqualityAsserts[method] && len(args) >= 2:
			left := renderExpr(ctx, args[0])
			right := renderExpr(ctx, args[1])
			if left != "" && left == right {
				violations = append(violations, r.violation(ctx, ctx.LineFor(call),
					"Assertion compares '"+left+"' with itself — it holds whatever the code does",
					"Compare the value produced by the code under test against an expected value stated independently",
					"self_comparison"))
			}
		case goTruthAsserts[method] && len(args) >= 1:
			if isGoLiteral(args[0]) {
				violations = append(violations, r.violation(ctx, ctx.LineFor(call),
					"Assertion checks a literal constant — the test cannot fail",
					"Assert a value produced by the code under test, or delete the test instead of claiming coverage",
					"constant_assertion"))
			}
		}
		return true
	})

	return violations
}

// renderExpr returns the source text of an expression. Offsets are resolved through the
// FileSet rather than used raw: token.Pos is a global position, not an index into this file.
func renderExpr(ctx *core.FileContext, expr ast.Expr) string {
	if ctx.GoFileSet == nil {
		return ""
	}
	start := ctx.GoFileSet.Position(expr.Pos()).Offset
	end := ctx.GoFileSet.Position(expr.End()).Offset
	if start < 0 || end > len(ctx.Content) || start >= end {
		return ""
	}
	return string(ctx.Content[start:end])
}

// isGoLiteral reports whether the expression is a bare constant: true, false, nil, a number
// or a string. Those carry no information about the code under test.
func isGoLiteral(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name == "true" || e.Name == "false" || e.Name == "nil"
	case *ast.BasicLit:
		return e.Kind == token.INT || e.Kind == token.FLOAT || e.Kind == token.STRING
	}
	return false
}

// --- TypeScript -------------------------------------------------------------

func (r *TautologicalAssertionRule) analyzeTypeScript(ctx *core.FileContext) []*core.Violation {
	var violations []*core.Violation
	pureReads := r.collectPureReads(ctx)

	for i, line := range ctx.Lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*") {
			continue
		}

		if v := r.checkTSEquality(ctx, i, trimmed, pureReads); v != nil {
			violations = append(violations, v)
			continue
		}
		if v := r.checkTSSelfSkipping(ctx, i); v != nil {
			violations = append(violations, v)
		}
	}

	return violations
}

// collectPureReads records variables assigned a pure read. Two variables with the same
// right-hand side are one value under two names; comparing them looks like a consistency
// check but is not one.
func (r *TautologicalAssertionRule) collectPureReads(ctx *core.FileContext) map[string]string {
	reads := map[string]string{}
	for _, line := range ctx.Lines {
		m := r.tsAssignment.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		name, value := m[1], strings.TrimSpace(m[2])
		if r.tsPureRead.MatchString(value) {
			reads[name] = value
		}
	}
	return reads
}

func (r *TautologicalAssertionRule) checkTSEquality(ctx *core.FileContext, index int, line string, pureReads map[string]string) *core.Violation {
	m := r.tsEquality.FindStringSubmatch(line)
	if m == nil {
		return nil
	}
	actual, expected := m[1], m[2]

	// Different names backed by the same read: exactly the shape in which the balance
	// consistency regression compared displayedBalance with itself.
	if actual != expected {
		left, leftOK := pureReads[actual]
		right, rightOK := pureReads[expected]
		if leftOK && rightOK && left == right {
			return r.violation(ctx, index+1,
				"'"+actual+"' and '"+expected+"' both come from '"+left+"' — the comparison cannot fail",
				"Compare the value produced by the code under test against an expected value stated independently",
				"self_comparison")
		}
	}

	if actual == expected {
		if r.tsConstant.MatchString(actual) {
			return r.violation(ctx, index+1,
				"Assertion checks a literal constant — the test cannot fail",
				"Assert a value produced by the code under test, or delete the test instead of claiming coverage",
				"constant_assertion")
		}
		return r.violation(ctx, index+1,
			"Assertion compares '"+actual+"' with itself — it holds whatever the code does",
			"Compare the value produced by the code under test against an expected value stated independently",
			"self_comparison")
	}

	return nil
}

// checkTSSelfSkipping finds an assertion guarded by a condition over the very value it
// asserts: when the value is wrong in the guarded direction the assertion never runs.
// Real case: `if (availability > 0) expect(availability).toBeGreaterThan(95)` — a service
// reporting zero availability passed the test silently.
func (r *TautologicalAssertionRule) checkTSSelfSkipping(ctx *core.FileContext, index int) *core.Violation {
	cond := r.tsCondition.FindStringSubmatch(ctx.Lines[index])
	if cond == nil {
		return nil
	}
	subject := cond[1]

	block, end := collectBraceBlock(ctx.Lines, index)
	if end <= index {
		return nil
	}
	// An else branch means the other case is asserted too.
	if strings.Contains(block, "else") {
		return nil
	}

	for _, m := range r.tsAssert.FindAllStringSubmatch(block, -1) {
		if m[1] == subject {
			return r.violation(ctx, index+1,
				"Assertion is guarded by a condition over '"+subject+"' — it skips itself exactly when the value is wrong",
				"Assert unconditionally, or assert the guard itself so an unexpected value fails the test",
				"self_skipping")
		}
	}

	return nil
}

func (r *TautologicalAssertionRule) violation(ctx *core.FileContext, line int, message, suggestion, kind string) *core.Violation {
	v := r.CreateViolation(ctx.RelPath, line, message)
	v.WithCode(ctx.GetLine(line))
	v.WithSuggestion(suggestion)
	v.WithContext("pattern", "tautological_assertion")
	v.WithContext("kind", kind)
	return v
}
