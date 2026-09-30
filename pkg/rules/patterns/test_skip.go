package patterns

import (
	"go/ast"
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewSkippedTestRule())
}

// SkippedTestRule detects tests switched off with no reason on record:
//
//	test.describe.skip('checkout', () => { ... })   // the whole suite
//	xit('refund', () => { ... })
//	test.skip('refund', async () => { ... })
//
//	func TestRefund(t *testing.T) {
//	    t.Skip("flaky")                              // always skips
//
//	//go:build ignore                                // on a _test.go file
//
// A skip hides a broken test instead of fixing it, and nobody sees the suite
// go quiet. A skip decided at run time — test.skip(condition, ...), t.Skip
// inside an if or a switch — adapts to the environment and is not reported;
// neither is a TypeScript skip with a reason on its line or in the comment
// right above it: a ticket key, a link, a TODO or the word reason or because. An unconditional t.Skip is reported
// whatever its message: the test never runs.
type SkippedTestRule struct {
	*rules.BaseRule
}

// NewSkippedTestRule creates the rule
func NewSkippedTestRule() *SkippedTestRule {
	return &SkippedTestRule{BaseRule: rules.NewBaseRule(
		"skipped-test",
		"patterns",
		"Detects tests switched off without a reason: describe.skip, xit, test.skip('...'), unconditional t.Skip, //go:build ignore on a test file",
		core.SeverityMedium,
	)}
}

var (
	// jsStaticSkip is a suite or a test skipped by declaration: its title
	// (a string) comes first, so no condition decides it.
	jsStaticSkip = regexp.MustCompile(`(?:^|[^\w$.])(?:(?:test\.)?describe\.(?:skip|fixme)|(?:test|it)\.(?:skip|fixme))\s*\(\s*['"` + "`" + `]|(?:^|[^\w$.])x(?:describe|it|test)\s*\(`)
	// skipReason is a reason written beside a skip.
	skipReason = regexp.MustCompile(`\b[A-Z][A-Z0-9]+-\d+\b|https?://|\bTODO\b|(?i:\breason|\bbecause\b|причин|потому)`)
	// goBuildIgnore is a build constraint that keeps a file out of every build.
	goBuildIgnore = regexp.MustCompile(`^//\s*(?:go:build|\+build)\s+ignore\s*$`)
)

// AnalyzeFile reports the skips of a test file.
func (r *SkippedTestRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsTestFile() {
		return nil
	}
	if ctx.IsTypeScriptFile() || ctx.IsJavaScriptFile() {
		return r.analyzeJS(ctx)
	}
	if strings.HasSuffix(ctx.Path, "_test.go") && ctx.HasGoAST() {
		return r.analyzeGo(ctx)
	}
	return nil
}

func (r *SkippedTestRule) analyzeJS(ctx *core.FileContext) []*core.Violation {
	var violations []*core.Violation
	code := newJSSource(ctx).code
	for i, line := range code {
		if !jsStaticSkip.MatchString(line) || skipReasonBeside(ctx.Lines, code, i) {
			continue
		}
		violations = append(violations, r.report(ctx, i+1,
			"Test switched off with no reason beside it — the suite goes quiet while the test stays broken",
			"Fix the test or delete it; a skip that must stay says why, with a ticket, on the line above"))
	}
	return violations
}

// skipReasonBeside reports a reason on the skip's own line or in the comment
// lines right above it — never on a neighbouring skip or other code.
func skipReasonBeside(lines, code []string, i int) bool {
	if skipReason.MatchString(lines[i]) {
		return true
	}
	for j := i - 1; j >= 0; j-- {
		comment := strings.TrimSpace(code[j]) == "" && strings.TrimSpace(lines[j]) != ""
		if !comment {
			return false
		}
		if skipReason.MatchString(lines[j]) {
			return true
		}
	}
	return false
}

func (r *SkippedTestRule) analyzeGo(ctx *core.FileContext) []*core.Violation {
	var violations []*core.Violation
	for _, group := range ctx.GoAST.Comments {
		if group.Pos() >= ctx.GoAST.Package {
			break
		}
		for _, comment := range group.List {
			if goBuildIgnore.MatchString(comment.Text) {
				line := ctx.LineForPos(comment.Pos())
				violations = append(violations, r.report(ctx, line,
					"The test file is built never — //go:build ignore switches the whole suite off",
					"Remove the constraint and fix the tests, or delete the file"))
			}
		}
	}
	for _, decl := range ctx.GoAST.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil {
			violations = append(violations, r.unconditionalSkips(ctx, fn.Body.List)...)
		}
	}
	return violations
}

// unconditionalSkips reports t.Skip as a statement of a test body itself,
// and of the subtests it runs, outside any if, switch or loop.
func (r *SkippedTestRule) unconditionalSkips(ctx *core.FileContext, stmts []ast.Stmt) []*core.Violation {
	var violations []*core.Violation
	for _, stmt := range stmts {
		expr, ok := stmt.(*ast.ExprStmt)
		if !ok {
			continue
		}
		call, ok := expr.X.(*ast.CallExpr)
		if !ok {
			continue
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			continue
		}
		switch sel.Sel.Name {
		case "Skip", "Skipf", "SkipNow":
			if _, isIdent := sel.X.(*ast.Ident); isIdent {
				violations = append(violations, r.report(ctx, ctx.LineFor(call),
					"Unconditional skip — the test never runs, whatever it would find",
					"Fix the cause and remove the skip; a skip that stays is conditional (testing.Short, a missing credential)"))
			}
		case "Run":
			for _, arg := range call.Args {
				if lit, isLit := arg.(*ast.FuncLit); isLit {
					violations = append(violations, r.unconditionalSkips(ctx, lit.Body.List)...)
				}
			}
		}
	}
	return violations
}

func (r *SkippedTestRule) report(ctx *core.FileContext, line int, message, suggestion string) *core.Violation {
	v := r.CreateViolation(ctx.RelPath, line, message)
	v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
	v.WithSuggestion(suggestion)
	return v
}
