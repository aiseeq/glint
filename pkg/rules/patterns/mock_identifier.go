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
	rules.Register(NewMockIdentifierRule())
}

// MockIdentifierRule detects identifiers (func/method/type/const/var) whose
// name contains a Mock/Fake/Stub/Dummy segment in non-test code. Such a name
// in production either mislabels a real code path (a "mock" quote that is in
// fact the live path for one execution mode — readers skip it as test-only and
// it silently drifts from the implementation it mirrors) or marks test
// scaffolding that leaked out of _test.go files. Deliberate simulation
// surfaces (a config-gated sandbox mode) stay, renamed to say what they do or
// opted out with //nolint:mock-identifier and a reason.
//
// Detects:
//   - func (a *Admin) createMockQuote(...)  — method with Mock in name
//   - func buildFakePayload(...)            — function with Fake in name
//   - type StubNotifier struct{}            — type with Stub prefix
//   - var dummy_response = ...              — snake_case value identifier
//
// Skips:
//   - Test files
//   - Generated files (*.gen.go, *_gen.go, /generated/)
//   - //nolint:mock-identifier opt-outs on the declaration line
type MockIdentifierRule struct {
	*rules.BaseRule
	mockPattern *regexp.Regexp
}

// NewMockIdentifierRule creates the rule
func NewMockIdentifierRule() *MockIdentifierRule {
	return &MockIdentifierRule{
		BaseRule: rules.NewBaseRule(
			"mock-identifier",
			"patterns",
			"Detects identifiers named Mock/Fake/Stub/Dummy outside tests — production code must say what it really does",
			core.SeverityMedium,
		),
		// A marker as a CamelCase segment (MockQuote, createMockQuote,
		// QuoteMock) or as a lowercase segment at a name/underscore boundary
		// (mockQuote, mock_quote, mock). The CamelCase boundary requires the
		// preceding char to be start-of-name, underscore, or *lowercase* (end
		// of previous word); the following char must start the next word
		// (uppercase, underscore, digit) or end the name. The lowercase branch
		// requires the same boundary on both sides, so incidental substrings
		// like "smock", "Mockingbird", "fakest" or "Stubborn" do not match.
		mockPattern: regexp.MustCompile(`(^|[a-z_])(Mock|Fake|Stub|Dummy)([A-Z_0-9]|$)|(^|_)(mock|fake|stub|dummy)([A-Z_0-9]|$)`),
	}
}

// AnalyzeFile checks for Mock/Fake/Stub/Dummy identifiers
func (r *MockIdentifierRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
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
			if r.mockPattern.MatchString(decl.Name.Name) {
				if v := r.violation(ctx, decl.Name.Pos(), decl.Name.Name, r.funcKind(decl)); v != nil {
					violations = append(violations, v)
				}
			}
		case *ast.TypeSpec:
			if r.mockPattern.MatchString(decl.Name.Name) {
				if v := r.violation(ctx, decl.Name.Pos(), decl.Name.Name, "type"); v != nil {
					violations = append(violations, v)
				}
			}
		case *ast.ValueSpec:
			for _, name := range decl.Names {
				if r.mockPattern.MatchString(name.Name) {
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
func (r *MockIdentifierRule) funcKind(fn *ast.FuncDecl) string {
	if fn.Recv != nil && len(fn.Recv.List) > 0 {
		return "method"
	}
	return "function"
}

// violation builds a violation (or nil if opt-out is present on the line).
func (r *MockIdentifierRule) violation(ctx *core.FileContext, pos token.Pos, name, kind string) *core.Violation {
	line := ctx.GoFileSet.Position(pos).Line
	lineContent := ctx.GetLine(line)

	if core.LineSuppresses(lineContent, "mock-identifier") {
		return nil
	}

	v := r.CreateViolation(ctx.RelPath, line,
		"Mock-style identifier in production code: "+kind+" "+name)
	v.WithCode(strings.TrimSpace(lineContent))
	v.WithSuggestion("Rename the " + kind + " to say what the code really does (local/manual/simulated/recorded), " +
		"move it into a _test.go file if it is test scaffolding, or opt out with //nolint:mock-identifier " +
		"and a reason if the simulation is deliberate and gated.")
	v.WithContext("kind", kind)
	v.WithContext("name", name)
	return v
}

// shouldSkipFile excludes generated files and diagnostic implementations
// whose subject is the marker itself (this rule, the stub-detection rules).
func (r *MockIdentifierRule) shouldSkipFile(ctx *core.FileContext) bool {
	path := ctx.RelPath
	if strings.HasSuffix(path, "mock_identifier.go") ||
		strings.HasSuffix(path, "stub_method.go") ||
		strings.HasSuffix(path, "nil_return_stub.go") {
		return true
	}
	if strings.HasSuffix(path, ".gen.go") || strings.HasSuffix(path, "_gen.go") {
		return true
	}
	if strings.Contains(path, "/generated/") || strings.Contains(path, "vendor/") {
		return true
	}
	return false
}
