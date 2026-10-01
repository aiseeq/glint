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
	rules.Register(NewTestEmailRegistrableDomainRule())
}

// TestEmailRegistrableDomainRule detects a test e-mail address on a domain
// anyone can register:
//
//	testEmail := "test-user@shop-test.com"
//	if strings.HasSuffix(email, "@shop-test.com") { /* treat as a test user */ }
//
// Mail sent to fixtures reaches whoever owns the domain, and code that treats
// the domain as "ours, a test" grants that to anyone who registers it. The
// reserved names (RFC 2606, RFC 6761) never resolve: example.com, .test,
// .example, .invalid, .localhost.
//
// In a test file only a domain without a local part ("@test.com",
// "%@test.com") is reported: it matches users by domain, so it picks real
// users on it too. A fixture address there sends nothing by itself.
type TestEmailRegistrableDomainRule struct {
	*rules.BaseRule
}

// NewTestEmailRegistrableDomainRule creates the rule
func NewTestEmailRegistrableDomainRule() *TestEmailRegistrableDomainRule {
	return &TestEmailRegistrableDomainRule{BaseRule: rules.NewBaseRule(
		"test-email-registrable-domain",
		"patterns",
		"Detects a test e-mail address on a registrable domain (test.com, app-test.com) — mail reaches its owner; use example.com or .test",
		core.SeverityMedium,
	)}
}

var (
	emailDomain = regexp.MustCompile(`@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)\b`)
	// reservedTLDs never resolve (RFC 2606, RFC 6761) or stay inside a network.
	reservedTLDs = map[string]bool{"test": true, "example": true, "invalid": true, "localhost": true, "local": true, "internal": true, "lan": true}
)

// AnalyzeFile reports the test addresses of a file on registrable domains.
func (r *TestEmailRegistrableDomainRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	switch {
	case ctx.IsGoFile() && ctx.HasGoAST():
		return r.analyzeGo(ctx)
	case ctx.IsTypeScriptFile() || ctx.IsJavaScriptFile():
		return r.analyzeJS(ctx)
	}
	return nil
}

func (r *TestEmailRegistrableDomainRule) analyzeGo(ctx *core.FileContext) []*core.Violation {
	var violations []*core.Violation
	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		text, ok := goStringLiteral(lit)
		if !ok {
			return true
		}
		if domain := registrableTestDomain(text, markersOnly(ctx)); domain != "" {
			violations = r.add(violations, ctx, ctx.LineFor(lit), domain)
		}
		return true
	})
	return violations
}

func (r *TestEmailRegistrableDomainRule) analyzeJS(ctx *core.FileContext) []*core.Violation {
	src := newJSSource(ctx)
	onlyMarkers := markersOnly(ctx)
	var violations []*core.Violation
	for i, line := range src.text {
		for _, loc := range emailDomain.FindAllStringSubmatchIndex(line, -1) {
			// Only literal text: the code view blanks it.
			if loc[0] >= len(src.code[i]) || src.code[i][loc[0]] != ' ' {
				continue
			}
			if onlyMarkers && !domainMarker(line, loc[0]) {
				continue
			}
			if domain := registrableTestDomain(line[loc[0]:loc[1]], false); domain != "" {
				violations = r.add(violations, ctx, i+1, domain)
				break
			}
		}
	}
	return violations
}

func (r *TestEmailRegistrableDomainRule) add(violations []*core.Violation, ctx *core.FileContext, line int, domain string) []*core.Violation {
	if ctx.IsSuppressed(line, r.Name()) {
		return violations
	}
	return append(violations, testReport(r.BaseRule, ctx, line,
		"Test address on the registrable domain "+domain+" — mail to it reaches whoever owns the domain, and code trusting it as a test domain trusts them",
		"Use a reserved name that never resolves: example.com, or a .test / .example / .invalid domain"))
}

// markersOnly reports a file of a test tree, where only domain markers count.
func markersOnly(ctx *core.FileContext) bool {
	return ctx.IsTestFile() || isE2EPath(ctx.RelPath)
}

// domainMarker reports an @ at index at with no local part before it: the
// start of the text, a quote, or a LIKE/glob wildcard.
func domainMarker(text string, at int) bool {
	return at == 0 || strings.ContainsRune("%*'\"`", rune(text[at-1]))
}

// registrableTestDomain returns the first domain after an @ in the text
// that is named as a test domain but can be registered; with onlyMarkers,
// only a domain without a local part.
func registrableTestDomain(text string, onlyMarkers bool) string {
	for _, loc := range emailDomain.FindAllStringSubmatchIndex(text, -1) {
		if onlyMarkers && !domainMarker(text, loc[0]) {
			continue
		}
		domain := strings.ToLower(text[loc[2]:loc[3]])
		labels := strings.Split(domain, ".")
		tld := labels[len(labels)-1]
		if reservedTLDs[tld] || len(tld) < 2 || strings.Trim(tld, "abcdefghijklmnopqrstuvwxyz") != "" {
			continue
		}
		if namedAsTest(labels[len(labels)-2]) {
			return domain
		}
	}
	return ""
}

// namedAsTest reports a domain label made of a test word: test, tests,
// testing, testmail, app-test — not latest or contest.
func namedAsTest(label string) bool {
	for _, word := range strings.Split(label, "-") {
		if strings.HasPrefix(word, "test") {
			return true
		}
	}
	return false
}
