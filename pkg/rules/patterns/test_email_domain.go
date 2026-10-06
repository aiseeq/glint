package patterns

import (
	"go/ast"
	"go/token"
	"path/filepath"
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
// Test files and end-to-end suites are checked too: tests that register
// users run against environments that send mail, and a fixture address copied
// from test to test is how the domain comes back after a clean-up.
//
// In SQL migrations, a LIKE or = pattern on an e-mail column is read the same
// way, and so is a test local part matching any domain ('test-%'): a trigger
// or a clean-up that takes such addresses for test users takes real people
// with them. A function body a later migration redefines is dead and is not
// reported, nor is a down migration.
type TestEmailRegistrableDomainRule struct {
	*rules.BaseRule
	// liveDefinitions are, by function name, the up migration holding the
	// definition the migrations leave.
	liveDefinitions map[string]string
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
	case isUpMigration(ctx.RelPath):
		return r.analyzeSQL(ctx)
	}
	return nil
}

var (
	createFunction = regexp.MustCompile(`(?i)\bCREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+(?:[A-Za-z_][A-Za-z0-9_]*\.)?"?([A-Za-z_][A-Za-z0-9_]*)`)
	sqlString      = regexp.MustCompile(`'((?:[^']|'')*)'`)
	emailPattern   = regexp.MustCompile(`(?i)email[^']*(?:\bI?LIKE|=|SIMILAR\s+TO)\s*$`)
	// testLocalPart is a LIKE pattern of a local part named as a test one
	// and any domain: 'test-%', 'qa.test%'.
	testLocalPart = regexp.MustCompile(`(?i)^[a-z0-9._+-]*test[a-z0-9._+-]*%$`)
)

// UseProjectFiles finds the up migration holding the live definition of
// each SQL function: the last one, in version order, that creates it.
func (r *TestEmailRegistrableDomainRule) UseProjectFiles(files []*core.FileContext) {
	r.liveDefinitions = make(map[string]string)
	for _, ctx := range files {
		if !isUpMigration(ctx.RelPath) {
			continue
		}
		for _, m := range createFunction.FindAllSubmatch(ctx.Content, -1) {
			name := strings.ToLower(string(m[1]))
			if previous, ok := r.liveDefinitions[name]; !ok || migrationOrder(previous) < migrationOrder(ctx.RelPath) {
				r.liveDefinitions[name] = ctx.RelPath
			}
		}
	}
}

// ResetState forgets the previous root's functions.
func (r *TestEmailRegistrableDomainRule) ResetState() { r.liveDefinitions = nil }

// migrationOrder is the sort key of a migration: its file name, the version
// first.
func migrationOrder(path string) string { return filepath.Base(path) }

// analyzeSQL reports the e-mail patterns of a migration that take test
// users by a registrable domain or by a test local part on any domain.
func (r *TestEmailRegistrableDomainRule) analyzeSQL(ctx *core.FileContext) []*core.Violation {
	var violations []*core.Violation
	live := true
	for i, line := range ctx.Lines {
		if m := createFunction.FindStringSubmatch(line); m != nil {
			owner, known := r.liveDefinitions[strings.ToLower(m[1])]
			live = !known || owner == ctx.RelPath
		}
		code, _, _ := strings.Cut(line, "--")
		if !live {
			continue
		}
		for _, loc := range sqlString.FindAllStringSubmatchIndex(code, -1) {
			if !emailPattern.MatchString(code[:loc[0]]) {
				continue
			}
			literal := code[loc[2]:loc[3]]
			if domain := registrableTestDomain(literal); domain != "" {
				violations = r.add(violations, ctx, i+1, domain)
				break
			}
			if testLocalPart.MatchString(literal) && !ctx.IsSuppressed(i+1, r.Name()) {
				violations = append(violations, testReport(r.BaseRule, ctx, i+1,
					"The pattern '"+literal+"' takes a test local part on any domain — a real user's address that starts the same way passes as a test one",
					"Recognize test users by a reserved domain the code owns (@example.com, a .test domain), not by the local part"))
				break
			}
		}
	}
	return violations
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
		if domain := registrableTestDomain(fillSubstitutions(text, formatVerb)); domain != "" {
			violations = r.add(violations, ctx, ctx.LineFor(lit), domain)
		}
		return true
	})
	return violations
}

func (r *TestEmailRegistrableDomainRule) analyzeJS(ctx *core.FileContext) []*core.Violation {
	src := newJSSource(ctx)
	var violations []*core.Violation
	for i, line := range src.text {
		line = fillSubstitutions(line, templateSubstitution)
		for _, loc := range emailDomain.FindAllStringSubmatchIndex(line, -1) {
			// Only literal text: the code view blanks it.
			if loc[0] >= len(src.code[i]) || src.code[i][loc[0]] != ' ' {
				continue
			}
			if domain := registrableTestDomain(line[loc[0]:loc[1]]); domain != "" {
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

var (
	templateSubstitution = regexp.MustCompile(`\$\{[^}]*\}`)
	formatVerb           = regexp.MustCompile(`%[-+# 0-9.]*[sdvxXq]`)
)

// fillSubstitutions replaces each substitution (a template's ${...}, a
// format verb) with letters of the same length: a domain assembled around
// one — shop-test-w${pid}.com — still names the registrable domain, and the
// columns of the line stay where they were.
func fillSubstitutions(text string, substitution *regexp.Regexp) string {
	return substitution.ReplaceAllStringFunc(text, func(s string) string { return strings.Repeat("x", len(s)) })
}

// registrableTestDomain returns the first domain after an @ in the text
// that is named as a test domain but can be registered.
func registrableTestDomain(text string) string {
	for _, loc := range emailDomain.FindAllStringSubmatchIndex(text, -1) {
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
