package patterns

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(newTSTestRule("test-mock-response-untyped-drifts-from-api",
		"Detects an untyped object constant passed to route.fulfill as the mocked API answer — the client's response type does not check it, and the mock keeps the old shape after the API changes",
		checkUntypedFulfillPayload))
	rules.Register(newTSTestRule("e2e-api-spec-mocks-endpoint-under-test",
		"Detects an *-api.spec file that answers every request with route.fulfill and sends none to the server — the API it is named after is never called",
		checkAPISpecAllFulfilled))
	rules.Register(newTSTestRule("test-retries-mask-flakiness",
		"Detects a test runner set to retry failed tests unconditionally (retries: 1) — a flaky test passes on the second try and the race behind it stays",
		checkTestRetries))
}

// frontendTestFile reports a TS/JS test or e2e file, or a test runner config.
func frontendTestFile(ctx *core.FileContext) bool {
	if ctx.IsGoFile() {
		return false
	}
	return testSourceFile(ctx) || (testRunnerConfig(ctx) && !strings.Contains(ctx.RelPath, "node_modules/"))
}

var testRunnerConfigName = regexp.MustCompile(`^(?:playwright|jest|vitest)\.config\.[cm]?[jt]s$`)

// testRunnerConfig reports playwright.config.ts and its jest and vitest kin.
func testRunnerConfig(ctx *core.FileContext) bool {
	return testRunnerConfigName.MatchString(filepath.Base(ctx.Path))
}

var (
	fulfillCall    = regexp.MustCompile(`\.fulfill\s*\(`)
	fulfillPayload = regexp.MustCompile(`\b(?:json\s*:\s*([A-Za-z_$][\w$]*)\s*(?:[,}]|$)|body\s*:\s*JSON\.stringify\(\s*([A-Za-z_$][\w$]*)\s*\))`)
)

// checkUntypedFulfillPayload reports the object constants without a type that a test
// hands to route.fulfill as the API's answer.
func checkUntypedFulfillPayload(r *tsRule, ctx *core.FileContext, f jsFlat) []*core.Violation {
	var out []*core.Violation
	reported := make(map[string]bool)
	consts := untypedObjectConsts(f)
	for _, m := range fulfillCall.FindAllStringIndex(f.code, -1) {
		open := m[1] - 1
		end, ok := f.closing(open)
		if !ok {
			continue
		}
		for _, p := range fulfillPayload.FindAllStringSubmatch(f.code[open:end+1], -1) {
			name := p[1] + p[2]
			if reported[name] {
				continue
			}
			decl, ok := consts[name]
			if !ok {
				continue
			}
			reported[name] = true
			out = jsReport(out, r.BaseRule, ctx, f.line(decl),
				name+" is the mocked API answer, and no type checks it against the response the client expects — after the API changes the mock keeps the old shape, and the test checks a page the real server no longer produces",
				"Type the mock with the client's response type (const "+name+": ListResponse = ... or ... satisfies ListResponse)")
		}
	}
	return out
}

var (
	objectConstDecl = regexp.MustCompile(`\b(?:const|let)\s+([A-Za-z_$][\w$]*)\s*(:[^=]*)?=\s*([{\[])`)
	typeAssertTail  = regexp.MustCompile(`^\s*(?:as|satisfies)\s`)
)

// untypedObjectConsts returns the offsets of the `const name = {` and `= [`
// declarations that have neither a type annotation nor an as/satisfies after
// the literal.
func untypedObjectConsts(f jsFlat) map[string]int {
	consts := make(map[string]int)
	for _, m := range objectConstDecl.FindAllStringSubmatchIndex(f.code, -1) {
		if m[4] >= 0 {
			continue
		}
		end, ok := f.closing(m[6])
		if !ok || typeAssertTail.MatchString(f.code[end+1:]) {
			continue
		}
		consts[f.code[m[2]:m[3]]] = m[0]
	}
	return consts
}

var (
	apiSpecName      = regexp.MustCompile(`(?i)[-_.]api\.(?:spec|test)\.[cm]?[jt]sx?$`)
	realServerAccess = regexp.MustCompile(`\brequest\s*\.\s*(?:get|post|put|patch|delete|head|fetch)\s*\(|\bnewContext\s*\(|\bfetch\s*\(|\.\s*(?:continue|fallback)\s*\(|\broute\s*\.\s*fetch\s*\(`)
)

// checkAPISpecAllFulfilled reports an API spec whose every answer is a mock.
func checkAPISpecAllFulfilled(r *tsRule, ctx *core.FileContext, f jsFlat) []*core.Violation {
	if !apiSpecName.MatchString(filepath.Base(ctx.Path)) || realServerAccess.MatchString(f.code) {
		return nil
	}
	m := fulfillCall.FindStringIndex(f.code)
	if m == nil {
		return nil
	}
	return jsReport(nil, r.BaseRule, ctx, f.line(m[0]),
		"The API spec answers every request with route.fulfill and sends none to the server — the endpoints it is named after are never called, and a broken API passes",
		"Call the API with the request fixture against the test server, and keep the mocked page checks in a UI spec")
}

var (
	configRetries   = regexp.MustCompile(`\bretries\s*:\s*[1-9]\d*\b`)
	vitestRetry     = regexp.MustCompile(`\bretry\s*:\s*[1-9]\d*\b`)
	describeRetries = regexp.MustCompile(`\.configure\s*\(\s*\{[^}]*\bretries\s*:\s*[1-9]\d*\b`)
	jestRetryTimes  = regexp.MustCompile(`\bjest\s*\.\s*retryTimes\s*\(\s*[1-9]\d*\b`)
)

// checkTestRetries reports retries set to a fixed positive number.
func checkTestRetries(r *tsRule, ctx *core.FileContext, f jsFlat) []*core.Violation {
	patterns := []*regexp.Regexp{describeRetries, jestRetryTimes}
	if testRunnerConfig(ctx) {
		patterns = append(patterns, configRetries, vitestRetry)
	}
	var out []*core.Violation
	for _, re := range patterns {
		for _, m := range re.FindAllStringIndex(f.code, -1) {
			out = jsReport(out, r.BaseRule, ctx, f.line(m[1]-1),
				"Failed tests are retried unconditionally — a flaky test passes on the second try, and the race behind it is never looked at",
				"Keep retries at 0 and fix the flaky test; if the CI needs retries, enable them for the CI only and report the retried tests")
		}
	}
	return out
}
