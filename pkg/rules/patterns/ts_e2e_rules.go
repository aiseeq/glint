package patterns

import (
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(&UntypedFulfillPayloadRule{BaseRule: rules.NewBaseRule("test-mock-response-untyped-drifts-from-api", "patterns",
		"Detects an untyped object constant passed to route.fulfill as the mocked API answer in a type-checked spec — the client's response type does not check it, and the mock keeps the old shape after the API changes",
		core.SeverityMedium)})
	rules.Register(newTSTestRule("e2e-api-spec-mocks-endpoint-under-test",
		"Detects an *-api.spec file that answers every request with route.fulfill and sends none to the server — the API it is named after is never called",
		checkAPISpecAllFulfilled))
	rules.Register(NewTSTestOutsideTypecheckRule())
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

// UntypedFulfillPayloadRule reports the untyped objects that the
// type-checked specs hand to route.fulfill; whether a spec is type-checked
// comes from the project's tsconfigs and package.json scripts, so the rule
// reads files other than the spec.
type UntypedFulfillPayloadRule struct {
	*rules.BaseRule
}

// ReadsOtherFiles reports that the findings depend on the tsconfigs.
func (r *UntypedFulfillPayloadRule) ReadsOtherFiles() bool { return true }

// AnalyzeFile checks a TS/JS test file.
func (r *UntypedFulfillPayloadRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !frontendTestFile(ctx) {
		return nil
	}
	return checkUntypedFulfillPayload(r.BaseRule, ctx, newJSFlat(ctx))
}

// checkUntypedFulfillPayload reports the object constants without a type that a test
// hands to route.fulfill as the API's answer.
func checkUntypedFulfillPayload(rule *rules.BaseRule, ctx *core.FileContext, f jsFlat) []*core.Violation {
	// A type on a mock helps only where the compiler reads the spec;
	// ts-test-outside-typecheck reports the specs it does not.
	checked, err := tsFileTypeChecked(ctx.ProjectRoot, ctx.Path)
	if err != nil {
		return jsReport(nil, rule, ctx, 1, "The tsconfigs of the project cannot be read, so the mocks were not checked: "+err.Error(), "Fix the tsconfig or package.json the error names")
	}
	if !checked {
		return nil
	}
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
			out = jsReport(out, rule, ctx, f.line(decl),
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

// TSTestOutsideTypecheckRule detects TS tests that no type check compiles:
//
//	// tsconfig.json
//	"exclude": ["node_modules", "e2e"]
//	// package.json: "type-check": "tsc --noEmit" — and nothing runs tsc -p e2e
//
// Playwright, and jest through babel or swc, strip the types without checking
// them: a spec that calls a page helper with the wrong arguments, or a mock
// typed with the API's response, runs as whatever it says, and the types
// protect nothing. A test compiled by ts-jest is type-checked by the runner.
type TSTestOutsideTypecheckRule struct {
	*rules.BaseRule
	// anchors maps the file a finding is reported on to the tests behind it.
	anchors map[string][]string
	failure error
}

// NewTSTestOutsideTypecheckRule creates the rule.
func NewTSTestOutsideTypecheckRule() *TSTestOutsideTypecheckRule {
	return &TSTestOutsideTypecheckRule{BaseRule: rules.NewBaseRule(
		"ts-test-outside-typecheck",
		"patterns",
		"Detects TS tests that no type-checked tsconfig compiles (tsconfig excludes e2e and no tsc -p e2e runs) — the runner strips their types unchecked, and typed mocks and helpers protect nothing",
		core.SeverityMedium,
	)}
}

// UseProjectFiles finds the TS tests outside every type-checked tsconfig and
// groups them under the test runner config above them, or by directory.
func (r *TSTestOutsideTypecheckRule) UseProjectFiles(files []*core.FileContext) {
	r.ResetState()
	configs := make(map[string]string) // directory → test runner config there
	for _, ctx := range files {
		if testRunnerConfig(ctx) {
			configs[filepath.Dir(ctx.Path)] = ctx.Path
		}
	}
	groups := make(map[string][]*core.FileContext)
	for _, ctx := range files {
		if !ctx.IsTypeScriptFile() || !ctx.IsTestFile() || !testSourceFile(ctx) {
			continue
		}
		checked, err := tsFileTypeChecked(ctx.ProjectRoot, ctx.Path)
		if err == nil && !checked {
			checked, err = typeCheckedByRunner(ctx.ProjectRoot, ctx.Path)
		}
		if err != nil {
			r.failure = err
			r.anchors[ctx.Path] = append(r.anchors[ctx.Path], ctx.RelPath)
			continue
		}
		if !checked {
			key := runnerConfigAbove(ctx, configs)
			groups[key] = append(groups[key], ctx)
		}
	}
	for key, group := range groups {
		sort.Slice(group, func(i, j int) bool { return group[i].RelPath < group[j].RelPath })
		anchor := group[0].Path
		if configs[filepath.Dir(key)] == key {
			anchor = key
		}
		for _, ctx := range group {
			r.anchors[anchor] = append(r.anchors[anchor], ctx.RelPath)
		}
	}
}

// runnerConfigAbove returns the test runner config in the nearest directory
// above the test, or the test's own directory when there is none.
func runnerConfigAbove(ctx *core.FileContext, configs map[string]string) string {
	for dir := filepath.Dir(ctx.Path); strings.HasPrefix(dir, ctx.ProjectRoot); dir = filepath.Dir(dir) {
		if config, ok := configs[dir]; ok {
			return config
		}
		if dir == filepath.Dir(dir) {
			break
		}
	}
	return filepath.Dir(ctx.Path)
}

// ResetState forgets the previous project's tests.
func (r *TSTestOutsideTypecheckRule) ResetState() {
	r.anchors = make(map[string][]string)
	r.failure = nil
}

// AnalyzeFile reports on a test runner config, or on the first test of a
// directory, the tests no type check compiles.
func (r *TSTestOutsideTypecheckRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	tests, ok := r.anchors[ctx.Path]
	if !ok || ctx.IsSuppressed(1, r.Name()) {
		return nil
	}
	if r.failure != nil {
		v := r.CreateViolation(ctx.RelPath, 1, "The tsconfigs of the project cannot be read, so the tests were not checked: "+r.failure.Error())
		v.WithSuggestion("Fix the tsconfig, package.json or jest config the error names")
		return []*core.Violation{v}
	}
	message := "This TS test is compiled by no type-checked tsconfig — the runner strips its types unchecked"
	if len(tests) > 1 || tests[0] != ctx.RelPath {
		message = fmt.Sprintf("%d TS tests (%s and the rest of the group) are compiled by no type-checked tsconfig — the runner strips their types unchecked", len(tests), tests[0])
	}
	v := r.CreateViolation(ctx.RelPath, 1, message)
	v.WithSuggestion("Add a tsconfig for the tests (extending the app's) and run tsc --noEmit -p on it in the type-check script, or compile them with ts-jest")
	return []*core.Violation{v}
}
