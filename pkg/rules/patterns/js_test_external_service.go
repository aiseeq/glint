package patterns

import (
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewJSTestExternalServiceRule())
}

// JSTestExternalServiceRule is test-external-service for TS/JS tests (jest,
// vitest, playwright): a test file that calls a third-party address with
// fetch, axios or a request context, or runs a command that goes to the
// network (npm audit or install, curl, wget, git clone) through
// child_process. A jest suite of a project ran npm audit against the npm
// registry on every run: the suite failed on the registry's outages and its
// advisories of the day, and the call sat in a helper class of the test file.
//
// Not reported: a local or reserved address (localhost, *.test,
// example.com), a file that mocks the transport (msw, nock, jest.spyOn on
// fetch, jest.mock of axios or child_process), and calls a gate covers. A
// gate skips the test unless a dedicated env flag is set - describe.skipIf
// (!process.env.X), describe.runIf(process.env.X), process.env.X ? describe :
// describe.skip, test.skip(!process.env.X), if (!process.env.X) return - and
// covers the rest of its block. The flag must be one no env file of the
// project sets: an exported .env opens it in every run.
type JSTestExternalServiceRule struct {
	*rules.BaseRule
	urls *TestExternalServiceRule

	mu      sync.Mutex
	envKeys map[string]projectEnv // by project root
}

// projectEnv is the keys of a project's env files, or why they are unknown.
type projectEnv struct {
	keys map[string]bool
	err  error
}

// NewJSTestExternalServiceRule creates the rule.
func NewJSTestExternalServiceRule() *JSTestExternalServiceRule {
	return &JSTestExternalServiceRule{
		BaseRule: rules.NewBaseRule(
			"js-test-external-service",
			"patterns",
			"Detects TS/JS tests that call a third-party service (fetch or axios on an external URL, npm audit, curl, git clone through child_process) without a mock or a skip behind a dedicated env flag",
			core.SeverityHigh,
		),
		urls:    NewTestExternalServiceRule(),
		envKeys: map[string]projectEnv{},
	}
}

var (
	// jsHTTPCall is a call whose first argument is a URL literal: fetch,
	// axios, a request context or http(s).get.
	jsHTTPCall = regexp.MustCompile(`(?:^|[^\w$])(?:fetch|axios|get|post|put|patch|delete|head|request)\s*\(\s*['"` + "`" + `](https?://[^'"` + "`" + `\s]+)`)
	// jsCommandCall is a child_process call whose command is a literal:
	// exec('npm audit'), execAsync(...), spawn('curl', [...]).
	jsCommandCall = regexp.MustCompile(`(?:^|[^\w$.])(?:exec\w*|spawn\w*|execa\w*)\s*\(\s*['"` + "`" + `]([^'"` + "`" + `]+)['"` + "`" + `](.*)`)
	// jsNetworkCommand is a command that goes to the network.
	jsNetworkCommand = regexp.MustCompile(`^\s*(?:(?:npm|yarn|pnpm)\s+(?:audit|install|i|ci|add|update|outdated|view|info|publish)\b|curl\b|wget\b|git\s+(?:clone|fetch|pull|push|ls-remote)\b)`)
	// jsLocalURL is a local address among a command's arguments.
	jsLocalURL = regexp.MustCompile(`(?i)https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])`)
	// jsHTTPReplaced is an HTTP transport the test file replaces.
	jsHTTPReplaced = regexp.MustCompile(`\bsetupServer\s*\(|\bsetupWorker\s*\(|\bnock\s*\(|spyOn\s*\(\s*(?:global|globalThis|window)\s*,\s*['"]fetch|(?:global|globalThis|window)\.fetch\s*=|stubGlobal\s*\(\s*['"]fetch|(?:jest|vi)\.mock\s*\(\s*['"](?:axios|node-fetch|undici|cross-fetch)['"]|\bfetchMock\b|\bmockFetch\b`)
	// jsCommandReplaced is a child_process the test file replaces.
	jsCommandReplaced = regexp.MustCompile(`(?:jest|vi)\.mock\s*\(\s*['"](?:node:)?(?:child_process|execa)['"]`)

	jsEnvUnset = `(?:!\s*\(?\s*process\.env\.([A-Za-z_]\w*)\b(?:\s*===?\s*['"][^'"]+['"]\s*\))?|process\.env\.([A-Za-z_]\w*)\s*!==?\s*['"][^'"]*['"])`
	jsEnvSet   = `process\.env\.([A-Za-z_]\w*)\b(?:\s*===?\s*['"][^'"]+['"])?`
	// jsEnvGate is a skip unless a flag is set.
	jsEnvGate  = regexp.MustCompile(`\.skipIf\s*\(\s*` + jsEnvUnset + `|\btest\.skip\s*\(\s*` + jsEnvUnset + `|\.runIf\s*\(\s*` + jsEnvSet + `\s*\)|` + jsEnvSet + `\s*\?\s*(?:describe|it|test)\b[^:]*:\s*(?:describe|it|test)\.skip\b|\bif\s*\(\s*` + jsEnvUnset + `\s*\)`)
	jsGateExit = regexp.MustCompile(`\breturn\b|\.skip\s*\(`)
	// jsEnvBracket is process.env['X'], read as process.env.X.
	jsEnvBracket = regexp.MustCompile(`process\.env\[\s*['"]([A-Za-z_]\w*)['"]\s*\]`)
	// jsFlagConstant is a constant holding a flag: const LIVE =
	// process.env.X === '1', Boolean(process.env.X), !!process.env.X.
	jsFlagConstant = regexp.MustCompile(`\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:Boolean\s*\(\s*|!!\s*)?(` + jsEnvSet + `)\s*\)?\s*;?\s*$`)
)

// gateText returns the text lines with every flag read spelled
// process.env.X: the bracket form and the file's flag constants
// (const LIVE = process.env.X === '1'; test.skip(!LIVE)).
func gateText(text []string) []string {
	out := make([]string, len(text))
	constants := map[string]string{}
	for i, line := range text {
		out[i] = jsEnvBracket.ReplaceAllString(line, "process.env.$1")
		if m := jsFlagConstant.FindStringSubmatch(out[i]); m != nil {
			constants[m[1]] = m[2]
		}
	}
	for name, read := range constants {
		use := regexp.MustCompile(`(^|[^\w$.])` + regexp.QuoteMeta(name) + `\b`)
		for i, line := range out {
			if jsFlagConstant.MatchString(line) {
				continue
			}
			out[i] = use.ReplaceAllString(line, "${1}("+strings.ReplaceAll(read, "$", "$$")+")")
		}
	}
	return out
}

// AnalyzeFile reports the live calls of a TS/JS test file.
func (r *JSTestExternalServiceRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if (!ctx.IsTypeScriptFile() && !ctx.IsJavaScriptFile()) || !ctx.IsTestFile() {
		return nil
	}
	code := helpers.FileJSCode(ctx)
	text := helpers.FileJSText(ctx)
	whole := strings.Join(text, "\n")
	httpReplaced, commandReplaced := jsHTTPReplaced.MatchString(whole), jsCommandReplaced.MatchString(whole)
	covered, envErr := r.gatedLines(ctx, code, text)
	// Флаг нельзя проверить по .env - гейты не засчитываются, и находка
	// называет причину.
	unknownEnv := ""
	if envErr != nil {
		unknownEnv = fmt.Sprintf(" (гейты по env-флагам не учтены: %v)", envErr)
	}

	var violations []*core.Violation
	for i, line := range text {
		if covered[i] || strings.TrimSpace(code[i]) == "" {
			continue
		}
		what := ""
		if m := jsHTTPCall.FindStringSubmatch(line); m != nil && !httpReplaced && r.urls.externalURLOf(m[1]) != "" {
			what = "вызывает " + m[1]
		}
		if m := jsCommandCall.FindStringSubmatch(line); what == "" && m != nil && !commandReplaced {
			command := strings.TrimSpace(m[1] + " " + strings.Trim(m[2], "[]',\")` "))
			if jsNetworkCommand.MatchString(command) && !jsLocalURL.MatchString(command) {
				what = "запускает " + strings.Fields(m[1])[0] + " с выходом в сеть"
			}
		}
		if what == "" {
			continue
		}
		v := r.CreateViolation(ctx.RelPath, i+1, fmt.Sprintf("Тест %s — живой внешний сервис: прогон падает на его отказах и лимитах, а тест не проверяет наш код%s", what, unknownEnv))
		v.WithCode(strings.TrimSpace(ctx.GetLine(i + 1)))
		v.WithSuggestion("Подставьте записанный ответ (msw, nock, jest.mock) или вынесите проверку в отдельную задачу; живой вызов — только за отдельным env-флагом, без которого тест пропускается")
		violations = append(violations, v)
	}
	return violations
}

// gatedLines returns the lines an env-flag gate covers: from the gate to the
// end of the block holding it. When the project's env files cannot be read,
// no gate counts and the error says why.
func (r *JSTestExternalServiceRule) gatedLines(ctx *core.FileContext, code, text []string) (map[int]bool, error) {
	covered := map[int]bool{}
	var env *projectEnv
	text = gateText(text)
	for i, line := range text {
		m := jsEnvGate.FindStringSubmatch(line)
		if m == nil || strings.TrimSpace(code[i]) == "" {
			continue
		}
		if strings.Contains(m[0], "if") && !strings.Contains(m[0], "skipIf") && !jsGateExit.MatchString(strings.Join(text[i:min(i+3, len(text))], "\n")) {
			continue
		}
		flag := firstNonEmpty(m[1:])
		if env == nil {
			loaded := r.projectEnv(ctx.ProjectRoot)
			env = &loaded
		}
		if env.err != nil {
			return map[int]bool{}, env.err
		}
		if env.keys[flag] {
			continue
		}
		depth := 0
		for j := i; j < len(code); j++ {
			covered[j] = true
			depth += strings.Count(code[j], "{") - strings.Count(code[j], "}")
			if depth < 0 {
				break
			}
		}
	}
	return covered, nil
}

// projectEnv returns the keys of the env files of a project root, read once
// per root.
func (r *JSTestExternalServiceRule) projectEnv(root string) projectEnv {
	r.mu.Lock()
	defer r.mu.Unlock()
	if env, ok := r.envKeys[root]; ok {
		return env
	}
	keys, err := envFileKeys(root)
	env := projectEnv{keys: keys, err: err}
	r.envKeys[root] = env
	return env
}

// firstNonEmpty returns the first non-empty string.
func firstNonEmpty(values []string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// ReadsOtherFiles reports that the findings of a file depend on the
// project's env files too: a flag set there opens a gate.
func (r *JSTestExternalServiceRule) ReadsOtherFiles() bool { return true }
