package frontendrules

import (
	"fmt"
	"math"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
)

// The wording of a caught error decides the branch: directly, through a
// variable, or in a helper the message is handed to.
func TestFrontendErrorMessageMatch_BranchesOnWording(t *testing.T) {
	const source = `export async function refresh(api: Api) {
  try {
    await api.refresh()
  } catch (err) {
    const errorMessage = err instanceof Error ? err.message : String(err)
    if (errorMessage.includes('token expired')) {
      return logout()
    }
    if (err.message === 'Network Error') {
      return retry()
    }
    throw err
  }
}

function friendlyError(msg: string): string {
  const clean = msg.replace(/\[trace:[^\]]*\]\s*/g, '').trim()
  if (clean.includes('expired')) return 'Code expired'
  if (/not available/i.test(clean)) return 'Code used'
  return clean
}

export function Claim() {
  const onError = (e: unknown) => setMessage(friendlyError(e instanceof Error ? e.message : ''))
  return onError
}

function label(status: string): string {
  if (status.includes('pending')) return 'Pending'
  return status
}

function show(err: Error) {
  const text = err.message
  console.error(text)
  setMessage(text)
  const trim = (s: unknown) => typeof s === 'string' ? s.slice(0, 200) : ''
  track(trim(err.message))
}
`
	assert.Equal(t, []int{6, 9, 18, 19}, rulestest.TextFileRuleLines(t, NewFrontendErrorMessageMatchRule(), "frontend/src/refresh.ts", source))
}

// Test files and a message that is only shown or logged stay out.
func TestFrontendErrorMessageMatch_SkipsTestsAndDisplay(t *testing.T) {
	const source = `it('fails', async () => {
  try { await run() } catch (err) {
    expect(err.message.includes('boom')).toBe(true)
  }
})
`
	assert.Empty(t, rulestest.TextFileRuleLines(t, NewFrontendErrorMessageMatchRule(), "frontend/src/run.test.ts", source))
}

// isErrorName keeps the names the former ^(?:e|err|error|\w*Err|\w*Error)$
// expression accepted.
func TestFrontendErrorMessageMatchErrorName(t *testing.T) {
	for name, want := range map[string]bool{
		"e": true, "err": true, "error": true, "Err": true, "fetchErr": true, "apiError": true,
		"errors": false, "ErrorBoundary": false, "$error": false, "x$Error": false, "er": false,
	} {
		if got := isErrorName(name); got != want {
			t.Errorf("isErrorName(%q) = %v, want %v", name, got, want)
		}
	}
}

// A helper's first parameter holds a message only when the first argument
// carries one: a message passed further along the argument list does not make
// the first argument, and what is read from it, an error message.
func TestFrontendErrorMessageMatch_MessageInLaterArgument(t *testing.T) {
	const source = `function bodyError(response: Response, text: string, reason: string): Error {
  return new Error(response.status + text + reason)
}

export async function readBody(response: Response) {
  const text = await response.text()
  try {
    return JSON.parse(text)
  } catch (parseError) {
    throw bodyError(response, text, parseError instanceof Error ? parseError.message : String(parseError))
  }
}

export function appendCode(text: string, code: string): string {
  if (text.endsWith(code)) return text
  return text + ' ' + code
}

function describe(msg: string): string {
  if (msg.includes('expired')) return 'Code expired'
  return msg
}

export function show(err: Error, code: string) {
  return describe(err.message) + appendCode('x', code)
}
`
	assert.Equal(t, []int{20}, rulestest.TextFileRuleLines(t, NewFrontendErrorMessageMatchRule(), "web/src/lib/body.ts", source))
}

func TestFrontendErrorMessageMatchLargeFileCompletes(t *testing.T) {
	source := func(n int) string {
		return "const helper = (message) => message;\n" + strings.Repeat("helper(error.message);\n", n)
	}
	const scale, limit = 40, 140
	// Measured at scale 40: current 29–32; the prefix-scan mutant 1229–1657. Limit 140.
	checkGrowth(t, ruleGrowthAtScale(t, NewFrontendErrorMessageMatchRule(), "frontend/src/perf.ts", source, 32, scale), scale, limit)
}

// Every call of a helper on a line hands it an argument, not only the first:
// a minified file keeps the helper's declaration and its calls on one line,
// and the declaration matches first.
func TestFrontendErrorMessageMatch_EveryHelperCallOnLine(t *testing.T) {
	const source = `function show(msg: string) {
  if (msg.includes("timeout")) retry()
}
export async function load() {
  try { await get() } catch (err) { show("x"); show(err.message) }
}
`
	assert.Equal(t, []int{2}, rulestest.TextFileRuleLines(t, NewFrontendErrorMessageMatchRule(), "web/src/load.ts", source))
	const minified = `function show(msg){if(msg.includes("timeout"))retry()}async function load(){try{await get()}catch(err){show(err.message)}}`
	assert.Equal(t, []int{1}, rulestest.TextFileRuleLines(t, NewFrontendErrorMessageMatchRule(), "web/src/load.js", minified))
	// No call hands the helper a message.
	const plain = `function show(msg: string) {
  if (msg.includes("timeout")) retry()
}
export async function load() {
  try { await get() } catch (err) { show("x"); show(String(count)); log(err.message) }
}
`
	assert.Empty(t, rulestest.TextFileRuleLines(t, NewFrontendErrorMessageMatchRule(), "web/src/load.ts", plain))
}

// The first argument runs to its own comma or closing parenthesis: a ';' in a
// callback inside it does not end it, and a message after the call's closing
// parenthesis or in a later argument is not in it.
func TestFrontendErrorMessageMatch_ArgumentHoldsSemicolon(t *testing.T) {
	const source = `function show(msg: string) {
  if (msg.includes("timeout")) retry()
}
export async function load() {
  try { await get() } catch (err) {
    show(ok ? () => { go(); } : err.message)
  }
}
`
	assert.Equal(t, []int{2}, rulestest.TextFileRuleLines(t, NewFrontendErrorMessageMatchRule(), "web/src/load.ts", source))
	const later = `function show(msg: string) {
  if (msg.includes("timeout")) retry()
}
export async function load() {
  try { await get() } catch (err) {
    show(ok ? () => { go(); } : "x"); log(err.message)
    show("x", () => { go(); return err.message })
  }
}
`
	assert.Empty(t, rulestest.TextFileRuleLines(t, NewFrontendErrorMessageMatchRule(), "web/src/load.ts", later))
}

// A function declared inside an expression is a helper too.
func TestFrontendErrorMessageMatch_FunctionDeclaredInExpression(t *testing.T) {
	const source = `const wrap = (function inner(msg) { if (msg.includes("timeout")) retry() })
export function a() {
  try { b() } catch (err) { inner(err.message) }
}
`
	assert.Equal(t, []int{1}, rulestest.TextFileRuleLines(t, NewFrontendErrorMessageMatchRule(), "web/src/a.js", source))
	const code = `const wrap = (function inner(msg) { if (msg.includes("timeout")) retry() })
export function a() {
  try { b() } catch (err) { inner(err.code) }
}
`
	assert.Empty(t, rulestest.TextFileRuleLines(t, NewFrontendErrorMessageMatchRule(), "web/src/a.js", code))
}

// A cast to a generic type with several type arguments still reads the
// message of the error; the code of the error is not its wording.
func TestFrontendErrorMessageMatch_CastToGenericWithComma(t *testing.T) {
	const source = `export function a() {
  try { b() } catch (err) {
    const m = (err as Failure<Request, Reply>).message
    if (m.includes("boom")) b()
    const n = (err as Failure<Request, Map<string, Reply>>).message
    if (n.startsWith("boom")) b()
    const c = (err as Failure<Request, Reply>).code
    if (c.includes("boom")) b()
  }
}
`
	assert.Equal(t, []int{4, 6}, rulestest.TextFileRuleLines(t, NewFrontendErrorMessageMatchRule(), "web/src/a.ts", source))
}

// A name may start with '$': an alias $m of the message, a catch parameter $e.
// a$m is another name, and so are $$m and m$$.
func TestFrontendErrorMessageMatch_NameStartsWithDollar(t *testing.T) {
	const source = `export function a() {
  try { b() } catch (err) {
    const $m = err.message
    if ($m.includes("boom")) b()
    if (a$m.includes("boom")) b()
    if ($$m.includes("boom")) b()
    const m$ = err.message
    if (m$$.includes("boom")) b()
    if (m$.includes("boom")) b()
    const $$n = err.message
    if ($$n.includes("boom")) b()
  }
  try { b() } catch ($e) {
    if ($e.message === "boom") b()
    if ($$e.message === "boom") b()
  }
}
`
	assert.Equal(t, []int{4, 9, 11, 14}, rulestest.TextFileRuleLines(t, NewFrontendErrorMessageMatchRule(), "web/src/a.ts", source))
}

// Calls of a helper nested in one another cost linear time.
func TestFrontendErrorMessageMatchNestedCallsComplete(t *testing.T) {
	source := func(depth int) string {
		return "function h(m){return m}try{x()}catch(err){" + strings.Repeat("h(", depth) + "err.message" + strings.Repeat(")", depth) + "}"
	}
	const scale, limit = 40, 120
	// Measured at scale 40: current 18–27; the bracket-rescan mutant 1230–2142. Limit 120.
	checkGrowth(t, ruleGrowthAtScale(t, NewFrontendErrorMessageMatchRule(), "web/src/n.js", source, 160, scale), scale, limit)
}

// A name that holds the message carries it into a helper as a message does:
// the alias reaches show, show hands it on to check, and check tests it.
func TestFrontendErrorMessageMatch_AliasHandedToHelper(t *testing.T) {
	const source = `function show(text: string) { check(text) }
function check(value: string) { if (value.includes("timeout")) retry() }
function label(code: string, value: string) { if (code.includes("x")) retry() }
function plain(texts: string) { if (texts.includes("x")) retry() }
export function load() {
  try { go() } catch (err) {
    const msg = err.message
    show(msg)
    label("code", msg)
    plain(msgs)
  }
}
`
	assert.Equal(t, []int{2}, rulestest.TextFileRuleLines(t, NewFrontendErrorMessageMatchRule(), "web/src/a.ts", source))
}

// operationGrowthAtScale compares the fastest of three runs at n and at scale
// times n, in
// CPU time of the process: a loaded machine delays the run, it does not make
// the run do more work, so the ratio does not follow the load (a wall clock
// did: 14.11, load 25, a linear path measured 8.3 times for 4 times the input).
// The limit sits between the scale and its square, so a path gone quadratic
// fails.
func operationGrowthAtScale(t *testing.T, operation func(int), n, scale int) float64 {
	t.Helper()
	fastest := func(size int) time.Duration {
		best := time.Duration(math.MaxInt64)
		for range 3 {
			start := processCPUTime(t)
			operation(size)
			best = min(best, processCPUTime(t)-start)
		}
		return best
	}
	smallRun := fastest(n)
	t.Logf("SMALLRUN %s %.0f", t.Name(), float64(smallRun)/float64(time.Microsecond))
	small := max(smallRun, 100*time.Microsecond)
	return float64(fastest(scale*n)) / float64(small)
}

// processCPUTime is the user and system time the test process has used, the
// garbage collector's threads included.
func processCPUTime(t *testing.T) time.Duration {
	t.Helper()
	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
		t.Fatalf("read the CPU time of the process: %v", err)
	}
	return time.Duration(usage.Utime.Nano() + usage.Stime.Nano())
}

func ruleGrowthAtScale(t *testing.T, rule rules.Rule, path string, source func(n int) string, n, scale int) float64 {
	return operationGrowthAtScale(t, func(size int) {
		ctx := rulestest.TextFile(t, path, source(size))
		rule.AnalyzeFile(ctx)
	}, n, scale)
}

func checkGrowth(t *testing.T, growth float64, scale, limit int) {
	t.Helper()
	t.Logf("GROWTH %s %.1f %d", t.Name(), growth, limit)
	if growth > float64(limit) {
		t.Errorf("%d times the input took %.1f times as long, want at most %d", scale, growth, limit)
	}
}

// Many names holding the message, each handed to a helper on a line of its
// own, and a chain of helpers each handing the message to the next, cost
// time linear in the file.
func TestFrontendErrorMessageMatchAliasesGrowLinearly(t *testing.T) {
	aliases := func(n int) string {
		var b strings.Builder
		b.WriteString("function h(m){if(m.includes(\"x\"))y()}\ntry{x()}catch(err){\n")
		for i := 1; i <= n; i++ {
			fmt.Fprintf(&b, "const a%d = err.message\n", i)
		}
		for i := 1; i <= n; i++ {
			fmt.Fprintf(&b, "log(a%d); h(b%d)\n", i, i)
		}
		b.WriteString("}\n")
		return b.String()
	}
	chain := func(n int) string {
		var b strings.Builder
		b.WriteString(`function h0(m0){if(m0.includes("x"))y()}`)
		for i := 1; i <= n; i++ {
			fmt.Fprintf(&b, "function h%d(m%d){h%d(m%d)}", i, i, i-1, i)
		}
		fmt.Fprintf(&b, "try{x()}catch(err){h%d(err.message)}\n", n)
		return b.String()
	}
	rule := NewFrontendErrorMessageMatchRule()
	assert.Equal(t, []int{1}, rulestest.TextFileRuleLines(t, rule, "web/src/chain.js", chain(40)))
	for name, c := range map[string]struct {
		source func(int) string
		n      int
	}{"aliases": {aliases, 32}, "chain": {chain, 20}} {
		t.Run(name, func(t *testing.T) {
			scale, limit := 32, 140
			// Scale 32 keeps the alias and chain guards below half the limit with margin; the former prefix and bracket mutants remain superlinear.
			analyze := func(size int) {
				ctx := rulestest.TextFile(t, "web/src/g.js", c.source(size))
				rule.AnalyzeFile(ctx)
			}
			checkGrowth(t, operationGrowthAtScale(t, analyze, c.n, scale), scale, limit)
		})
	}
}

// A helper's parameter holds a message only inside the helper: a variable of
// the same name elsewhere in the file, and the same name as the parameter of
// a helper nobody hands a message, are other names.
func TestFrontendErrorMessageMatch_HelperParameterOnlyInItsBody(t *testing.T) {
	const source = `const seen: string[] = []
const record = (text: string): void => { seen.push(text) }

export function collect(page: Page) {
  page.on('console', (message) => {
    if (message.type() !== 'error') return
    const text = message.text()
    if (/favicon|net::ERR_|Failed to load resource/.test(text)) return
    record(text)
  })
  page.on('pageerror', (error) => record(` + "`PageError: ${error.message}`" + `))
}

export function isCriticalPageError(text: string): boolean {
  return /TypeError|ReferenceError|SyntaxError|Cannot read|is not defined|PageError/.test(text)
}
`
	rule := NewFrontendErrorMessageMatchRule()
	assert.Empty(t, rulestest.TextFileRuleLines(t, rule, "web/src/console.ts", source))
	// The helper itself tests the message it is handed.
	testing := strings.Replace(source, "{ seen.push(text) }", "{ if (text.includes('x')) return; seen.push(text) }", 1)
	assert.Equal(t, []int{2}, rulestest.TextFileRuleLines(t, rule, "web/src/console.ts", testing))
	// A variable of the parameter's name assigned from a message holds it in
	// the whole file, inside the body of a helper with that parameter too.
	declared := strings.Replace(source, "const text = message.text()", "const text = error.message", 1)
	assert.Equal(t, []int{8, 15}, rulestest.TextFileRuleLines(t, rule, "web/src/console.ts", declared))
}

// A body runs from the parameters to the brace that closes it, past a return
// type with braces of its own and over lines; an arrow without braces runs to
// the end of the block around it.
func TestFrontendErrorMessageMatch_HelperBodyEnds(t *testing.T) {
	const source = `function shape(text: string): { kind: string } {
  const kind = text.trim()
  return { kind }
}
export function load() {
  const short = (text: string) => text.toLowerCase()
  try { go() } catch (err) {
    shape(err.message)
    short(err.message)
  }
}
export function other(text: string) {
  if (text.includes('x')) retry()
}
export function inShape(text: string): { kind: string } {
  if (text.includes('x')) retry()
}
`
	assert.Empty(t, rulestest.TextFileRuleLines(t, NewFrontendErrorMessageMatchRule(), "web/src/a.ts", source))
	const inside = `function shape(text: string): { kind: string } {
  const kind = text.trim()
  if (kind.includes('y')) retry()
  if (text.includes('x')) retry()
  return { kind }
}
const short = (text: string) =>
  text.includes('z')
export function load() {
  try { go() } catch (err) {
    shape(err.message)
    short(err.message)
  }
}
`
	assert.Equal(t, []int{3, 4, 8}, rulestest.TextFileRuleLines(t, NewFrontendErrorMessageMatchRule(), "web/src/a.ts", inside))
}

// The message goes on from a helper's parameter only where the parameter is
// the helper's: a call outside the helper hands on a variable of that name.
func TestFrontendErrorMessageMatch_HelperParameterHandedOnInItsBody(t *testing.T) {
	const source = `function check(value: string) { if (value.includes("timeout")) retry() }
function show(text: string) { log(text) }
export function load(item: Item) {
  try { go() } catch (err) { show(err.message) }
  const text = item.label()
  check(text)
}
`
	assert.Empty(t, rulestest.TextFileRuleLines(t, NewFrontendErrorMessageMatchRule(), "web/src/a.ts", source))
	handed := strings.Replace(source, "{ log(text) }", "{ check(text) }", 1)
	assert.Equal(t, []int{1}, rulestest.TextFileRuleLines(t, NewFrontendErrorMessageMatchRule(), "web/src/a.ts", handed))
	// A declaration further on that reads the name does not change what the
	// call in the helper's body reads.
	read := strings.Replace(handed, "  check(text)\n}", "  check(text)\n  const later = text.trim()\n}", 1)
	assert.Equal(t, []int{1}, rulestest.TextFileRuleLines(t, NewFrontendErrorMessageMatchRule(), "web/src/a.ts", read))
}

// The body of a helper runs from its parameters past a return type to the
// brace that closes it; an arrow's body without braces runs to the end of the
// block around it, of the code where its braces do not pair. A declaration
// whose code shows no body has none.
func TestFrontendErrorMessageMatchHelperBody(t *testing.T) {
	for code, want := range map[string]string{
		"function f(text) { a } b":                         "(text) { a }",
		"function f(text)\n  { a } b":                      "(text)\n  { a }",
		"function f(text): { k: string } { a } b":          "(text): { k: string } { a }",
		"function f(text):{ k: string } { a } b":           "(text):{ k: string } { a }",
		"function f(text): Promise<{ k: string }> { a } b": "(text): Promise<{ k: string }> { a }",
		"function f(text): A | { k: string } { a } b":      "(text): A | { k: string } { a }",
		"function f(text): A & { k: string } { a } b":      "(text): A & { k: string } { a }",
		"function f(text): Map<A, { k: string }> { a } b":  "(text): Map<A, { k: string }> { a }",
		"function f(text): string[] { a } b":               "(text): string[] { a }",
		"function f(text) { a":                             "(text) { a",
		"function f(text): string;\nconst b":               "",
		"function f(text) b":                               "",
		"function f(text":                                  "",
		"x{ function f(text":                               "",
		"function f(text) => { a } b":                      "",
		"function f(text): a = 1 { b }":                    "",
		"function f(text): string":                         "",
		"function f(text): = 1":                            "",
		"function f(text): a) { b }":                       "",
		"function f(text): a] { b }":                       "",
		"function f(text): a} { b }":                       "",
		"function f(text): () => { k: string } { a } b":    "(text): () => { k: string } { a }",
		"function f(text) { a(1) } b":                      "(text) { a(1) }",
		"function f(text) { a :( b } c":                    "(text) { a :( b }",
		"function f(text) { a 1) b } c":                    "(text) { a 1) b }",
		"function f(text) { a [1) b] } c":                  "(text) { a [1) b] }",
		"const f = (text) => { a } b":                      "(text) => { a }",
		"const f = (text): string => { a } b":              "(text): string => { a }",
		"const f = (a + b) * 2; c":                         "",
		"const f = (text) { a } b":                         "",
		"const f = (text): T { a } b":                      "",
		"const f = (text): a = 1":                          "",
		"const f = (text): a; b => c":                      "",
		"const f = (text): a":                              "",
		"const f = (text): a) => b":                        "",
		"const f = (text) => text; b\nconst c":             "(text) => text; b\nconst c",
		"{ const f = (text) => a; b } c":                   "(text) => a; b ",
		"function g() {\n  const f = (text) => a\n  return (<p>1) {text}</p>)\n}\nb": "(text) => a\n  return (<p>1) {text}</p>)\n",
		"g((x) => { const f = (text) => <li>1) {text}</li>\n  h() }) b":              "(text) => <li>1) {text}</li>\n  h() ",
		"{ a { b } const f = (text) => c { d } e } f":                                "(text) => c { d } e ",
		"function g() { if (x) { const f = (text) => a } b }":                        "(text) => a ",
		"{ a } const f = (text) => b":                                                "(text) => b",
		"{ const f = (text, { k } = {}) => a } b":                                    "(text, { k } = {}) => a ",
		"{ const f = (text) => a } b }":                                              "(text) => a } b }",
		"{ { const f = (text) => a } b":                                              "(text) => a } b",
		"const f = (text): { k: string } => ({ k: text }); b":                        "(text): { k: string } => ({ k: text }); b",
		"const f = async (text) => text; b":                                          "(text) => text; b",
		"const wrap = (function inner(text) { a }) + b":                              "(text) { a }",
	} {
		lines := strings.Split(code, "\n")
		rule := NewFrontendErrorMessageMatchRule()
		var got []string
		for _, decl := range rule.helperDecls(lines, lineOffsets(lines)).scoped() {
			got = append(got, code[decl.start:decl.end])
		}
		if want == "" {
			assert.Empty(t, got, code)
		} else {
			assert.Equal(t, []string{want}, got, code)
		}
	}
}

// Inside a helper nested in another one the name of both their parameters
// holds what either is handed; past the inner body only the outer one's.
func TestFrontendErrorMessageMatch_NestedHelperParameter(t *testing.T) {
	const source = `function outer(text: string) {
  const inner = (text: string) => text.includes('a')
  if (text.includes('b')) retry()
}
export function load() {
  try { go() } catch (err) { outer(err.message) }
}
`
	rule := NewFrontendErrorMessageMatchRule()
	assert.Equal(t, []int{2, 3}, rulestest.TextFileRuleLines(t, rule, "web/src/a.ts", source))
	// The inner arrow has no braces: its body runs to the end of the outer one.
	inner := strings.Replace(source, "outer(err.message)", "inner(err.message)", 1)
	assert.Equal(t, []int{2, 3}, rulestest.TextFileRuleLines(t, rule, "web/src/a.ts", inner))
	// Past both bodies the name is the variable again.
	const after = `function outer(text: string) {
  const inner = (text: string) => log(text)
}
export function load() {
  try { go() } catch (err) {
    const text = err.message
    if (text.includes('x')) retry()
  }
}
`
	assert.Equal(t, []int{7}, rulestest.TextFileRuleLines(t, rule, "web/src/a.ts", after))
	// Right after the closing brace the name is no longer the parameter.
	const minified = `function show(text){log(text)}text.includes("x");try{go()}catch(err){show(err.message)}`
	assert.Empty(t, rulestest.TextFileRuleLines(t, rule, "web/src/a.js", minified))
}

// typeof before a name on the line keeps the place of the name, so a name
// past the end of a helper's body is not taken for its parameter.
func TestFrontendErrorMessageMatch_TypeofKeepsOffsets(t *testing.T) {
	const source = `const record = (text: string) => { return typeof text === 'string' ? text : '' }; if (text.includes('x')) b()
export function load() {
  try { go() } catch (err) { record(err.message) }
}
`
	assert.Empty(t, rulestest.TextFileRuleLines(t, NewFrontendErrorMessageMatchRule(), "web/src/a.ts", source))
}

// Of two names holding a message where one runs on past a '$' in the other,
// m and m$x, the longer is tested.
func TestFrontendErrorMessageMatch_NamesOverlap(t *testing.T) {
	const source = `export function a() {
  try { b() } catch (err) {
    const m = err.message
    const m$x = err.message
    if (m$x.includes("a")) b()
    const y$m = err.message
    if (y$m.includes("a")) b()
  }
}
`
	assert.Equal(t, []int{5, 7}, rulestest.TextFileRuleLines(t, NewFrontendErrorMessageMatchRule(), "web/src/a.ts", source))
}

// Many helpers with one name for their parameters, and that name looked up
// on many lines past their bodies, cost time linear in the file: a body passed
// over is not passed over again for every later lookup.
func TestFrontendErrorMessageMatchHelperScopesGrowLinearly(t *testing.T) {
	rule := NewFrontendErrorMessageMatchRule()
	lookups := func(n int) {
		lines := make([]string, 0, 2*n)
		for range n {
			lines = append(lines, "function h(text) { log(text) }")
		}
		for range n {
			lines = append(lines, "text")
		}
		starts := lineOffsets(lines)
		scopes := newHelperScopes(rule.helperDecls(lines, starts))
		for i := n; i < 2*n; i++ {
			for range 8 {
				if got := scopes.innermost("text", starts[i]); got != -1 {
					t.Fatalf("line %d: text is in body %d, want none", i+1, got)
				}
			}
		}
	}
	const scale, limit = 32, 140
	// Measured at scale 32: current 24–52; the mutant that drops the bodies it
	// passed over only for the one lookup 254–630. Limit 140.
	checkGrowth(t, operationGrowthAtScale(t, lookups, 500, scale), scale, limit)
}

// A variable assigned from code that reads a helper's parameter inside the
// helper's body holds the message the helper is handed.
func TestFrontendErrorMessageMatch_DeclarationReadsParameterInBody(t *testing.T) {
	const source = `const kind = keep(function shape(text: string) { return text.trim() })
export function load() {
  try { go() } catch (err) { shape(err.message) }
  if (kind.includes('x')) retry()
}
`
	assert.Equal(t, []int{4}, rulestest.TextFileRuleLines(t, NewFrontendErrorMessageMatchRule(), "web/src/a.ts", source))
	// A name of the value past the end of the helper on the same line is the
	// variable, wherever the value starts.
	const later = `function shape(text){log(text)};const kind=String(1,2,3,4,5,6,7,text)
try{go()}catch(err){shape(err.message)}
if(kind.includes('x'))retry()
`
	assert.Empty(t, rulestest.TextFileRuleLines(t, NewFrontendErrorMessageMatchRule(), "web/src/a.js", later))
}

// The body of an arrow without braces runs on over lines: past a line ending
// in an operator, a line starting with one, a JSX element, a comma between
// type arguments. A bracket in the text of JSX that nothing pairs moves no
// end of a body, and a function type returned by a function is not taken for
// its body.
func TestFrontendErrorMessageMatch_BodyRunsToItsEnd(t *testing.T) {
	tail := "export async function load() {\n  try { await go() } catch (err) { if (check(err.message)) retry() }\n}\n"
	for name, c := range map[string]struct {
		path, source string
		want         []int
	}{
		"operator at the end of a line":   {"web/src/a.ts", "const check = (text: string) =>\n  text.includes('a') ||\n  text.includes('b') ||\n  text.includes('c')\n" + tail, []int{2, 3, 4}},
		"operator at the start of a line": {"web/src/a.ts", "const check = (text: string) => text.includes('a')\n  || text.includes('b')\n" + tail, []int{1, 2}},
		"comparison then and":             {"web/src/a.ts", "export const check = (text: string): boolean =>\n  !text.startsWith('4') &&\n  text !== 'Unauthorized'\n" + tail, []int{2, 3}},
		"ternary over lines":              {"web/src/a.ts", "const check = (text: string): number =>\n  text.startsWith('a')\n    ? 1\n    : text.startsWith('b')\n      ? 2\n      : 3\n" + tail, []int{2, 4}},
		"JSX on the next line":            {"web/src/a.tsx", "const check = (text: string) =>\n  <div>\n    {text.includes('quota') ? 'a' : 'b'}\n    <br />\n    Try later\n  </div>\n" + tail, []int{3}},
		"comma of type arguments":         {"web/src/a.ts", "const check = (text: string) => test<A, B>(text) || text.includes('x')\n" + tail, []int{1}},
		"closing parenthesis in JSX text": {"web/src/a.tsx", "function check(text: string) {\n  if (!text) return <li>1) Retry later</li>\n  if (text.includes('quota')) return <p>Limit</p>\n  return <p>{text}</p>\n}\n" + tail, []int{3}},
		"opening parenthesis in JSX text": {"web/src/a.tsx", "function render(text: string) {\n  if (!text) return <p>Nothing :(</p>\n  return <p>{text}</p>\n}\nexport function load() {\n  try { go() } catch (err) {\n    const text = err.message\n    if (text.includes('quota')) retry()\n  }\n}\n", []int{8}},
		"function type returned":          {"web/src/a.ts", "function check(text: string): () => { ok: boolean } {\n  if (text.includes('x')) retry()\n  return () => ({ ok: true })\n}\n" + tail, []int{2}},
		"space after the parenthesis":     {"web/src/a.ts", "function check( text: string) {\n  if (text.includes('x')) retry()\n}\n" + tail, []int{2}},
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, c.want, rulestest.TextFileRuleLines(t, NewFrontendErrorMessageMatchRule(), c.path, c.source))
		})
	}
}

// Where the end of a helper's body is misread, a name past it is still the
// variable of the file: a body read too long keeps every finding of the
// variable, so a bracket in the text of JSX, a template over lines or a cast
// in angle brackets loses none.
func TestFrontendErrorMessageMatch_BodyBoundaryLosesNoFinding(t *testing.T) {
	declared := "export function load() {\n  try { go() } catch (err) {\n    const value = err.message\n    if (value.includes('quota')) retry()\n  }\n}\n"
	for name, c := range map[string]struct {
		path, source string
		want         []int
	}{
		"parenthesis closed in JSX text": {"web/src/a.tsx", "const ErrorList = (text: string) => (\n  <ol>\n    <li>1) Retry</li>\n    {text.includes('quota') && <b>Limit</b>}\n  </ol>\n)\nexport function View() {\n  try { go() } catch (err) { return ErrorList(err.message) }\n  return null\n}\n", []int{4}},
		"template over lines":            {"web/src/a.ts", "const fmt = (text: string) => `\n  ${text.includes('x') ? 'a' : 'b'}\n`\nexport function load() { try { go() } catch (err) { fmt(err.message) } }\n", []int{2}},
		"cast in angle brackets":         {"web/src/a.ts", "const asText = (value: unknown) => <string>value\n" + declared, []int{5}},
		"parenthesis opened in JSX text": {"web/src/a.tsx", "const Empty = (value: string) => (\n  <p>Nothing :( {value}</p>\n)\n" + declared, []int{7}},
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, c.want, rulestest.TextFileRuleLines(t, NewFrontendErrorMessageMatchRule(), c.path, c.source))
		})
	}
}

// A variable declared from a message holds it inside the body of a helper
// whose parameter has its name too: the parameter does not hide it.
func TestFrontendErrorMessageMatch_DeclarationHoldsInsideHelper(t *testing.T) {
	const source = `function check(value: string) {
  try { go(value) } catch (err) {
    const value = err.message
    if (value.includes('x')) retry()
  }
}
`
	assert.Equal(t, []int{4}, rulestest.TextFileRuleLines(t, NewFrontendErrorMessageMatchRule(), "web/src/a.ts", source))
}

// An arrow's body that runs on over many empty lines costs time linear in
// them: a line break is not looked past again for every next one.
func TestFrontendErrorMessageMatchBlankLinesGrowLinearly(t *testing.T) {
	source := func(n int) string {
		return "const isBad = (text: string) => text.length > 1 ||\n" + strings.Repeat("\n", n) +
			"  text.includes('x')\nexport function load() { try { go() } catch (err) { isBad(err.message) } }\n"
	}
	rule := NewFrontendErrorMessageMatchRule()
	assert.Equal(t, []int{102}, rulestest.TextFileRuleLines(t, rule, "web/src/a.ts", source(100)))
	const scale, limit = 32, 140
	checkGrowth(t, ruleGrowthAtScale(t, rule, "web/src/a.ts", source, 500, scale), scale, limit)
}

// A helper of many declarations called on many lines, and many helpers nested
// one in another with one name for their parameters each called with a
// message, cost time linear in the file: a helper or a body is marked once.
func TestFrontendErrorMessageMatchMarkingGrowsLinearly(t *testing.T) {
	calls := func(n int) string {
		return strings.Repeat("function h(text){log(text)}", n) + "\ntry{go()}catch(err){" + strings.Repeat("h(err.message);", n) + "}\n"
	}
	nested := func(n int) string {
		var b strings.Builder
		for i := range n {
			fmt.Fprintf(&b, "const a%d = (text: string) => {\n", i)
		}
		b.WriteString("log(text)\n")
		for range n {
			b.WriteString("}\n")
		}
		for i := range n {
			fmt.Fprintf(&b, "try { go() } catch (err) { a%d(err.message) }\n", i)
		}
		return b.String()
	}
	rule := NewFrontendErrorMessageMatchRule()
	for name, source := range map[string]func(int) string{"calls": calls, "nested": nested} {
		t.Run(name, func(t *testing.T) {
			const scale, limit = 32, 140
			checkGrowth(t, ruleGrowthAtScale(t, rule, "web/src/a.ts", source, 300, scale), scale, limit)
		})
	}
}

// An arrow's body without braces runs to the end of the block around it: a
// ';' of an entity, a word of a statement or a parenthesis in the text of JSX
// does not end it. The masked text of JSX hides none of them; only braces are
// safe there.
func TestFrontendErrorMessageMatch_ArrowBodyRunsToBlockEnd(t *testing.T) {
	for name, c := range map[string]struct {
		source string
		want   []int
	}{
		"entity with a semicolon":  {"const Label = (text: string) => <span>Error:&nbsp;{text.includes('quota') ? 'a' : 'b'}</span>\nexport function View() { try { go() } catch (err) { return Label(err.message) } }\n", []int{1}},
		"word of a statement":      {"const Tip = (text: string) =>\n  <p>\n    if it repeats, write to us\n    {text.includes('quota') && '!'}\n  </p>\nexport function View() { try { go() } catch (err) { return Tip(err.message) } }\n", []int{4}},
		"parenthesis in a block":   {"export const Panel = forwardRef((props: Props, ref) => {\n  const Item = (text: string) => <li>1) {text.includes('quota') ? 'a' : 'b'}</li>\n  try { go() } catch (err) { return Item(err.message) }\n  return <div ref={ref} />\n})\n", []int{2}},
		"parenthesis over lines":   {"export function List(items: string[]) {\n  return items.map((item) => {\n    const Row = (text: string) =>\n      <li>\n        Step 1) wait\n        {text.includes('quota') && <b/>}\n      </li>\n    try { go() } catch (err) { return Row(err.message) }\n    return Row(item)\n  })\n}\n", []int{6}},
		"semicolon in parentheses": {"const Hint = (text: string) => (\n  <p>\n    1) a&nbsp;b\n    {text.includes('x') && 1}\n  </p>\n)\nexport function View() { try { go() } catch (err) { return Hint(err.message) } }\n", []int{4}},
		// The apostrophe opens a string to the end of its line, which hides the
		// '{' after it; its '}' on the next line is left unpaired.
		"apostrophe hides a brace": {"export function View() {\n  const Tip = (text: string) => <p>Don't {ok &&\n    'x'} {text.includes('quota') && '!'}</p>\n  try { go() } catch (err) { return Tip(err.message) }\n}\n", []int{3}},
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, c.want, rulestest.TextFileRuleLines(t, NewFrontendErrorMessageMatchRule(), "web/src/a.tsx", c.source))
		})
	}
}
