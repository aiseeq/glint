package frontendrules

import (
	"fmt"
	"math"
	"strings"
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
	source := "const helper = (message) => message;\n" + strings.Repeat("helper(error.message);", 1<<16)
	start := time.Now()
	rulestest.TextFileRuleLines(t, NewFrontendErrorMessageMatchRule(), "frontend/src/generated.ts", source)
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("analyzing %d bytes took %s, want at most 10s", len(source), elapsed)
	}
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
	depth := 1 << 14
	source := "function h(m){return m}try{x()}catch(err){" + strings.Repeat("h(", depth) + "err.message" + strings.Repeat(")", depth) + "}"
	start := time.Now()
	rulestest.TextFileRuleLines(t, NewFrontendErrorMessageMatchRule(), "web/src/n.js", source)
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("analyzing %d nested calls took %s, want at most 5s", depth, elapsed)
	}
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

// ruleGrowth returns how many times longer rule takes on source(4n) than on
// source(n), each the fastest of three runs, the shorter one taken as at
// least a millisecond. Linear work grows about four times, quadratic
// sixteen; a ratio leaves the slowdown of the race detector out.
func ruleGrowth(t *testing.T, rule rules.Rule, path string, source func(n int) string, n int) float64 {
	t.Helper()
	fastest := func(n int) time.Duration {
		text := source(n)
		best := time.Duration(math.MaxInt64)
		for range 3 {
			ctx := rulestest.TextFile(t, path, text)
			start := time.Now()
			rule.AnalyzeFile(ctx)
			best = min(best, time.Since(start))
		}
		return best
	}
	small := max(fastest(n), time.Millisecond)
	return float64(fastest(4*n)) / float64(small)
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
	}{"aliases": {aliases, 500}, "chain": {chain, 40}} {
		if growth := ruleGrowth(t, rule, "web/src/g.js", c.source, c.n); growth > 8 {
			t.Errorf("%s: four times the input took %.1f times as long, want at most 8", name, growth)
		}
	}
}
