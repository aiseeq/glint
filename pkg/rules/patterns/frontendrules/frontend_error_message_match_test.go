package frontendrules

import (
	"fmt"
	"strings"
	"testing"
	"time"

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

func TestFrontendErrorMessageMatch_SubjectForms(t *testing.T) {
	errors := map[string]bool{"err": true}
	texts := map[string]bool{"messageText": true}
	for _, line := range []string{
		"if (err.message?.includes('expired')) retry()",
		"if ('expired' === messageText) retry()",
		"if (/expired/i.test(messageText)) retry()",
		"if (messageText != `expired`) retry()",
	} {
		assert.True(t, lineTestsText(line, errors, texts), line)
	}
	assert.False(t, lineTestsText("if (messageText.length === 0) retry()", errors, texts))
	assert.True(t, containsErrorMessage("(err as Error).message", errors))
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

func TestFrontendErrorMessageMatch_LongMinifiedLine(t *testing.T) {
	var source strings.Builder
	source.WriteString("try{throw 0}catch(err){")
	for i := range 240 {
		fmt.Fprintf(&source, "function helper%d(message%d){return message%d}", i, i, i)
	}
	for i := range 240 {
		fmt.Fprintf(&source, "helper%d(err.message);", i)
	}
	source.WriteString("if(err.message.includes('failed')){run()}/*")
	source.WriteString(strings.Repeat("x", 320*1024))
	source.WriteString("*/}")
	assert.GreaterOrEqual(t, source.Len(), 300*1024)

	started := time.Now()
	lines := rulestest.TextFileRuleLines(t, NewFrontendErrorMessageMatchRule(), "frontend/src/bundle.js", source.String())
	elapsed := time.Since(started)
	assert.Equal(t, []int{1}, lines)
	assert.Less(t, elapsed, 3*time.Second, "long single-line source took %s", elapsed)
}
