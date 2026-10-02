package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/core"
)

func frontendErrorMessageLines(t *testing.T, path, source string) []int {
	t.Helper()
	ctx := core.NewFileContext(path, ".", []byte(source), nil)
	return violationLines(NewFrontendErrorMessageMatchRule().AnalyzeFile(ctx))
}

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
	assert.Equal(t, []int{6, 9, 18, 19}, frontendErrorMessageLines(t, "frontend/src/refresh.ts", source))
}

// Test files and a message that is only shown or logged stay out.
func TestFrontendErrorMessageMatch_SkipsTestsAndDisplay(t *testing.T) {
	const source = `it('fails', async () => {
  try { await run() } catch (err) {
    expect(err.message.includes('boom')).toBe(true)
  }
})
`
	assert.Empty(t, frontendErrorMessageLines(t, "frontend/src/run.test.ts", source))
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
	assert.Equal(t, []int{20}, frontendErrorMessageLines(t, "web/src/lib/body.ts", source))
}
