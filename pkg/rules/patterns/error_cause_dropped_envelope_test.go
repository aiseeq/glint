package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/core"
)

// A body that does not parse is answered with an error envelope built from
// the status line alone: the parse error, and what the server sent instead
// of JSON, are gone.
func TestErrorCauseDropped_TSErrorEnvelopeWithoutCause(t *testing.T) {
	code := `async function request(response: Response) {
  let data
  try {
    data = JSON.parse(await response.text())
  } catch {
    if (!response.ok) {
      data = { error: response.statusText || 'HTTP ' + response.status }
    }
  }
  try {
    data = JSON.parse(raw)
  } catch (parseError) {
    data = { error: 'not JSON: ' + String(parseError) }
  }
  try {
    data = JSON.parse(raw)
  } catch {
    data = { error: null, items: [] }
  }
  return data
}`
	ctx := core.NewFileContext("/src/api/base.ts", "/src", []byte(code), core.DefaultConfig())
	var lines []int
	for _, v := range NewErrorCauseDroppedRule().AnalyzeFile(ctx) {
		lines = append(lines, v.Line)
	}
	assert.Equal(t, []int{5}, lines)
}

// "error:" inside a logged message is not an envelope.
func TestErrorCauseDropped_TSErrorWordInMessage(t *testing.T) {
	code := `async function load() {
  try {
    await api.load()
  } catch (e) {
    console.error('Load error:', e)
  }
}`
	ctx := core.NewFileContext("/src/api/load.ts", "/src", []byte(code), core.DefaultConfig())
	assert.Empty(t, NewErrorCauseDroppedRule().AnalyzeFile(ctx))
}

// The fields of a log record are not the answer of the catch.
func TestErrorCauseDropped_TSErrorFieldOfLogRecord(t *testing.T) {
	code := `function read() {
  try {
    return JSON.parse(localStorage.getItem('k') || '{}')
  } catch (err) {
    log.warn('storage unavailable', { error: String(err) })
    return {}
  }
}`
	ctx := core.NewFileContext("/src/lib/store.ts", "/src", []byte(code), core.DefaultConfig())
	assert.Empty(t, NewErrorCauseDroppedRule().AnalyzeFile(ctx))
}
