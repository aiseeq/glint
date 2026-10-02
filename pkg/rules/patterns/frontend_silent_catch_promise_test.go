package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/core"
)

// A promise .catch whose arrow handler only logs - as an expression body, or
// a block that logs and answers null - leaves the page showing nothing about
// the failure.
func TestFrontendSilentCatchPromiseHandler(t *testing.T) {
	code := `export function Page() {
  useEffect(() => {
    api.getAccounts(id).then(a => setAccounts(a)).catch(err => console.error('load accounts failed:', err))
    const summary = api.getSummary(id).catch(err => {
      console.error('getSummary failed:', err)
      return null
    })
    api.getRates().catch(console.error)
    api.getTotals().catch((err) => {
      console.error(err)
      setTotalsError(String(err))
    })
    api.getUsers().catch(err => { throw new Error('users: ' + err) })
    api.ping().catch(() => undefined)
  }, [id])
}`
	ctx := core.NewFileContext("frontend/src/page.tsx", ".", []byte(code), nil)
	var lines []int
	for _, v := range NewFrontendSilentCatchRule().AnalyzeFile(ctx) {
		lines = append(lines, v.Line)
	}
	assert.Equal(t, []int{3, 4, 8}, lines)
}

// A handler that sets a failure flag shows the failure.
func TestFrontendSilentCatchPromiseFailureFlag(t *testing.T) {
	code := `export function Page() {
  useEffect(() => {
    api.lookup(ids).then(setLabels).catch(err => {
      console.error('lookup failed:', err)
      if (!cancelled) setLookupFailed(true)
    })
  }, [ids])
}`
	ctx := core.NewFileContext("frontend/src/page.tsx", ".", []byte(code), nil)
	assert.Empty(t, NewFrontendSilentCatchRule().AnalyzeFile(ctx))
}

// An error state set through a generic setter is shown to the user.
func TestFrontendSilentCatchPromiseErrorState(t *testing.T) {
	code := `export function Card() {
  useEffect(() => {
    api.get(url).then(setCard).catch((err: unknown) => {
      logger.error('card load failed', err)
      setState({ kind: 'error' })
    })
  }, [url])
}`
	ctx := core.NewFileContext("frontend/src/card.tsx", ".", []byte(code), nil)
	assert.Empty(t, NewFrontendSilentCatchRule().AnalyzeFile(ctx))
}

// A hook that hands the failure to its caller's error callback (onError,
// onLoadError, onFailure) shows it wherever the caller does.
func TestFrontendSilentCatchPromiseCallerErrorCallback(t *testing.T) {
	code := `export function useRecord(load: (id: string) => Promise<Rec>, onError: (message: string) => void, onLoadFailure: () => void) {
  useEffect(() => {
    let cancelled = false
    load(id).then(setRec).catch((err: unknown) => {
      console.error('load failed:', err)
      if (!cancelled) onError(err instanceof Error ? err.message : String(err))
    })
    load(other).catch(err => {
      console.error('other failed:', err)
      onLoadFailure()
    })
    return () => { cancelled = true }
  }, [id])
}`
	ctx := core.NewFileContext("frontend/src/use-record.ts", ".", []byte(code), nil)
	assert.Empty(t, NewFrontendSilentCatchRule().AnalyzeFile(ctx))
}
