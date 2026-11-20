package httprules

import (
	"strings"
	"testing"
	"time"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
)

func TestResponseJSONUnguardedLargeLineCompletes(t *testing.T) {
	source := "const response=await fetch('/');response.json();" + strings.Repeat("{};", 1<<18)
	start := time.Now()
	rulestest.TextFileRuleLines(t, NewResponseJSONUnguardedRule(), "web/src/generated.ts", source)
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("analyzing %d bytes took %s, want at most 10s", len(source), elapsed)
	}
}

// A body that is not JSON — a plain-text refusal from a middleware, a proxy's
// HTML page — makes response.json() throw a SyntaxError, and the user reads
// the parser's message instead of the reason.
func TestResponseJSONUnguarded(t *testing.T) {
	assert.Equal(t, []int{3}, rulestest.TextFileRuleLines(t, NewResponseJSONUnguardedRule(), "web/src/lib/claim.ts", `export async function claim(): Promise<void> {
  const response = await fetch('/api/codes/claim', { method: 'POST' })
  const data = await response.json()
  use(data)
}
`))
	assert.Equal(t, []int{2}, rulestest.TextFileRuleLines(t, NewResponseJSONUnguardedRule(), "web/src/lib/list.ts", `export const list = (): Promise<Item[]> =>
  fetch('/api/items').then((res) => res.json())
`))
	assert.Equal(t, []int{2}, rulestest.TextFileRuleLines(t, NewResponseJSONUnguardedRule(), "web/src/lib/read.ts", `export async function read(resp: Response) {
  return (await resp.json()) as Envelope
}
`))
}

func TestResponseJSONUnguardedAllowed(t *testing.T) {
	assert.Empty(t, rulestest.TextFileRuleLines(t, NewResponseJSONUnguardedRule(), "web/src/app/cancel/page.tsx", `export async function cancel(): Promise<void> {
  const response = await fetch('/api/profile/cancel', { method: 'POST' })
  const payload = await response.json().catch(() => null)
  const other = await fetch('/api/x')
    .then((r) => r.json())
    .catch(() => null)
  use(payload, other)
}
`), ".catch in the chain")
	assert.Empty(t, rulestest.TextFileRuleLines(t, NewResponseJSONUnguardedRule(), "web/src/lib/guarded.ts", `export async function load() {
  const response = await fetch('/api/users/profile')
  try {
    return await response.json()
  } catch {
    throw new ApiError(response.status, await response.text())
  }
}
`), "inside try")
	assert.Empty(t, rulestest.TextFileRuleLines(t, NewResponseJSONUnguardedRule(), "web/src/lib/schema.ts", `export const body = schema.json()
const text = JSON.stringify(value)
// const data = await response.json()
const s = 'response.json()'
`), "not a response, comments and strings")
	code := "const body = await response.json()\n"
	assert.Empty(t, rulestest.TextFileRuleLines(t, NewResponseJSONUnguardedRule(), "e2e/tests/codes-api.spec.ts", code), "tests read raw responses on purpose")
	assert.Empty(t, rulestest.TextFileRuleLines(t, NewResponseJSONUnguardedRule(), "web/src/__tests__/api.test.ts", code))
	assert.Empty(t, rulestest.TextFileRuleLines(t, NewResponseJSONUnguardedRule(), "api/x.go", "package api\n// await response.json()\n"))
}

// A .catch that ends the chain several lines below a multi-line callback
// catches the parse inside it, and so does the second handler of the .then
// that follows the parse.
func TestResponseJSONUnguardedCaughtFurtherDownTheChain(t *testing.T) {
	assert.Empty(t, rulestest.TextFileRuleLines(t, NewResponseJSONUnguardedRule(), "web/static/poll.js", `(function poll(){
  fetch('/api/status').then(function(r){return r.json()}).then(function(d){
    if(d.ready){ location.reload(); } else {setTimeout(poll,3000)}
  }).catch(function(e){console.warn('poll failed', e);setTimeout(poll,5000)});
})();
function load(url) {
  fetch(url, {headers: {'Accept': 'application/json'}})
    .then(function(r) {
      if (r.ok) return r.json();
      return r.json().then(function(body) {
        return Promise.reject(body.error);
      }, function() { return Promise.reject('HTTP ' + r.status); });
    })
    .then(function(data) { show(data); })
    .catch(function(e) { showError(e); });
}
fetch('/e').then(function(r) { return r.json().then(show, function() { showError(); }); });
`))
}

// A .catch of another statement or of another chain does not guard the parse,
// nor does the rejection handler of the .then whose callback parses.
func TestResponseJSONUnguardedCatchOfAnotherStatement(t *testing.T) {
	assert.Equal(t, []int{2, 7, 12, 16, 18, 22, 23}, rulestest.TextFileRuleLines(t, NewResponseJSONUnguardedRule(), "web/static/other.js", `fetch('/a').then(function(r) {
  var d = r.json();
  other().catch(function() {});
  return d;
});
function parse(r) {
  return r.json();
}
other().catch(function() {});
fetch('/b').then(function(r) {
  if (r.ok) {
    return r.json()
  }
  other().catch(function() {})
});
fetch('/c').then(function(r) { return r.json(); }, function() { return null; });
fetch('/d').then((r) => {
  const d = r.json()
  other().catch(() => {})
  return d
})
function parseOne(r) { return r.json(); } other().catch(function() {});
fetch('/f').then(function(r) { var d = r.json(); other().catch(function() {}); return d; });
`))
}

// A helper of the file returns the parse to its callers: when every call
// of it in the file ends in a .catch, the parse is guarded there.
func TestResponseJSONUnguardedHelperCaughtByCallers(t *testing.T) {
	assert.Empty(t, rulestest.TextFileRuleLines(t, NewResponseJSONUnguardedRule(), "web/static/corridor.js", `function fetchJSON(url) {
  return fetch(url).then(function(r) {
    if (r.ok) return r.json();
    return Promise.reject(new Error('HTTP ' + r.status));
  });
}
function loadBanks() {
  fetchJSON('/banks').then(show).catch(showError);
}
var loadOptions = function() {
  fetchJSON('/options?type=' + encodeURIComponent(kind))
    .then(function(o) { fill(o); })
    .catch(function(e) { console.warn(e); });
};
`))
}

// A helper with a call that nothing catches, a helper handed over as a
// value, an exported helper and a helper nobody calls in the file leave the
// parse unguarded.
func TestResponseJSONUnguardedHelperNotCaughtEverywhere(t *testing.T) {
	assert.Equal(t, []int{2, 7, 12, 17}, rulestest.TextFileRuleLines(t, NewResponseJSONUnguardedRule(), "web/src/lib/helpers.ts", `function getA(url: string) {
  return fetch(url).then((r) => r.json())
}
getA('/a').catch(report)
getA('/b').then(show)
function getB(url: string) {
  return fetch(url).then((r) => r.json())
}
getB('/a').catch(report)
urls.map(getB)
export function getC(url: string) {
  return fetch(url).then((r) => r.json())
}
getC('/a').catch(report)
const getD = async (url: string) => {
  const response = await fetch(url)
  return response.json()
}
`))
	assert.Equal(t, []int{3}, rulestest.TextFileRuleLines(t, NewResponseJSONUnguardedRule(), "web/static/nested.js", `function outer() {
  function inner(url) {
    return fetch(url).then(function(r) { return r.json(); });
  }
  inner('/x').then(show);
  return Promise.resolve();
}
outer().catch(report);
`), "the innermost helper hands the parse over")
}
