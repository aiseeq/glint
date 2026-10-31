package frontendrules

import (
	"go/ast"
	"go/types"

	"github.com/aiseeq/glint/pkg/rules/duplication"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patterntest"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestMirrorCommentCopy(t *testing.T) {
	source := `// Mirror of a backend source list.
export const SOURCE_NAMES = ['alpha', 'beta']

// Keep in sync with the server value.
export function sourceName() { return 'alpha' }

// Режимы — зеркало Go models.PayoutGuardMode.
export const PROTECTION_MODES = []`
	assert.Equal(t, []string{"src/names.ts:2", "src/names.ts:5", "src/names.ts:8"}, patterntest.LinesOf(t, NewMirrorCommentCopyRule(), "src/names.ts", source))
}
func TestMirrorCommentCopyVerbInBlock(t *testing.T) {
	source := `/* This helper follows the routing policy.
 * Зеркалит backend models.IsInTransitRoute.
 */
export function isTransferInTransit(route) { return route.active }`
	assert.Equal(t, []string{"src/routes.ts:4"}, patterntest.LinesOf(t, NewMirrorCommentCopyRule(), "src/routes.ts", source))
}

func TestMirrorCommentCopyValueFromSource(t *testing.T) {
	source := `// Keep in sync with constants.SystemIDs.
var excludeSQL = constants.ClientClause("")`
	assert.Empty(t, patterntest.LinesOf(t, NewMirrorCommentCopyRule(), "src/query.go", source))
}

func TestMirrorCommentCopyRuntimeCopy(t *testing.T) {
	source := `// Arrive — прогноз (копия Clone): keeps forecast values.
func (a *Arrival) Arrive() {}`
	assert.Empty(t, patterntest.LinesOf(t, NewMirrorCommentCopyRule(), "src/arrival.go", source))
}

func TestMirrorCommentCopyNegatives(t *testing.T) {
	source := `function render() {
 // UI mirrors the image for the preview.
 return mirroredImage
}
// A mirror image is useful in this explanation.
export const preview = true`
	assert.Empty(t, patterntest.LinesOf(t, NewMirrorCommentCopyRule(), "src/view.ts", source))
	descriptive := `// Recalculates the mirror reference field after a transfer.
func updateMirror() {}
// Returns a copy of a TypeScript source line.
func sourceLine() {}
// The backup mirror of the currency endpoint.
const endpoint = '/rates'`
	assert.Empty(t, patterntest.LinesOf(t, NewMirrorCommentCopyRule(), "src/description.ts", descriptive))
	test := `// Copy of a server list.
export const VALUES = []`
	assert.Empty(t, patterntest.LinesOf(t, NewMirrorCommentCopyRule(), "src/view.test.ts", test))
}

// A copy of a data file made at run time names the file, not a declaration
// whose source of truth lives elsewhere.
func TestMirrorCommentCopyDataFileCopy(t *testing.T) {
	source := `// workerEnv builds the environment: the agent signs in by a copy of its key,
// the other one — по копии auth.json в своём каталоге данных.
func workerEnv() {}

// Pick — копия auth.json без refresh_token.
func Pick(b []byte) []byte { return b }`
	assert.Empty(t, patterntest.LinesOf(t, NewMirrorCommentCopyRule(), "src/worker.go", source))
	code := `// Limit — копия limits.Value из бэкенда.
const Limit = 5`
	assert.Equal(t, []string{"src/limits.go:2"}, patterntest.LinesOf(t, NewMirrorCommentCopyRule(), "src/limits.go", code))
}

// A method is not considered by the body rule, so its comment remains reportable.
func TestMirrorCommentCopyGoMethodReported(t *testing.T) {
	source := `package stream

// isAdmin — копия httpx.IsAdmin.
func (u *User) isAdmin() bool { return u.Role == "admin" }`
	assert.Equal(t, []int{4}, rulestest.GoFileRuleLines(t, NewMirrorCommentCopyRule(), "src/stream.go", source))
	ts := `// Mirrors httpx.IsStreamRequest.
export function isStreamRequest(r) { return r.stream }`
	assert.Equal(t, []string{"src/stream.ts:2"}, patterntest.LinesOf(t, NewMirrorCommentCopyRule(), "src/stream.ts", ts))
}

func TestMirrorCommentCopyGoMethodNotConsideredByBodyRule(t *testing.T) {
	source := `package middleware

// Guard handles requests.
type Guard struct{}

// isStream mirrors httpx.IsStreamRequest.
func (Guard) isStream(r *http.Request) bool {
	if r == nil {
		return false
	}
	accept := strings.ToLower(r.Header.Get("Accept"))
	if strings.Contains(accept, "text/event-stream") {
		return true
	}
	return r.URL.Query().Get("stream") == "1" && r.Method == http.MethodGet
}`
	assert.Equal(t, []int{7}, rulestest.GoFileRuleLines(t, NewMirrorCommentCopyRule(), "src/stream.go", source))
}

func TestMirrorCommentCopyGoParameterlessFunctionNotConsideredByBodyRule(t *testing.T) {
	source := `package api

// defaultHeaders mirrors defaults.Headers.
func defaultHeaders() map[string]string {
	h := map[string]string{"Accept": "application/json", "X-Client": "probe"}
	if len(h) > 1 {
		h["X-Count"] = "2"
	}
	for k, v := range h {
		h[k] = v + ";"
	}
	return h
}`
	assert.Equal(t, []int{4}, rulestest.GoFileRuleLines(t, NewMirrorCommentCopyRule(), "src/defaults.go", source))
}

func TestMirrorCommentCopyGoBodyCandidateRemainsWithBodyRule(t *testing.T) {
	source := `package api


// derive mirrors defaults.Derive.
func derive(n int) bool {
	if n == 0 {
		return false
	}
	value := n
	if value > 2 {
		value--
	}
	for i := 0; i < 3; i++ {
		value += i
	}
	return value > 0
}`
	ctx := rulestest.GoFile(t, "src/stream.go", source)
	info := &types.Info{
		Defs: make(map[*ast.Ident]types.Object),
		Uses: make(map[*ast.Ident]types.Object),
	}
	_, err := (&types.Config{}).Check("example.com/api", ctx.GoFileSet, []*ast.File{ctx.GoAST}, info)
	assert.NoError(t, err)
	ctx.GoTypesInfo = info
	assert.True(t, duplication.IsDuplicateFuncBodyCandidate(ctx.GoAST.Decls[0].(*ast.FuncDecl), info))
	assert.Empty(t, NewMirrorCommentCopyRule().AnalyzeFile(ctx))
}

// A Go function that only calls the function its note names holds no copy:
// the honest note stays without a finding, whatever words it uses.
func TestMirrorCommentCopyGoWrapperCallingOriginalNotReported(t *testing.T) {
	files := map[string]string{
		"lib/score.go": `package lib

// Score sums the values capped at ceiling.
func Score(xs []int, ceiling int) int {
	total := 0
	for _, x := range xs {
		total += min(x, ceiling)
	}
	return total
}
`,
		"app/weigh.go": `package app

import "example.com/rulestest/lib"

// weigh mirrors lib.Score.
func weigh(xs []int, ceiling int) int { return lib.Score(xs, ceiling) }

// clamp must match lib.Score, so it calls it.
func clamp(xs []int) int { return lib.Score(xs, 10) }
`,
	}
	assert.Empty(t, rulestest.RunRuleOnFiles(t, NewMirrorCommentCopyRule(), files))
}

// Saying which part of the source the copy needs does not make it less of a copy.
func TestMirrorCommentCopyPartialCopyStillReported(t *testing.T) {
	ts := `// Mirrors backend.MaxUploadBytes; only the upload cap is needed in the form.
export const MAX_UPLOAD_BYTES = 10485760;`
	assert.Equal(t, []string{"src/limits.ts:2"}, patterntest.LinesOf(t, NewMirrorCommentCopyRule(), "src/limits.ts", ts))
}
