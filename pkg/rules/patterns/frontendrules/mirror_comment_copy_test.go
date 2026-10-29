package frontendrules

import (
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patterntest"
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
