package doccheck

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// A section whose code was deleted keeps its banner and the notes about what
// went away: up to the next banner, the brace closing the block or the end of
// the file there is no code under it. A banner with a doc comment and a
// declaration under it heads code; a banner titled END closes a section.
func TestEmptySectionBanner(t *testing.T) {
	file := rulestest.GoFile(t, "store/store.go", `package store

// ==========================================
// CONFIG STRUCTURES
// ==========================================

// Config moved to the config package

// ==========================================
// QUERIES
// ==========================================

// Query runs a statement.
func Query() string {
	// ---- cleanup ----
	return "`+"// ==== not a banner ===="+`"
	// ---- retries ----
	// retries moved to the client
}

// ============= BEGIN HELPERS =============
func helper() {}

// ============= END HELPERS =============

// ============= LEGACY =============

// ============================================================================
// REMOVED API
// ============================================================================

func template() string {
	return `+"`"+`// ==== Utility types ====

/* Amount is a number or a string */
// ==== Constants ====
`+"`"+`
}
`)
	violations := NewEmptySectionBannerRule().AnalyzeFile(file)
	var lines []int
	for _, v := range violations {
		lines = append(lines, v.Line)
	}
	assert.Equal(t, []int{3, 17, 26}, lines)
	if assert.NotEmpty(t, violations) {
		assert.Contains(t, violations[0].Message, `"CONFIG STRUCTURES"`)
	}
}

func TestEmptySectionBannerTypeScript(t *testing.T) {
	file := core.NewFileContext("/src/api.ts", "/src", []byte(`// ===== Types =====

/* the types moved
   to generated.ts */

// ===== Requests =====
export const fetchItems = () => fetch('/items')

// ===== Helpers =====
`), core.DefaultConfig())
	violations := NewEmptySectionBannerRule().AnalyzeFile(file)
	var lines []int
	for _, v := range violations {
		lines = append(lines, v.Line)
	}
	assert.Equal(t, []int{1, 9}, lines)
}
