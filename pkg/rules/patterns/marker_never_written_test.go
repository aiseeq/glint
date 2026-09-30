package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// A check for a marker the code no longer writes: the writer dropped the
// "[promo]" prefix, the reader kept looking for it, and promotional credits
// were counted as paid ones.
func TestMarkerNeverWritten(t *testing.T) {
	files := map[string]string{
		"activity/split.go": `package activity

import "strings"

func IsPromo(description string) bool {
	return strings.HasPrefix(description, "[promo]") // want marker-never-written
}

func IsRefund(description string) bool {
	return strings.Contains(description, "[refund]")
}

func IsBonus(note string) bool {
	return strings.HasPrefix(note, "[bonus]")
}

func IsPlain(s string) bool {
	return strings.HasPrefix(s, "plain")
}
`,
		"activity/write.go": `package activity

import "fmt"

func RefundNote(id string) string { return "[refund] " + id }

func BonusNote(id string) string { return fmt.Sprintf("[bonus] %s", id) }
`,
		"activity/split_test.go": `package activity

import "testing"

func TestIsPromo(t *testing.T) {
	if !IsPromo("[promo] code") {
		t.Fatal("promo")
	}
}
`,
	}
	violations, err := NewMarkerNeverWrittenRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	assert.Equal(t, wantedLines(files, "marker-never-written"), foundLines(violations))
}
