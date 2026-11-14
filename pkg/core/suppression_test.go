package core

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// A marker keeps the highest severity of the findings it silenced: the
// oversight finding about a marker without a reason is as severe as what the
// marker hides. A marker a rule consulted on its own (IsSuppressed) silenced
// a finding of unknown severity, and is unrated.
func TestSuppressionHitKeepsTheHighestSeverity(t *testing.T) {
	source := "package p\n//nolint:my-rule\nvar a, b = 1, 2\nvar c = 3 //nolint:my-rule\n"
	ctx := &FileContext{Path: "a.go", RelPath: "a.go", Lines: strings.Split(source, "\n")}

	assert.True(t, ctx.SuppressesFinding(3, "my-rule", SeverityMedium))
	assert.True(t, ctx.SuppressesFinding(3, "my-rule", SeverityCritical))
	assert.True(t, ctx.SuppressesFinding(3, "my-rule", SeverityLow))
	assert.True(t, ctx.IsSuppressed(4, "my-rule"))
	assert.False(t, ctx.SuppressesFinding(1, "my-rule", SeverityHigh), "no marker covers line 1")

	assert.Equal(t, []SuppressionHit{
		{Line: 2, Severity: SeverityCritical, Rated: true},
		{Line: 4},
	}, ctx.TakeSuppressions("my-rule"))
	assert.Empty(t, ctx.TakeSuppressions("my-rule"), "taken hits are forgotten")
}

// A marker consulted on its own first and with a severity later is rated by
// the severity; the lines alone are what TakeSuppressionHits returns.
func TestSuppressionHitRatedAfterAnUnratedConsult(t *testing.T) {
	source := "//nolint:my-rule\nx\n"
	ctx := &FileContext{Path: "a.go", RelPath: "a.go", Lines: strings.Split(source, "\n")}

	assert.True(t, ctx.IsSuppressed(2, "my-rule"))
	assert.True(t, ctx.SuppressesFinding(2, "my-rule", SeverityHigh))
	assert.Equal(t, []SuppressionHit{{Line: 1, Severity: SeverityHigh, Rated: true}}, ctx.TakeSuppressions("my-rule"))

	assert.True(t, ctx.SuppressesFinding(2, "my-rule", SeverityHigh))
	assert.Equal(t, []int{1}, ctx.TakeSuppressionHits("my-rule"))
	assert.Empty(t, ctx.TakeSuppressions("my-rule"), "TakeSuppressionHits forgets the severity too")

	assert.True(t, ctx.IsSuppressed(2, "my-rule"))
	assert.Equal(t, []SuppressionHit{{Line: 1}}, ctx.TakeSuppressions("my-rule"), "a severity taken before rates no later consult")
}
