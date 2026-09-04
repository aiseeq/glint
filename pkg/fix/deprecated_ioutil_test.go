package fix

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
)

// Repro found by the map-iteration-order rule inside glint itself: the fixer
// picked the replacement by walking a map, so a line using two ioutil calls got
// a different rewrite on every run.
func TestDeprecatedIoutilFixerPicksSameReplacementEveryRun(t *testing.T) {
	ctx := fixerContext(t, `package sample

func read(r io.Reader) {
	data, _ := ioutil.ReadAll(ioutil.NopCloser(r))
	_ = data
}
`)
	violation := &core.Violation{Rule: "deprecated-ioutil", File: "rule.go", Line: 4}
	fixer := NewDeprecatedIoutilFixer()

	first := fixer.GenerateFix(ctx, violation)
	require.Len(t, first, 1)

	for range 50 {
		again := fixer.GenerateFix(ctx, violation)
		require.Len(t, again, 1)
		assert.Equal(t, first[0].OldText, again[0].OldText, "the replacement must not depend on map walk order")
		assert.Equal(t, first[0].NewText, again[0].NewText)
	}
}

func TestDeprecatedIoutilFixerRewritesSingleCall(t *testing.T) {
	ctx := fixerContext(t, `package sample

func read(path string) {
	data, _ := ioutil.ReadFile(path)
	_ = data
}
`)
	fixes := NewDeprecatedIoutilFixer().GenerateFix(ctx, &core.Violation{Rule: "deprecated-ioutil", File: "rule.go", Line: 4})

	require.Len(t, fixes, 1)
	assert.Equal(t, "ioutil.ReadFile", fixes[0].OldText)
	assert.Equal(t, "os.ReadFile", fixes[0].NewText)
}
