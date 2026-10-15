package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// hotSmallMapSource answers "is this one of three ids" with a hash lookup on
// every tick; a switch on the constants answers it without hashing. A map
// someone writes to, one with many keys, one with keys known only at run
// time, or one read outside hot code is a table, not a set of constants.
const hotSmallMapSource = `package units

const (
	KindA   = 45
	KindB = 84
	KindC = 104
)

var fastKinds = map[uint32]bool{KindA: true, KindB: true, KindC: true}

var (
	bonus = map[uint32]uint32{KindA: 1, KindB: 2}
	learned = map[uint32]bool{KindA: true}
	big     = map[int]int{1: 1, 2: 2, 3: 3, 4: 4, 5: 5, 6: 6, 7: 7, 8: 8, 9: 9}
	dynamic = map[int]bool{kindBID(): true}
	coldSet = map[int]bool{1: true}
	passed  = map[int]bool{1: true}
)

func kindBID() int { return KindB }

func Learn(t uint32) { learned[t] = true }

func Use(m map[int]bool) {}

//glint:hot
func IsFast(t uint32) bool {
	return fastKinds[t] // want small-constant-map-in-hot-function
}

//glint:hot
func Step(t uint32, n int) uint32 {
	b, ok := bonus[t] // want small-constant-map-in-hot-function
	if !ok || learned[t] || dynamic[n] || passed[n] {
		return 0
	}
	Use(passed)
	return b + uint32(big[n]) + uint32(len(fastKinds))
}

func Cold(n int) bool { return coldSet[n] }
`

func TestSmallConstantMapInHotFunction(t *testing.T) {
	files := map[string]string{"units/units.go": hotSmallMapSource}
	violations, err := NewSmallConstantMapInHotFunctionRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	assert.Equal(t, wantedLines(files, "small-constant-map-in-hot-function"), foundLines(violations))
}
