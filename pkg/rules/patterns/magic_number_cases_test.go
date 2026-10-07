package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// Chain IDs are registry numbers that name themselves wherever the code
// labels them as chain IDs, in any directory of any project: no path list.
func TestMagicNumberChainIDIsSelfDescribing(t *testing.T) {
	ctx := rulestest.GoFile(t, "payprov/networks.go", `package payprov

type Network struct {
	Name    string
	ChainID int64
}

func networkFor(name string) Network {
	return Network{Name: name, ChainID: 8453}
}

func label(chainID int64) string {
	switch chainID {
	case 42161:
		return "arb"
	}
	return ""
}

func retries() int {
	return 4321
}
`)
	violations := NewMagicNumberRule().AnalyzeFile(ctx)
	require.Len(t, violations, 1)
	assert.Equal(t, "4321", violations[0].Code)
}

// A provider directory is not exempt by its name: the old project-specific
// path exemption is gone.
func TestMagicNumberProviderDirectoryIsNotExempt(t *testing.T) {
	rule := NewMagicNumberRule()
	assert.False(t, rule.shouldSkipFile("walletprov/client.go"))
	ctx := rulestest.GoFile(t, "walletprov/client.go", `package walletprov

func limit() int { return 4321 }
`)
	assert.Len(t, rule.AnalyzeFile(ctx), 1)
}

// A package-level map or slice literal is a lookup table: its keys and
// elements are external identifiers (chain IDs, instruction discriminator
// bytes, provider error codes) that the table itself names. Every number of
// such a table is skipped alike; numbers inside functions stay reported, each
// one of them.
func TestMagicNumberPackageLevelLookupTables(t *testing.T) {
	ctx := rulestest.GoFile(t, "bridge/tables.go", `package bridge

var supportedChains = map[int]string{1: "ethereum", 56: "bnb", 8453: "base"}

var ownChainIDs = map[int64]string{224235520: "ton"}

var discriminator = []byte{217, 106, 208, 99, 116, 151, 42, 135}

var unreachableCodes = []int{2, 3, 35, 45, 49}

var weights = map[string]int{"a": 4321}

type limit struct {
	Name string
	Max  int
}

var limits = []limit{{"daily", 7777}}

func pick() []int {
	return []int{4321, 4322}
}
`)
	var codes []string
	for _, v := range NewMagicNumberRule().AnalyzeFile(ctx) {
		codes = append(codes, v.Code)
	}
	assert.Equal(t, []string{"7777", "4321", "4322"}, codes)
}
