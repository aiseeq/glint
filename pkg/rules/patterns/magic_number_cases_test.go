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
