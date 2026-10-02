package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// A chain's explorer left on its test network among the production explorers
// of the other chains.
func TestTestnetURLAmongMainnet(t *testing.T) {
	ctx := createAppendContext(t, "chains/explorers.go", `package chains

const (
	ChainA       = "a"
	ChainB       = "b"
	ChainC       = "c"
	ChainSepolia = "sepolia"
)

var explorers = map[string]string{
	ChainA:       "https://explorer-a.io/tx/",
	ChainB:       "https://scan.b-chain.org/tx/",
	ChainC:       "https://testnet.c-explorer.xyz/tx/",
	ChainSepolia: "https://sepolia.explorer-a.io/tx/",
}

var testNodes = map[string]string{
	ChainA: "https://rpc-testnet.a.io",
	ChainB: "https://rpc.sepolia.b.org",
	ChainC: "https://devnet.c.xyz",
}

var pair = []string{"https://api.a.io", "https://api.testnet.a.io"}

var contestHosts = []string{"https://contest.example.com", "https://a.io", "https://b.io"}
`)
	var lines []int
	for _, v := range NewTestnetURLAmongMainnetRule().AnalyzeFile(ctx) {
		lines = append(lines, v.Line)
	}
	assert.Equal(t, []int{13}, lines)
}
