package patterns

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

func bigSetStringFindings(t *testing.T, files map[string]string) []string {
	t.Helper()
	violations, err := NewBigSetStringUncheckedRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	var out []string
	for _, v := range violations {
		out = append(out, fmt.Sprintf("%s:%d", v.File, v.Line))
	}
	return out
}

// A hex amount that does not parse leaves the value at zero: the transfer
// is recorded as zero instead of failing.
func TestBigSetStringUnchecked(t *testing.T) {
	found := bigSetStringFindings(t, map[string]string{
		"chain/amount.go": `package chain

import (
	"errors"
	"math/big"
	"reflect"
	"strings"
)

func Amount(hexValue string) *big.Int {
	value := new(big.Int)
	value.SetString(strings.TrimPrefix(hexValue, "0x"), 16)
	return value
}

func Rate(text string) *big.Float {
	rate, _ := new(big.Float).SetString(text)
	return rate
}

func Share(text string) *big.Rat {
	share := new(big.Rat)
	share.SetString(text)
	return share
}

func Checked(hexValue string) (*big.Int, error) {
	value, ok := new(big.Int).SetString(hexValue, 16)
	if !ok {
		return nil, errors.New("bad amount")
	}
	return value, nil
}

type label struct{}

func (label) SetString(s string, n int) {}

func Other(v reflect.Value, l label) {
	v.SetString("x")
	l.SetString("x", 16)
}
`,
		"chain/amount_test.go": `package chain

import "math/big"

func fixture() *big.Int {
	n := new(big.Int)
	n.SetString("ff", 16)
	return n
}
`,
	})
	assert.Equal(t, []string{"chain/amount.go:12", "chain/amount.go:17", "chain/amount.go:23", "chain/amount_test.go:7"}, found)
}
