package patterns

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// decimalStub is the part of github.com/shopspring/decimal the money
// rules reason about. Tests load it as a replaced module so that the code
// under test type-checks against the real import path.
const decimalStub = `package decimal

import "math/big"

type Decimal struct{ value int64 }

var Zero = Decimal{}

func New(v int64, exp int32) Decimal          { return Decimal{value: v} }
func NewFromInt(v int64) Decimal              { return Decimal{value: v} }
func NewFromFloat(v float64) Decimal          { return Decimal{} }
func NewFromString(v string) (Decimal, error) { return Decimal{}, nil }
func RequireFromString(v string) Decimal      { return Decimal{} }
func NewFromBigInt(v *big.Int, exp int32) Decimal { return Decimal{} }

func (d Decimal) Add(o Decimal) Decimal       { return d }
func (d Decimal) Sub(o Decimal) Decimal       { return d }
func (d Decimal) Mul(o Decimal) Decimal       { return d }
func (d Decimal) Div(o Decimal) Decimal       { return d }
func (d Decimal) Round(places int32) Decimal  { return d }
func (d Decimal) RoundCeil(places int32) Decimal  { return d }
func (d Decimal) RoundFloor(places int32) Decimal { return d }
func (d Decimal) RoundUp(places int32) Decimal    { return d }
func (d Decimal) RoundDown(places int32) Decimal  { return d }
func (d Decimal) Truncate(places int32) Decimal   { return d }
func (d Decimal) Ceil() Decimal                   { return d }
func (d Decimal) Floor() Decimal                  { return d }
func (d Decimal) Float64() (float64, bool)        { return 0, true }
func (d Decimal) IntPart() int64                  { return d.value }
func (d Decimal) String() string                  { return "" }
func (d Decimal) StringFixed(places int32) string { return "" }
func (d Decimal) Equal(o Decimal) bool            { return d == o }
func (d Decimal) IsZero() bool                    { return d.value == 0 }
func (d Decimal) DivRound(o Decimal, p int32) Decimal { return d }
func (d Decimal) Mod(o Decimal) Decimal             { return d }
func (d Decimal) QuoRem(o Decimal, p int32) (Decimal, Decimal) { return d, d }
func (d Decimal) Abs() Decimal                      { return d }
func (d Decimal) Neg() Decimal                      { return d }
func (d Decimal) Sign() int                         { return 0 }
func (d Decimal) Cmp(o Decimal) int                 { return 0 }
func (d Decimal) GreaterThan(o Decimal) bool        { return false }
func (d Decimal) GreaterThanOrEqual(o Decimal) bool { return false }
func (d Decimal) LessThan(o Decimal) bool           { return false }
func (d Decimal) LessThanOrEqual(o Decimal) bool    { return false }
func (d Decimal) IsPositive() bool                  { return false }
func (d Decimal) IsNegative() bool                  { return false }
func (d Decimal) RoundBank(places int32) Decimal    { return d }
func (d Decimal) StringFixedBank(places int32) string { return "" }
`

// decimalProject loads the given files as a typed module that can import
// github.com/shopspring/decimal.
func decimalProject(t *testing.T, files map[string]string) *core.GoProjectContext {
	t.Helper()
	all := map[string]string{
		"go.mod": "module example.com/rulestest\n\ngo 1.24\n\n" +
			"require github.com/shopspring/decimal v0.0.0\n\n" +
			"replace github.com/shopspring/decimal => ./third_party/decimal\n",
		"third_party/decimal/go.mod":     "module github.com/shopspring/decimal\n\ngo 1.24\n",
		"third_party/decimal/decimal.go": decimalStub,
	}
	for name, content := range files {
		all[name] = content
	}
	return rulestest.Project(t, all)
}
