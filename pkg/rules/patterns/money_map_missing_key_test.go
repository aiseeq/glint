package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMoneyMapMissingKeyReadAsZero(t *testing.T) {
	assert.Equal(t, []string{"report/report.go:13", "report/report.go:19"}, typedFuncFindings(t, NewMoneyMapMissingKeyReadAsZeroRule(), map[string]string{
		"report/report.go": `package report

import "github.com/shopspring/decimal"

type CalendarDate string
func (date CalendarDate) Format(string) string { return string(date) }
type Snapshot struct{ Date CalendarDate }
type Context struct{ values map[string]decimal.Decimal }
type Response struct{ Profit decimal.Decimal }

func Build(snapshot Snapshot, context Context) Response {
	key := string(snapshot.Date)
	profit := context.values[key] // want
	return Response{Profit: profit}
}

func BuildFormatted(snapshot Snapshot, context Context) Response {
	key := snapshot.Date.Format("2006-01-02")
	profit := context.values[key] // want
	return Response{Profit: profit}
}

func Checked(snapshot Snapshot, context Context) Response {
	if profit, ok := context.values[string(snapshot.Date)]; ok {
		return Response{Profit: profit}
	}
	return Response{}
}

func ReadChecked(values map[string]decimal.Decimal, key string) (decimal.Decimal, bool) {
	value, ok := values[key]
	return value, ok
}

func OwnKeys(context Context) decimal.Decimal {
	for key := range context.values {
		return context.values[key]
	}
	return decimal.Zero
}

func ShadowedOwnMapKey(key string, context Context) decimal.Decimal {
	for key := range context.values {
		return context.values[key]
	}
	return decimal.Zero
}

func NonMoney(snapshot Snapshot, context struct{ values map[string]int }) int {
	return context.values[string(snapshot.Date)]
}
`,
	}))
}
