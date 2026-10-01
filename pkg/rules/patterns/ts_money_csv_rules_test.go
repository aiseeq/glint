package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// A valuation used only when positive and replaced with the invested amount
// otherwise: a lost investment reads as break-even.
func TestMoneyZeroShownAsOtherField(t *testing.T) {
	rule := NewMoneyZeroShownAsOtherFieldRule()
	assert.Equal(t, []string{"src/lib/portfolio.ts:3", "src/lib/portfolio.ts:9"}, linesOf(t, rule, "src/lib/portfolio.ts", `export function value(inv: Investment, invAmount: number) {
  const currentValue = (() => {
    if (inv.currentValue !== undefined && parseFloat(String(inv.currentValue)) > 0) {
      return parseFloat(String(inv.currentValue))
    }
    // valuation not done yet
    return invAmount
  })()
  const shown = inv.balance > 0 ? inv.balance : inv.depositAmount
  const fee = inv.fee > 0 ? inv.fee : 0
  const count = page.total > 0 ? page.total : items.length
  if (inv.amount > 0) {
    return inv.amount
  }
  return null
}
`))
}

// A CSV export that doubles quotes but keeps a leading = runs a user's text
// as a spreadsheet formula on the admin's machine.
func TestCSVFormulaInjection(t *testing.T) {
	rule := NewCSVFormulaInjectionRule()
	unguarded := `function exportToCsv(rows: Row[]) {
  const lines = rows.map(row => row.map(value => {
    const str = String(value)
    return str.includes(',') ? '"' + str.replace(/"/g, '""') + '"' : str
  }).join(','))
  const blob = new Blob([lines.join('\n')], { type: 'text/csv' })
  return blob
}
`
	assert.Equal(t, []string{"src/export.ts:4"}, linesOf(t, rule, "src/export.ts", unguarded))

	guarded := `function sanitize(value: string): string {
  return /^[=+\-@]/.test(value) ? "'" + value : value
}
` + unguarded
	assert.Empty(t, linesOf(t, rule, "src/export.ts", guarded))

	notCSV := `export const quote = (s: string) => s.replace(/"/g, '""')
`
	assert.Empty(t, linesOf(t, rule, "src/sql.ts", notCSV))
}
