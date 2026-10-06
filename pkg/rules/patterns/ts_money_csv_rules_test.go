package patterns

import (
	"strings"
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
  return /^[=+\-@\t\r]/.test(value) ? "'" + value : value
}
` + unguarded
	assert.Empty(t, linesOf(t, rule, "src/export.ts", guarded))

	notCSV := `export const quote = (s: string) => s.replace(/"/g, '""')
`
	assert.Empty(t, linesOf(t, rule, "src/sql.ts", notCSV))
}

// A spreadsheet takes a leading tab or carriage return for a formula start
// too, and a carriage return inside an unquoted cell breaks the row: a guard
// of =, +, - and @ only, or quoting on \n but not \r, lets them through.
func TestCSVFormulaInjectionIncompleteGuard(t *testing.T) {
	rule := NewCSVFormulaInjectionRule()
	partial := `const SIGNED_NUMBER = /^[+-]?\d+(?:\.\d+)?$/

export function sanitizeCsvField(value: string): string {
  if (/^[=+\-@]/.test(value) && !SIGNED_NUMBER.test(value)) {
    return "'" + value
  }
  return value
}

export function escapeCsvCell(value: unknown): string {
  const str = sanitizeCsvField(String(value))
  if (str.includes(',') || str.includes('"') || str.includes('\n')) {
    return '"' + str.replace(/"/g, '""') + '"'
  }
  return str
}
`
	assert.Equal(t, []string{"src/csv.ts:12", "src/csv.ts:4"}, linesOf(t, rule, "src/csv.ts", partial))

	guardOnly := strings.NewReplacer(`@]`, `@\t\r]`).Replace(partial)
	assert.Equal(t, []string{"src/csv.ts:12"}, linesOf(t, rule, "src/csv.ts", guardOnly))

	complete := strings.NewReplacer(`@]`, `@\t\r]`, `str.includes('\n')`, `str.includes('\n') || str.includes('\r')`).Replace(partial)
	assert.Empty(t, linesOf(t, rule, "src/csv.ts", complete))

	classQuoted := strings.NewReplacer(`@]`, `@\t\r]`, `str.includes(',') || str.includes('"') || str.includes('\n')`, `/[",\r\n]/.test(str)`).Replace(partial)
	assert.Empty(t, linesOf(t, rule, "src/csv.ts", classQuoted))
}
