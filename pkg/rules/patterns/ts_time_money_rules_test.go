package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Repro from a real project: the arrival field of a transfer was filled with
// the UTC digits of the stored timestamp, the operator's browser read them
// as local time, and the saved arrival moved by the zone offset.
func TestDatetimeLocalFilledWithUTC(t *testing.T) {
	assert.Equal(t, []string{"src/Journal.tsx:13", "src/Journal.tsx:7"}, linesOf(t, NewDatetimeLocalFilledWithUTCRule(), "src/Journal.tsx", `export function Journal({ transfer, setTransfer, at }: Props) {
  return (
    <div>
      <input
        type="datetime-local"
        title="Arrived (executed_at)"
        value={transfer.executedAt != null ? transfer.executedAt.slice(0, 16) : ''}
        onChange={e => setTransfer({ ...transfer, executedAt: e.target.value })}
      />
      <input type="datetime-local" value={toLocalInput(at)} onChange={e => setTransfer({ ...transfer, at: e.target.value })} />
      <input type="text" value={transfer.note.slice(0, 16)} />
      <input type="date" value={transfer.day.slice(0, 10)} />
      <Input type='datetime-local' defaultValue={new Date(at).toISOString().substring(0, 16)} />
    </div>
  )
}
`))
}

const halfUpGoEntries = `package ledger

import "github.com/shopspring/decimal"

type DailyEntry struct {
	Date         string ` + "`json:\"date\"`" + `
	ClosingAmount string ` + "`json:\"totalBalance\"`" + `
	DailyGain   string ` + "`json:\"dailyGain\"`" + `
	Fee          string ` + "`json:\"fee\"`" + `
}

func entry(balance, yield, fee decimal.Decimal) DailyEntry {
	return DailyEntry{
		Date:         "2026-01-02",
		ClosingAmount: balance.RoundFloor(2).StringFixed(2),
		DailyGain:   yield.StringFixed(2),
		Fee:          fee.String(),
	}
}
`

// Repro from a real project: the backend rounded the day's yield half up
// and the feed floored it to cents, while the "yesterday" card floored the
// raw figure; the two showed amounts a cent apart for the same day.
func TestClientFloorsServerRoundedAmount(t *testing.T) {
	assert.Equal(t, []string{"frontend/feed.ts:12", "frontend/feed.ts:8"},
		deployFindings(t, "client-floors-server-rounded-amount", map[string]string{
			"backend/ledger/entry.go": halfUpGoEntries,
			"frontend/feed.ts": `import { floorToCent } from './money'

export function rows(entries: DailyEntry[]) {
  return entries.map(entry => {
    const delta = parseRequiredDecimal('dailyGain', entry.dailyGain)
    const balance = Number(entry.totalBalance)
    return {
      amount: floorToCent(delta),
      balance: floorToCent(balance),
      fee: floorToCent(Number(entry.fee)),
      raw: Math.floor(Number(entry.dailyGain)),
      cents: Math.floor(Number(entry.dailyGain) * 100) / 100,
    }
  })
}
`,
			"frontend/money.ts": `export function floorToCent(value: number): number {
  return Math.floor(value * 100 + 1e-9) / 100
}
`,
		}))
}
