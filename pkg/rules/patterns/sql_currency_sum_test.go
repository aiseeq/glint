package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

const currencySumMigration = `CREATE TABLE transfers (
    id UUID PRIMARY KEY,
    batch_id UUID,
    status TEXT NOT NULL,
    sender_currency VARCHAR(5) NOT NULL,
    payout_currency VARCHAR(5) NOT NULL,
    transfer_amount NUMERIC(20,2) NOT NULL,
    fee_amount NUMERIC(20,2),
    attempts INT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE fees (id UUID PRIMARY KEY, amount NUMERIC NOT NULL);`

// A dashboard total summing transfer amounts of every currency makes a
// number in none; a total per currency, one fixed to a currency, one over
// the rows of one batch, a count and a table without currencies are fine.
func TestMoneySummedAcrossCurrencies(t *testing.T) {
	files := map[string]string{
		"storage/migrations/001_init.up.sql": currencySumMigration,
		"storage/repo.go": `package storage

func Stats(db DB, where string, args []any) {
	db.QueryRowContext(ctx, ` + "`" + `
		SELECT COUNT(*),
			COALESCE(SUM(transfer_amount) FILTER (WHERE status <> 'CANCELLED'), 0),
			COALESCE(SUM(t.fee_amount), 0)
		FROM transfers t` + "`" + `+where, args...)
}

func Others(db DB, cur string) {
	db.QueryContext(ctx, "SELECT sender_currency, SUM(transfer_amount) FROM transfers GROUP BY sender_currency")
	db.QueryContext(ctx, "SELECT sender_currency, SUM(transfer_amount) FROM transfers GROUP BY 1")
	db.QueryRowContext(ctx, "SELECT SUM(transfer_amount) FROM transfers WHERE sender_currency = $1", cur)
	db.QueryRowContext(ctx, "SELECT SUM(transfer_amount) FROM transfers WHERE batch_id = $1", batch)
	db.QueryRowContext(ctx, "SELECT SUM(attempts) FROM transfers")
	db.QueryRowContext(ctx, "SELECT SUM(amount) FROM fees")
}
`,
	}
	assert.Equal(t, []int{6, 7}, moduleSQLRuleLines(t, NewMoneySummedAcrossCurrenciesRule(), files, "storage/repo.go"))
}

// A WHERE joined in from a builder of the same file that fixes the currency
// keeps the sum to one currency.
func TestMoneySummedAcrossCurrenciesBuiltWhere(t *testing.T) {
	files := map[string]string{
		"storage/migrations/001_init.up.sql": currencySumMigration,
		"storage/repo.go": `package storage

func where(cur string) string { return " WHERE sender_currency = $1" }

func Stats(db DB, cur string) {
	db.QueryRowContext(ctx, "SELECT SUM(transfer_amount) FROM transfers"+where(cur), cur)
}
`,
	}
	assert.Empty(t, moduleSQLRuleLines(t, NewMoneySummedAcrossCurrenciesRule(), files, "storage/repo.go"))
}
