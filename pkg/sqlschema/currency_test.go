package sqlschema

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMixedCurrencySums(t *testing.T) {
	schema := (&Schema{tables: map[string]*Table{}}).With([]string{`CREATE TABLE transfers (
    id UUID PRIMARY KEY,
    batch_id UUID,
    sender_currency VARCHAR(5) NOT NULL,
    transfer_amount NUMERIC(20,2) NOT NULL,
    attempts INT NOT NULL DEFAULT 0
)`, `CREATE TABLE deposits (id UUID PRIMARY KEY, currency VARCHAR(10) NOT NULL DEFAULT 'USDC', amount NUMERIC NOT NULL)`})
	// A table whose currency every row gets by default is kept in one.
	assert.Empty(t, schema.MixedCurrencySums("SELECT SUM(amount) FROM deposits"))
	sql := "SELECT COUNT(*), SUM(transfer_amount) FROM transfers WHERE created_at > $1"
	sums := schema.MixedCurrencySums(sql)
	if assert.Len(t, sums, 1) {
		assert.Equal(t, "transfer_amount", sums[0].Column)
		assert.Equal(t, []string{"sender_currency"}, sums[0].Currency)
		assert.Equal(t, "SUM(transfer_amount)", sql[sums[0].Offset:sums[0].Offset+20])
	}
	assert.Empty(t, schema.MixedCurrencySums("SELECT sender_currency, SUM(transfer_amount) FROM transfers GROUP BY 1"))
	assert.Empty(t, schema.MixedCurrencySums("SELECT SUM(transfer_amount) FROM transfers WHERE batch_id = $1"))
	assert.Empty(t, schema.MixedCurrencySums("SELECT SUM(attempts) FROM transfers"))
}
