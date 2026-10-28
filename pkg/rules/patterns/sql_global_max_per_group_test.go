package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSQLGlobalMaxUsedAsPerGroupLatest(t *testing.T) {
	query := `WITH latest AS (
		SELECT MAX(rate_date) AS rate_date FROM rates
		WHERE (from_currency = $1 OR to_currency = $1) AND rate_date <= $2
	)
	SELECT from_currency, to_currency, rate, rate_date FROM rates
	WHERE rate_date = (SELECT rate_date FROM latest)
	  AND (from_currency = $1 OR to_currency = $1)
	ORDER BY from_currency, to_currency`
	source := "package repo\nfunc Rates(db DB) { db.Query(`" + query + "`) }\n"
	assert.Equal(t, []int{7}, sqlFileRuleLines(t, NewSQLGlobalMaxUsedAsPerGroupLatestRule(), "repo/rates.go", source))
}

func TestSQLGlobalMaxUsedAsPerGroupLatestSafeQueries(t *testing.T) {
	for _, query := range []string{
		`SELECT DISTINCT ON (from_currency, to_currency) from_currency, to_currency, rate_date FROM rates WHERE rate_date <= $1 ORDER BY from_currency, to_currency, rate_date DESC`,
		`SELECT from_currency, to_currency, rate_date FROM rates r WHERE rate_date = (SELECT MAX(rate_date) FROM rates x WHERE x.from_currency = r.from_currency AND x.to_currency = r.to_currency)`,
		`SELECT rate_date FROM rates WHERE rate_date = (SELECT MAX(rate_date) FROM rates)`,
		// the latest complete publication: the whole set of one date is wanted
		`SELECT from_currency, to_currency, rate_date FROM rates WHERE rate_date = (SELECT MAX(rate_date) FROM rates) ORDER BY from_currency, to_currency`,
		`SELECT from_currency, to_currency, rate_date FROM rates WHERE rate_date = (SELECT MAX(rate_date) FROM rates WHERE rate_date <= $1) ORDER BY from_currency, to_currency`,
		`WITH latest AS (SELECT MAX(rate_date) AS rate_date FROM rates WHERE rate_date <= $1) SELECT from_currency, to_currency, rate_date FROM rates WHERE rate_date = (SELECT rate_date FROM latest) ORDER BY from_currency, to_currency`,
	} {
		source := "package repo\nfunc Rates(db DB) { db.Query(`" + query + "`) }\n"
		assert.Empty(t, sqlFileRuleLines(t, NewSQLGlobalMaxUsedAsPerGroupLatestRule(), "repo/rates.go", source), query)
	}
}

func TestSQLGlobalMaxUsedAsPerGroupLatestSubquery(t *testing.T) {
	queries := []string{
		`SELECT from_currency, to_currency, rate_date FROM rates WHERE rate_date = (SELECT MAX(rate_date) FROM rates WHERE from_currency = $1 OR to_currency = $1) ORDER BY from_currency, to_currency`,
		`SELECT from_currency, to_currency, rate_date FROM rates r WHERE rate_date = (SELECT MAX(rate_date) FROM rates x WHERE x.from_currency = r.from_currency AND x.to_currency = r.to_currency) ORDER BY from_currency, to_currency`,
	}
	for i, query := range queries {
		source := "package repo\nfunc Rates(db DB) { db.Query(`" + query + "`) }\n"
		lines := sqlFileRuleLines(t, NewSQLGlobalMaxUsedAsPerGroupLatestRule(), "repo/rates.go", source)
		if i == 0 {
			assert.Equal(t, []int{2}, lines)
		} else {
			assert.Empty(t, lines)
		}
	}
}
