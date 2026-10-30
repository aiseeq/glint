package dbrules

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func intervalParamViolations(t *testing.T, source string) []*core.Violation {
	t.Helper()
	return NewSQLIntervalParamUntypedRule().AnalyzeFile(rulestest.GoFile(t, "store/repo.go", source))
}

func TestSQLIntervalParamUntyped(t *testing.T) {
	violations := intervalParamViolations(t, `package store
func query(db DB) {
	db.Query("SELECT $2 - INTERVAL '30 days'")
	db.Query("SELECT INTERVAL '30 days' + $3")
	db.Query("SELECT $4 - '30 days'::interval")
	db.Query("SELECT '30 days'::interval + $5")
	db.Query("SELECT created_at FROM orders WHERE created_at < $6 - INTERVAL '30 days'")
	db.Query("SELECT $7 - INTERVAL '30 days' FROM orders")
	db.Query("SELECT $1::timestamptz, $10 - INTERVAL '30 days'")
}
`)
	require.Len(t, violations, 7)
	for _, violation := range violations {
		assert.Equal(t, core.SeverityHigh, violation.Severity)
		assert.Contains(t, violation.Message, "meets INTERVAL arithmetic before any cast")
		assert.Contains(t, violation.Suggestion, "Cast the parameter:")
	}
}

func TestSQLIntervalParamUntypedNegatives(t *testing.T) {
	violations := intervalParamViolations(t, `package store
func query(db DB) {
	db.Query("SELECT $1::timestamptz - INTERVAL '30 days'")
	db.Query("SELECT CAST($2 AS timestamptz) - INTERVAL '30 days'")
	db.Query("SELECT created_at - INTERVAL '30 days' FROM orders")
	db.Query("SELECT $4::date, $4 - INTERVAL '30 days'")
	db.Query("SELECT CAST($5 AS date), $5 - INTERVAL '30 days'")
	db.Query("SELECT t.created_at < $6, $6 - INTERVAL '30 days' FROM orders t")
	db.Query("SELECT $7 - t.created_at, $7 - INTERVAL '30 days' FROM orders t")
	db.Query("SELECT $8 * INTERVAL '30 days'")
	db.Query("SELECT created_at - $9 - INTERVAL '30 days' FROM orders")
}
`)
	assert.Empty(t, violations)
}

func TestSQLIntervalParamUntypedFirstUse(t *testing.T) {
	violations := intervalParamViolations(t, `package store
func query(db DB) {
	db.Query("SELECT $2 - t.created_at, $2 - INTERVAL '30 days' FROM orders t")
	db.Query("SELECT $3 - INTERVAL '30 days', $3 - t.created_at FROM orders t")
}
`)
	require.Len(t, violations, 1)
	assert.Contains(t, violations[0].Message, "$3 meets INTERVAL arithmetic")
}
