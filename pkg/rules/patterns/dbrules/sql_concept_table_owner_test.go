package dbrules

import (
	"testing"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func configuredConceptOwner(t *testing.T, where string) *SQLConceptTableOwnerRule {
	t.Helper()
	concept := map[string]any{
		"name": "staff", "table": "staff",
		"files": []any{"consts/staff.go", "repo/staff_repository.go"},
	}
	if where != "" {
		concept["where"] = where
	}
	rule := NewSQLConceptTableOwnerRule()
	require.NoError(t, rule.Configure(map[string]any{"concepts": []any{concept}}))
	return rule
}

func TestSQLConceptTableOwner_Join(t *testing.T) {
	rule := configuredConceptOwner(t, "")
	outside := rulestest.GoFile(t, "alerts/bot.go", `package alerts
func run() {
 db.Query("SELECT u.id FROM users u JOIN staff s ON s.user_id = u.id")
 db.Query("SELECT user_id FROM staff")
}`)
	owner := rulestest.GoFile(t, "consts/staff.go", `package consts
func run() { db.Query("SELECT user_id FROM staff") }
`)
	assert.Len(t, rule.AnalyzeFile(outside), 2)
	assert.Empty(t, rule.AnalyzeFile(owner))
}

func TestSQLConceptTableOwner_CTENameShadows(t *testing.T) {
	rule := configuredConceptOwner(t, "")
	ctx := rulestest.GoFile(t, "alerts/bot.go", `package alerts
func run() {
 db.Query("WITH staff AS (SELECT id FROM users) SELECT id FROM staff")
}
`)
	assert.Empty(t, rule.AnalyzeFile(ctx))
}

func TestSQLConceptTableOwner_CTEReadsSameTable(t *testing.T) {
	rule := configuredConceptOwner(t, "")
	ctx := rulestest.GoFile(t, "alerts/bot.go", `package alerts
func run() {
 db.Query("WITH staff AS (SELECT id FROM staff) SELECT id FROM staff")
}
`)
	assert.Len(t, rule.AnalyzeFile(ctx), 1)
}

func TestSQLConceptTableOwner_Schema(t *testing.T) {
	rule := NewSQLConceptTableOwnerRule()
	require.NoError(t, rule.Configure(map[string]any{"concepts": []any{
		map[string]any{"name": "staff", "table": "public.staff", "files": []any{"consts/staff.go"}},
	}}))
	ctx := rulestest.GoFile(t, "alerts/bot.go", `package alerts
func run() {
 db.Query("SELECT id FROM public.staff")
 db.Query("SELECT id FROM private.staff")
 db.Query("SELECT id FROM staff")
}
`)
	assert.Len(t, rule.AnalyzeFile(ctx), 1)

	unqualified := configuredConceptOwner(t, "")
	qualified := rulestest.GoFile(t, "alerts/qualified.go", `package alerts
func run() { db.Query("SELECT id FROM private.staff") }
`)
	assert.Len(t, unqualified.AnalyzeFile(qualified), 1)
}

func TestSQLConceptTableOwner_Exists(t *testing.T) {
	rule := configuredConceptOwner(t, "")
	ctx := rulestest.GoFile(t, "alerts/bot.go", `package alerts
func run() {
 db.Query("SELECT id FROM users u WHERE EXISTS (SELECT 1 FROM staff s WHERE s.user_id = u.id)")
 db.Query("SELECT id FROM users WHERE id IN (SELECT user_id FROM staff)")
}`)
	assert.Len(t, rule.AnalyzeFile(ctx), 2)
}

func TestSQLConceptTableOwner_LeftJoinForColumns(t *testing.T) {
	rule := configuredConceptOwner(t, "")
	ctx := rulestest.GoFile(t, "alerts/bot.go", `package alerts
func run() {
 db.Query("SELECT u.id, s.created_by FROM users u LEFT JOIN staff s ON s.user_id = u.id WHERE u.active")
 db.Query("SELECT u.id FROM users u LEFT JOIN staff s ON s.user_id = u.id WHERE s.id IS NULL")
}`)
	assert.Len(t, rule.AnalyzeFile(ctx), 1)
}

func TestSQLConceptTableOwner_AntiJoinSchemaNoAlias(t *testing.T) {
	rule := configuredConceptOwner(t, "")
	ctx := rulestest.GoFile(t, "alerts/bot.go", `package alerts
func run() {
 db.Query("SELECT u.id FROM users u LEFT JOIN public.staff ON staff.user_id = u.id WHERE staff.id IS NULL")
}
`)
	assert.Len(t, rule.AnalyzeFile(ctx), 1)
}

func TestSQLConceptTableOwner_Where(t *testing.T) {
	rule := configuredConceptOwner(t, "name = 'internal'")
	ctx := rulestest.GoFile(t, "alerts/bot.go", `package alerts
func run() {
 db.Query("SELECT m.id FROM members m JOIN staff s ON s.member_id = m.id JOIN groups g ON g.id = m.group_id WHERE g.name = 'internal'")
 db.Query("SELECT m.id FROM members m JOIN staff s ON s.member_id = m.id JOIN groups g ON g.id = m.group_id WHERE g.name = 'external'")
}`)
	assert.Len(t, rule.AnalyzeFile(ctx), 1)
}

func TestSQLConceptTableOwner_Settings(t *testing.T) {
	ctx := rulestest.GoFile(t, "alerts/bot.go", `package alerts
func run() { db.Query("SELECT user_id FROM staff") }
`)
	assert.Empty(t, NewSQLConceptTableOwnerRule().AnalyzeFile(ctx))
	for _, settings := range []map[string]any{
		{"concepts": "staff"},
		{"concepts": []any{map[string]any{"name": "staff", "files": []any{"consts/staff.go"}}}},
		{"concepts": []any{map[string]any{"name": "staff", "table": "staff"}}},
		{"concepts": []any{map[string]any{"name": "staff", "table": "staff", "files": "consts/staff.go"}}},
	} {
		err := NewSQLConceptTableOwnerRule().Configure(settings)
		assert.Error(t, err)
	}
}

func TestSQLConceptTableOwner_Writes(t *testing.T) {
	rule := configuredConceptOwner(t, "")
	ctx := rulestest.GoFile(t, "repo/updates.go", `package repo
func run() {
 db.Exec("UPDATE staff SET active = false WHERE id = $1")
 db.Exec("DELETE FROM staff WHERE id = $1")
}`)
	testFile := rulestest.GoFile(t, "repo/updates_test.go", `package repo
func TestStaff() { db.Query("SELECT id FROM staff") }
`)
	assert.Empty(t, rule.AnalyzeFile(ctx))
	assert.Empty(t, rule.AnalyzeFile(testFile))
}

func TestSQLConceptTableOwner_OwnerGlob(t *testing.T) {
	rule := NewSQLConceptTableOwnerRule()
	require.NoError(t, rule.Configure(map[string]any{"concepts": []any{
		map[string]any{"name": "staff", "table": "staff", "files": []any{"cmd/**"}},
	}}))
	owner := rulestest.GoFile(t, "cmd/tool/main.go", `package main
func run() { db.Query("SELECT id FROM staff") }
`)
	nonOwner := rulestest.GoFile(t, "repo/a.go", `package repo
func run() { db.Query("SELECT id FROM staff") }
`)
	assert.Empty(t, rule.AnalyzeFile(owner))
	assert.Len(t, rule.AnalyzeFile(nonOwner), 1)

	bad := NewSQLConceptTableOwnerRule()
	err := bad.Configure(map[string]any{"concepts": []any{
		map[string]any{"name": "staff", "table": "staff", "files": []any{"["}},
	}})
	require.Error(t, err)
}

func TestSQLConceptTableOwner_WhereElsewhere(t *testing.T) {
	rule := NewSQLConceptTableOwnerRule()
	require.NoError(t, rule.Configure(map[string]any{"concepts": []any{
		map[string]any{
			"name": "staff", "table": "staff", "where": "name = 'internal'",
			"files": []any{"consts/staff.go"},
		},
	}}))
	ctx := rulestest.GoFile(t, "alerts/bot.go", `package alerts
func run() {
 db.Query("SELECT m.id FROM staff m JOIN groups g ON g.id = m.group_id AND g.name = 'internal'")
 db.Query("WITH intr AS (SELECT id FROM groups WHERE name = 'internal') SELECT m.id FROM staff m WHERE m.group_id IN (SELECT id FROM intr)")
}`)
	assert.Len(t, rule.AnalyzeFile(ctx), 2)
}

func fragmentConceptOwner(t *testing.T) *SQLConceptTableOwnerRule {
	t.Helper()
	rule := NewSQLConceptTableOwnerRule()
	require.NoError(t, rule.Configure(map[string]any{"concepts": []any{
		map[string]any{"name": "transaction", "table": "transactions", "where": "type = 'deposit'", "files": []any{"owner.go"}},
	}}))
	return rule
}

func TestSQLConceptTableOwner_ConcatenatedConstant(t *testing.T) {
	rule := fragmentConceptOwner(t)
	ctx := rulestest.GoFile(t, "reader.go", `package sample
const clause = " AND x"
const Q3 = `+"`"+`SELECT (SELECT t.id FROM transactions t WHERE t.user_id = gc.claimed_by AND t.type = 'deposit'`+"`"+` + clause + `+"`"+` ) FROM gift_codes gc`+"`"+`
`)
	assert.Len(t, rule.AnalyzeFile(ctx), 1)
}

func TestSQLConceptTableOwner_CallArgument(t *testing.T) {
	rule := fragmentConceptOwner(t)
	ctx := rulestest.GoFile(t, "reader.go", `package sample
import "context"
const clause = " AND x"
var Q7 = f(`+"`"+`SELECT t.id FROM transactions t WHERE t.user_id = $1 AND t.type = 'deposit'`+"`"+` + clause)
func run(ctx context.Context) {
 db.QueryContext(ctx, "SELECT id FROM transactions WHERE type = 'deposit'" + clause)
}
`)
	assert.Len(t, rule.AnalyzeFile(ctx), 2)
}

func TestSQLConceptTableOwner_InList(t *testing.T) {
	rule := fragmentConceptOwner(t)
	ctx := rulestest.GoFile(t, "reader.go", `package sample
const Q5 = `+"`"+`SELECT SUM(amount) FROM transactions WHERE type IN ('deposit') AND status = 'completed'`+"`"+`
const Q6 = `+"`"+`SELECT SUM(amount) FROM transactions WHERE type NOT IN ('deposit')`+"`"+`
`)
	assert.Len(t, rule.AnalyzeFile(ctx), 1)
}

func TestSQLConceptTableOwner_AggregateFilter(t *testing.T) {
	rule := fragmentConceptOwner(t)
	ctx := rulestest.GoFile(t, "reader.go", `package sample
const Q6 = `+"`"+`SELECT SUM(amount) FILTER (WHERE type = 'deposit') FROM transactions`+"`"+`
`)
	assert.Len(t, rule.AnalyzeFile(ctx), 1)
}

func TestSQLConceptTableOwner_PredicateScope(t *testing.T) {
	rule := fragmentConceptOwner(t)
	ctx := rulestest.GoFile(t, "reader.go", `package sample
const query = `+"`"+`WITH deposited AS (SELECT user_id FROM transactions WHERE type IN ('deposit')) SELECT id FROM transactions t WHERE t.user_id = `+"`"+` + membershipClause()
`)
	assert.Len(t, rule.AnalyzeFile(ctx), 1)
}

func TestSQLConceptTableOwner_FragmentsNegatives(t *testing.T) {
	rule := fragmentConceptOwner(t)
	ctx := rulestest.GoFile(t, "owner.go", `package sample
const clause = " AND x"
const Q3 = `+"`"+`SELECT (SELECT t.id FROM transactions t WHERE t.user_id = gc.claimed_by AND t.type = 'deposit'`+"`"+` + clause + `+"`"+` ) FROM gift_codes gc`+"`"+`
const Q5 = `+"`"+`SELECT SUM(amount) FROM transactions WHERE type IN ('deposit') AND status = 'completed'`+"`"+`
const Q6 = `+"`"+`SELECT SUM(amount) FILTER (WHERE type = 'deposit') FROM transactions`+"`"+`
var Q9 = f(`+"`"+`SELECT id FROM transactions WHERE type = 'deposit'`+"`"+` + clause)
func run() {
 db.QueryContext(nil, "SELECT id FROM transactions WHERE type = 'deposit'" + clause)
}
const Q7 = `+"`"+`SELECT id FROM transactions WHERE type = 'bonus'`+"`"+`
const Q8 = `+"`"+`SELECT id FROM transactions`+"`"+`
`)
	assert.Empty(t, rule.AnalyzeFile(ctx))

	outside := rulestest.GoFile(t, "reader.go", `package sample
const Q7 = `+"`"+`SELECT id FROM transactions WHERE type = 'bonus'`+"`"+`
const Q8 = `+"`"+`SELECT id FROM transactions`+"`"+`
`)
	assert.Empty(t, rule.AnalyzeFile(outside))
}

func TestSQLConceptTableOwner_RepositorySelect(t *testing.T) {
	rule := fragmentConceptOwner(t)
	ctx := rulestest.GoFile(t, "reader.go", `package sample
import "context"
type Repo struct{}
func (r *Repo) q(context.Context) queryer { return nil }
func (r *Repo) Links(ctx context.Context, userID string) {
	_ = r.q(ctx).SelectContext(ctx, &userID, `+"`"+`
		SELECT gc.id,
			(SELECT t.id FROM transactions t
			 WHERE t.user_id = gc.claimed_by AND t.type = 'deposit'`+"`"+`+clauses.Claim("t")+`+"`"+`
			   AND t.created_at BETWEEN gc.claimed_at - $2::interval AND gc.claimed_at
			 ORDER BY t.created_at LIMIT 1) AS claim_tx_id,
			ARRAY(SELECT d.id::text FROM transactions h
			      JOIN transactions d ON d.user_id = gc.claimed_by AND d.type = 'deposit'`+"`"+`+clauses.Claim("d")+`+"`"+`
			      WHERE h.user_id = $3 AND h.type = 'transfer'
			      ORDER BY d.created_at) AS top_up_ids
		FROM gift_codes gc
		WHERE gc.claimed_by = $1`+"`"+`, userID)
}
type queryer interface { SelectContext(context.Context, any, string, ...any) error }
var clauses struct { Claim func(string) string }
`)
	assert.Len(t, rule.AnalyzeFile(ctx), 2)
}

func TestSQLConceptTableOwner_JoinOnCondition(t *testing.T) {
	rule := fragmentConceptOwner(t)
	ctx := rulestest.GoFile(t, "reader.go", `package sample
const query = `+"`"+`SELECT d.id FROM transactions h JOIN transactions d ON d.type = 'deposit'`+"`"+`
`)
	assert.Len(t, rule.AnalyzeFile(ctx), 1)
}
