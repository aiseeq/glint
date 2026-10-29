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
