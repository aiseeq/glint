package dbrules

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/require"
)

func predicateCopyFindings(t *testing.T, files map[string]string) []*core.Violation {
	t.Helper()
	root, _ := rulestest.Module(t, files)
	contexts, errs := core.NewWalker(root, core.DefaultConfig()).WalkSync()
	require.Empty(t, errs)
	rule := NewSQLLiteralCopiesConstantRule()
	rule.UseProjectFiles(contexts)
	var findings []*core.Violation
	for _, ctx := range contexts {
		findings = append(findings, rule.AnalyzeFile(ctx)...)
	}
	return findings
}
func TestSQLLiteralCopiesConstant_PredicateCopied(t *testing.T) {
	findings := predicateCopyFindings(t, map[string]string{
		"consts/users.go": `package consts
const ExcludeArchivedClause = "status NOT IN ('deleted', 'system')"
`,
		"store/users.go": `package store
func count(db interface{ Query(string, ...any) }) {
 db.Query("SELECT count(*) FROM users u WHERE u.status NOT IN ('system','deleted') AND u.created_at > $1", 1)
}
`,
	})
	require.Len(t, findings, 1)
	require.Equal(t, 3, findings[0].Line)
}
func TestSQLLiteralCopiesConstant_PredicateParamConstant(t *testing.T) {
	findings := predicateCopyFindings(t, map[string]string{
		"consts/network.go": `package consts
const NetworkIDClause = "network_id <> 0"
const LocalNetworkID = 0
`,
		"store/network.go": `package store
import "project/consts"
func read(db interface{ Query(string, ...any) }) { db.Query("SELECT id FROM users WHERE network_id <> $1", consts.LocalNetworkID) }
`,
	})
	require.Len(t, findings, 1)
}
func TestSQLLiteralCopiesConstant_PredicateRedundant(t *testing.T) {
	findings := predicateCopyFindings(t, map[string]string{
		"consts/users.go": `package consts
const ExcludeArchivedClause = "status NOT IN ('deleted', 'system')"
`,
		"store/users.go": `package store
import "project/consts"
const query = "SELECT id FROM users WHERE status NOT IN ('system','deleted') AND " + consts.ExcludeArchivedClause
`,
	})
	require.Len(t, findings, 1)
	require.Equal(t, 3, findings[0].Line)
}

func TestSQLLiteralCopiesConstant_PredicateConstantUse(t *testing.T) {
	findings := predicateCopyFindings(t, map[string]string{
		"consts/users.go": `package consts
const ExcludeArchivedClause = "status NOT IN ('deleted', 'system')"
`,
		"store/users.go": `package store
import "project/consts"
const legit = "SELECT id FROM users WHERE " + consts.ExcludeArchivedClause
`,
	})
	require.Empty(t, findings)
}

func TestSQLLiteralCopiesConstant_PredicateParamAfterContext(t *testing.T) {
	findings := predicateCopyFindings(t, map[string]string{
		"consts/network.go": `package consts
const NetworkIDClause = "network_id <> 0"
const RegionIDClause = "region_id <> 0"
const LocalNetworkID = 0
`,
		"store/network.go": `package store
import "context"
import "project/consts"
func read(db interface{ QueryContext(context.Context, string, ...any) }) {
 db.QueryContext(context.Background(), "SELECT id FROM users WHERE network_id <> $1", consts.LocalNetworkID)
 db.QueryContext(context.Background(), "SELECT id FROM users WHERE network_id <> $1 AND region_id <> $10", 1, 2, 3, 4, 5, 6, 7, 8, 9, consts.LocalNetworkID)
}
`,
	})
	require.Len(t, findings, 2)
	require.Contains(t, findings[1].Message, "RegionIDClause")
}

func TestSQLLiteralCopiesConstant_PredicateSprintfFunc(t *testing.T) {
	findings := predicateCopyFindings(t, map[string]string{
		"consts/staff.go": `package consts
import "fmt"
func StaffExpr(col string) string { return fmt.Sprintf("EXISTS (SELECT 1 FROM staff s WHERE s.user_id = %s) AND kind = 'internal'", col) }
`,
		"store/staff.go": `package store
func read(db interface{ Query(string, ...any) }) {
 db.Query("SELECT id FROM users WHERE kind = 'internal'")
}
`,
	})
	require.Len(t, findings, 1)
}

func TestSQLLiteralCopiesConstant_PredicateBuilderNotSource(t *testing.T) {
	findings := predicateCopyFindings(t, map[string]string{
		"consts/builders.go": `package consts
import "fmt"
type Request struct { }
type filterResult struct { }
func buildFilterClauses(req Request) filterResult {
	cat := ""
	argIndex := 1
	cat = fmt.Sprintf(" AND u.status <> 'deleted' AND (u.client_number = $%d OR (TRUE%s))", argIndex, cat)
	return filterResult{}
}
`,
		"consts/users.go": `package consts
const MembersWhereA = "u.status <> 'deleted'"
`,
	})
	require.Empty(t, findings)
}

func TestSQLLiteralCopiesConstant_PredicateInsideExists(t *testing.T) {
	findings := predicateCopyFindings(t, map[string]string{
		"consts/users.go": `package consts
const HiddenClause = "EXISTS (SELECT 1 FROM users WHERE id = 1)"
`,
		"store/users.go": `package store
func read(db interface{ Query(string, ...any) }) {
 db.Query("SELECT id FROM users WHERE id = 1")
}
`,
	})
	require.Empty(t, findings)
}
func TestSQLLiteralCopiesConstant_PredicateNegatives(t *testing.T) {
	findings := predicateCopyFindings(t, map[string]string{
		"consts/users.go": `package consts
const ExcludeArchivedClause = "status NOT IN ('deleted', 'system')"
const Hidden = "EXISTS (SELECT 1 FROM users WHERE id = 1)"
const NoSuffix = "status = 'hidden'"
func local(db interface{ Query(string, ...any) }) {
 db.Query("SELECT id FROM users WHERE status NOT IN ('deleted', 'system')")
}
`,
		"consts/other.go": `package consts
const SameFile = "status NOT IN ('deleted', 'system')"
`,
		"store/users.go": `package store
func read(db interface{ Query(string, ...any) }) {
 db.Query("SELECT id FROM users WHERE id = $1", 1)
 db.Query("SELECT id FROM users WHERE id IN (SELECT id FROM users WHERE id = 1)")
 db.Query("UPDATE users SET status = $1 WHERE status <> 'deleted'", "x")
 db.Query("SELECT id FROM users WHERE status = 'hidden'")
}
`,
		"store/users_test.go": `package store
const query = "SELECT id FROM users WHERE status NOT IN ('deleted', 'system')"
`,
	})
	require.Empty(t, findings)
}

func TestSQLLiteralCopiesConstant_PredicateFullQueryNotSource(t *testing.T) {
	findings := predicateCopyFindings(t, map[string]string{
		"consts/reports.go": `package consts
const reportQuery = "SELECT id FROM orders WHERE status = 'completed'"
`,
		"store/reports.go": `package store
func list(db interface{ Query(string, ...any) }) {
 db.Query("SELECT id FROM orders WHERE status = 'completed'")
}
`,
	})
	require.Empty(t, findings)
}

func TestSQLLiteralCopiesConstant_PredicateClauseNames(t *testing.T) {
	findings := predicateCopyFindings(t, map[string]string{
		"consts/users.go": `package consts
const ExcludeRobotClauseA = " AND u.status <> 'system'"
const ActiveWhereU = "u.state = 'active'"
const Condition = "kind = 'x'"
`,
		"store/users.go": `package store
func read(db interface{ Query(string, ...any) }) {
 db.Query("SELECT id FROM users u WHERE u.status <> 'system' AND u.created_at > $1")
 db.Query("SELECT id FROM users u WHERE u.state = 'active'")
 db.Query("SELECT id FROM users WHERE kind = 'x'")
}
`,
	})
	require.Len(t, findings, 2)
}

func TestSQLLiteralCopiesConstant_PredicateNotInExpands(t *testing.T) {
	findings := predicateCopyFindings(t, map[string]string{
		"consts/users.go": `package consts
const LiveWhereA = "u.status <> 'deleted'"
const ExcludeRobotClauseA = " AND u.status <> 'system'"
const OnlyCrewClauseA = " AND u.staff = TRUE"
`,
		"store/users.go": `package store
import "project/consts"
func count(db interface{ Query(string, ...any) }) {
 db.Query("SELECT COUNT(*) FROM users u WHERE u.status NOT IN ('deleted', 'system')" + consts.OnlyCrewClauseA)
 db.Query("SELECT COUNT(*) FROM users u WHERE u.status NOT IN ('deleted', 'archived')" + consts.OnlyCrewClauseA)
}
`,
	})
	require.Len(t, findings, 1)
	require.Contains(t, findings[0].Message, "LiveWhereA")
	require.Contains(t, findings[0].Message, "ExcludeRobotClauseA")
}

func TestSQLLiteralCopiesConstant_PredicateConcatWithCall(t *testing.T) {
	findings := predicateCopyFindings(t, map[string]string{
		"consts/users.go": `package consts
const ExcludeStaffClauseU = " AND u.staff = TRUE"
const ExcludeRobotClauseA = " AND u.status <> 'system'"
const ExcludeArchivedClauseA = ExcludeStaffClauseU + ExcludeRobotClauseA
func MoneyClause(alias string) string { return " AND " + alias + ".amount > 0" }
`,
		"store/users.go": `package store
import "context"
import "project/consts"
func count(db interface{ QueryRow(context.Context, string, ...any) }) {
 db.QueryRow(context.Background(), "SELECT count(*) FROM users u WHERE u.created_at > $1 AND u.status != 'system'" + consts.MoneyClause("u") + consts.ExcludeArchivedClauseA, 1)
}
`,
	})
	require.Len(t, findings, 1)
	require.Contains(t, findings[0].Message, "ExcludeArchivedClauseA")
	require.Contains(t, findings[0].Message, "already in the constant")
}

func TestSQLLiteralCopiesConstant_PredicateUpdateGuard(t *testing.T) {
	findings := predicateCopyFindings(t, map[string]string{
		"consts/users.go": `package consts
const DeletedStatusClause = "u.status <> 'deleted'"
`,
		"store/users.go": `package store
func remove(db interface{ Exec(string, ...any) }) {
 db.Exec("UPDATE users SET status = 'deleted' WHERE id = $1 AND status != 'deleted'", 1)
}
`,
	})
	require.Empty(t, findings)
}
