package dbrules

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/require"
)

func goFilterCopiesSQLFindings(t *testing.T, files map[string]string) []*core.Violation {
	t.Helper()
	root, _ := rulestest.Module(t, files)
	contexts, errs := core.NewWalker(root, core.DefaultConfig()).WalkSync()
	require.Empty(t, errs)
	rule := NewGoFilterCopiesSQLPredicateRule()
	projectFiles, ok := any(rule).(rules.ProjectFilesRule)
	require.True(t, ok)
	projectFiles.UseProjectFiles(contexts)
	var findings []*core.Violation
	for _, ctx := range contexts {
		findings = append(findings, rule.AnalyzeFile(ctx)...)
	}
	return findings
}

func TestGoFilterCopiesSQLPredicateComposedSource(t *testing.T) {
	findings := goFilterCopiesSQLFindings(t, map[string]string{
		"scope/predicates.go": `package scope
import "fmt"
const orderKind = "purchase"
const readyStatus = "ready"
const zeroAccountID = 0
func orderPrefix(alias string) string {
	prefix := ""
	if alias != "" { prefix = alias + "." }
	return prefix
}
func orderState(alias string) string {
	prefix := orderPrefix(alias)
	return fmt.Sprintf("%sstatus = '%s' AND %saccount_id <> %d", prefix, readyStatus, prefix, zeroAccountID)
}
func A(alias string) string { return orderPrefix(alias) + "type = '" + orderKind + "'" }
func B(alias string) string { return orderState(alias) }
func OwnCompletedOrderPredicate(alias string) string { return A(alias) + " AND " + B(alias) }
`,
		"report/filter.go": `package report
type order struct { Type, Status string; AccountID int }
func eligible(o order) bool { return o.Type == "purchase" && o.Status == "ready" && o.AccountID != 0 }
`,
	})
	require.Len(t, findings, 1)
	require.Contains(t, findings[0].Message, "OwnCompletedOrderPredicate")
}

func TestGoFilterCopiesSQLPredicate(t *testing.T) {
	findings := goFilterCopiesSQLFindings(t, map[string]string{
		"constants/scope.go": `package constants
func CompletedOrderPredicate(alias string) string { return alias + ".type = 'deposit' AND " + alias + ".status = 'completed'" }
func RealOrderClause(alias string) string { return " AND " + alias + ".network_id <> 0" }
func OwnCompletedOrderPredicate(alias string) string { return CompletedOrderPredicate(alias) + RealOrderClause(alias) }
`,
		"report/sum.go": `package report
type tx struct { Type, Status string; NetworkID int; Amount float64 }
func sum(txs []tx) (s float64) {
	for _, t := range txs {
		if t.Type == "deposit" && t.Status == "completed" && t.NetworkID != 0 { s += t.Amount }
	}
	return
}
`,
	})
	require.Len(t, findings, 1)
	require.Equal(t, 5, findings[0].Line)
	require.Equal(t, "This filter repeats the SQL predicate OwnCompletedOrderPredicate (constants/scope.go:4) in Go — filter in the query or derive the check from one definition", findings[0].Message)
}

func TestGoFilterCopiesSQLPredicateNegatives(t *testing.T) {
	findings := goFilterCopiesSQLFindings(t, map[string]string{
		"constants/scope.go": `package constants
func CompletedOrderPredicate(alias string) string { return alias + ".type = 'deposit' AND " + alias + ".status = 'completed'" }
`,
		"report/filter.go": `package report
func one(t tx) bool { return t.Status == "completed" }
func either(t tx) bool { return t.Type == "deposit" || t.Status == "completed" }
func mixed(a, b tx) bool { return a.Type == "deposit" && b.Status == "completed" }
func different(t tx) bool { return t.Type == "deposit" && t.Status == "pending" }
`,
		"report/filter_test.go": `package report
func testOnly(t tx) bool { return t.Type == "deposit" && t.Status == "completed" }
`,
	})
	require.Empty(t, findings)
	findings = goFilterCopiesSQLFindings(t, map[string]string{
		"report/filter.go": `package report
func local(t tx) bool { return t.Type == "deposit" && t.Status == "completed" }
`,
	})
	require.Empty(t, findings)
}

func TestGoFilterCopiesSQLPredicateDBTag(t *testing.T) {
	findings := goFilterCopiesSQLFindings(t, map[string]string{
		"constants/scope.go": `package constants
func EligiblePredicate(alias string) string { return alias + ".account_state = 'ready' AND " + alias + ".region_id <> 0" }
`,
		"report/filter.go": `package report
type item struct {
	State string ` + "`db:\"account_state\"`" + `
	RegionID int ` + "`db:\"region_id\"`" + `
}
func eligible(i item) bool { return i.State == "ready" && i.RegionID != 0 }
`,
	})
	require.Len(t, findings, 1)
}
