package patterns

import (
	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/sqlschema"
)

func init() {
	rules.Register(NewAdvisoryLockInSameStatementRule())
}

// AdvisoryLockInSameStatementRule detects a blocking advisory lock taken in
// a WITH query or a subquery of the statement whose read it is meant to
// serialize:
//
//	WITH locked AS (SELECT pg_advisory_xact_lock(42)),
//	     next AS (SELECT n FROM locked, generate_series(1, 999) n
//	              WHERE NOT EXISTS (SELECT 1 FROM orders WHERE number = n) LIMIT 1)
//	INSERT INTO orders (number) SELECT n FROM next
//
// The statement's snapshot is taken when it starts, before it waits for the
// lock: a number a neighbour took while this one waited still looks free,
// and both insert it. The lock serializes the read only when a statement of
// its own takes it first, in the same transaction.
type AdvisoryLockInSameStatementRule struct {
	*rules.BaseRule
}

// NewAdvisoryLockInSameStatementRule creates the rule
func NewAdvisoryLockInSameStatementRule() *AdvisoryLockInSameStatementRule {
	return &AdvisoryLockInSameStatementRule{BaseRule: rules.NewBaseRule(
		"advisory-lock-in-same-statement-as-guarded-read",
		"patterns",
		"Detects pg_advisory_xact_lock taken in a WITH query or a subquery of the statement that reads what it guards — the statement's snapshot predates the lock wait, so the read does not see a neighbour's write",
		core.SeverityHigh,
	)}
}

// AnalyzeFile reports the advisory locks of a file's SQL taken beside a read.
func (r *AdvisoryLockInSameStatementRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || !ctx.HasGoAST() {
		return nil
	}
	var violations []*core.Violation
	reported := make(map[int]bool)
	for _, literal := range sqlLiterals(ctx.GoAST) {
		for _, offset := range sqlschema.LockedReads(literal.text) {
			line := literal.lineAt(ctx, offset)
			if reported[line] || ctx.IsSuppressed(line, r.Name()) {
				continue
			}
			reported[line] = true
			violations = append(violations, sqlViolation(r.BaseRule, ctx, line,
				"The advisory lock is taken inside the statement that reads what it guards — the statement's snapshot is older than the lock wait, and rows a neighbour wrote meanwhile stay invisible to the read",
				"Take the lock by a statement of its own (SELECT pg_advisory_xact_lock(...)) in the same transaction before the read"))
		}
	}
	return violations
}
