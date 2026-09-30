package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

func valueSetDriftFindings(t *testing.T, files map[string]string) []*core.Violation {
	t.Helper()
	root, _ := rulestest.Module(t, files)
	contexts, errs := core.NewWalker(root, core.DefaultConfig()).WalkSync()
	require.Empty(t, errs)
	rule := NewValueSetDriftRule()
	rule.UseProjectFiles(contexts)
	var violations []*core.Violation
	for _, ctx := range contexts {
		violations = append(violations, rule.AnalyzeFile(ctx)...)
	}
	return violations
}

// A set of values kept by hand in two places: one copy gets the new member,
// the other does not, and a status the backend sends has no badge, a network
// maps to another id, a strategy fails validation.
func TestValueSetDrift(t *testing.T) {
	files := map[string]string{
		"backend/models/withdrawal.go": `package models

type WithdrawalStatus string

const (
	WithdrawalStatusPending    WithdrawalStatus = "pending"
	WithdrawalStatusApproved   WithdrawalStatus = "approved"
	WithdrawalStatusProcessing WithdrawalStatus = "processing"
	WithdrawalStatusCompleted  WithdrawalStatus = "completed"
	WithdrawalStatusRejected   WithdrawalStatus = "rejected"
	WithdrawalStatusFailed     WithdrawalStatus = "failed"
)

type LedgerStatus string

const (
	LedgerStatusPending   LedgerStatus = "pending"
	LedgerStatusCompleted LedgerStatus = "completed"
	LedgerStatusFailed    LedgerStatus = "failed"
	LedgerStatusRefunded  LedgerStatus = "refunded"
)
`,
		"backend/validation/strategy.go": `package validation

func Forbidden() map[string]any {
	return map[string]any{"success": false, "error": "forbidden", "permission": "admin"}
}

func ValidStrategy(s string) bool {
	valid := map[string]bool{"starter": true, "growth": true, "premium": true} // want value-set-drift
	return valid[s]
}

func IsDollar(currency string) bool {
	switch currency { // want value-set-drift
	case "USD", "USDC", "USDT":
		return true
	}
	return false
}

const (
	TransferStatusPending   = "pending"
	TransferStatusSent      = "sent"
	TransferStatusReturned  = "returned"
	TransferStatusHeld      = "held"
	TransferKindInternal    = "internal"
)

// Terminal statuses: a deliberate part of the set.
var terminal = []string{"completed", "rejected", "failed"}
`,
		"backend/routing/labels.go": `package routing

var strategyLabels = map[string]string{
	"starter": "Low risk",
	"growth":     "Medium risk",
	"premium":   "High risk",
}

func strategyLabel(s string) string {
	switch s {
	case "starter":
		return "Low risk"
	case "growth":
		return "Medium risk"
	case "premium":
		return "High risk"
	}
	return s
}

func response(ok bool) map[string]any {
	return map[string]any{"success": ok, "error": nil, "permission": nil}
}

var chainTokens = map[string][]string{
	"ethereum": {"USDC", "USDT", "DAI"},
	"base":     {"USDC", "USDT", "DAI"},
}

func dollarCurrencies() []string {
	return []string{"USD", "USDC", "USDT"}
}
`,
		"web/src/lib/status.ts": `export const WITHDRAWAL_STATUSES = ['pending', 'processing', 'completed', 'rejected'] // want value-set-drift

export type LedgerStatus = 'pending' | 'confirmed' | 'failed' | 'refunded' // want value-set-drift

export const TRANSFER_STATES = ['pending', 'sent', 'returned', 'held', 'lost'] // want value-set-drift
`,
		"web/src/components/Badge.tsx": `export function Badge({ status }: { status: string }) {
  const styles = { // want value-set-drift
    pending: 'bg-yellow',
    approved: 'bg-green',
    processing: 'bg-blue',
    rejected: 'bg-red',
    completed: 'bg-gray',
  }
  return <span className={styles[status as keyof typeof styles]} />
}
`,
		"web/src/components/Labels.tsx": `export const withdrawalLabels: Record<string, string> = { pending: 'P', approved: 'A', processing: 'R', completed: 'C', rejected: 'X', failed: 'F' }
export const withdrawalColors: Record<string, string> = { pending: 'gray', approved: 'teal', processing: 'blue', completed: 'green', rejected: 'red', failed: 'red' }
export function levelName(level: string) {
  switch (level) {
    case 'debug': return 'D'
    case 'warn': return 'W'
    case 'error': return 'E'
    default: return 'I'
  }
}
export const LEVELS = ['debug', 'info', 'warn', 'error']
type Size = 'sm' | 'md' | 'lg' | 'xl'
const buttonSizes: Record<Size, string> = { sm: 'px-1', md: 'px-2', lg: 'px-3', xl: 'px-4' }
const modalSizes = { sm: 'w-64', md: 'w-96', lg: 'w-128' }
`,
		"web/src/components/Badge.test.tsx": `const statuses = ['pending', 'processing', 'completed', 'rejected', 'approved', 'unknown']
`,
	}
	assert.Equal(t, wantedLines(files, "value-set-drift"), foundLines(valueSetDriftFindings(t, files)))
}
