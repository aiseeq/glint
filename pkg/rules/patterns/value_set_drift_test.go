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

// Not copies kept by hand: a constant whose last word is two words
// (StatusInProgress) belongs to its block's group, HTTP methods are the
// protocol's vocabulary, and a tool's configuration names the tool's options.
func TestValueSetDriftNotCopies(t *testing.T) {
	files := map[string]string{
		"backend/models/transfer.go": `package models

const (
	TransferStatusPending    = "pending"
	TransferStatusInProgress = "in_progress"
	TransferStatusCompleted  = "completed"
	TransferStatusFailed     = "failed"
	TransferStatusCancelled  = "cancelled"
)

type PaymentStatus string

const (
	PaymentStatusPending   PaymentStatus = "pending"
	PaymentStatusCompleted PaymentStatus = "completed"
	PaymentStatusFailed    PaymentStatus = "failed"
	PaymentStatusCancelled PaymentStatus = "cancelled"
	PaymentStatusRefunded  PaymentStatus = "refunded"
)
`,
		"backend/middleware/csrf.go": `package middleware

func safe(method string) bool {
	safeMethods := []string{"GET", "HEAD", "OPTIONS"}
	return slices.Contains(safeMethods, method)
}
`,
		"web/src/transfer.ts": `export const transferLabels = { pending: 'Waiting', in_progress: 'Moving', completed: 'Done', failed: 'Failed', cancelled: 'Cancelled' }
export const RETRY_METHODS = ['GET', 'HEAD', 'OPTIONS']
`,
		"web/app/jest.config.js": `module.exports = { moduleFileExtensions: ['ts', 'tsx', 'js', 'json'] }
`,
		"web/admin/jest.config.js": `module.exports = { moduleFileExtensions: ['ts', 'tsx', 'js', 'json'] }
`,
	}
	assert.Empty(t, foundLines(valueSetDriftFindings(t, files)))
}

// A switch the compiler holds to its union is not a copy kept by hand: with no
// default in a function that cannot return undefined, or with a default that
// assigns the value to never, a member added to the list breaks the build.
// A switch the compiler does not check is still a copy.
func TestValueSetDriftExhaustiveSwitch(t *testing.T) {
	files := map[string]string{
		"web/src/sort.ts": `const SORT_KEYS = ['value', 'income', 'opened'] as const
type SortKey = typeof SORT_KEYS[number]

export function sortValue(key: SortKey, row: { value: number; income: number }): number | null {
  switch (key) {
    case 'value': return row.value
    case 'income': return row.income
    case 'opened': return null
  }
}

export const sortLabel = (key: SortKey) => {
  switch (key) {
    case 'value': return 'Value'
    case 'income': return 'Income'
    case 'opened': return 'Opened'
    default: {
      const unreachable: never = key
      throw new Error(String(unreachable))
    }
  }
}

export function logSort(key: SortKey): void {
  switch (key) { // want value-set-drift
    case 'value': console.log(1); break
    case 'income': console.log(2); break
    case 'opened': console.log(3); break
  }
}
`,
	}
	assert.Equal(t, wantedLines(files, "value-set-drift"), foundLines(valueSetDriftFindings(t, files)))
}

// A screen lists payout method codes as literal options under labels of its
// own, and the code's label switch gives the same codes other meanings: an
// operator picks "Mobile Wallet" and saves the code for cash pickup. A select
// of another name sharing the codes is left alone.
func TestValueSetDriftTemplateOptionsAgainstLabelSwitch(t *testing.T) {
	found := foundLines(valueSetDriftFindings(t, map[string]string{
		"admin/pricing.go": `package admin

import "fmt"

func payoutMethodDesc(pm int) string {
	switch pm {
	case 1:
		return "Bank Transfer"
	case 2:
		return "Card Transfer"
	case 3:
		return "Cash Pickup"
	case 5:
		return "Wallet"
	default:
		return fmt.Sprintf("Method %d", pm)
	}
}
`,
		"admin/templates/channels.html": `<form>
<select name="payout_method" required>
  <option value="1" selected>1 — Bank Transfer</option>
  <option value="2">2 — Cash Pickup</option>
  <option value="3">3 — Mobile Wallet</option>
</select>
<select name="transfer_type">
  <option value="1">1 — B2B</option>
  <option value="2">2 — B2C</option>
  <option value="3">3 — C2C</option>
</select>
</form>
`,
	}))
	assert.Equal(t, []string{"admin/pricing.go:6"}, found)
}
