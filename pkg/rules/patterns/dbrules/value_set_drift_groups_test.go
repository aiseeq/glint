package dbrules

import (
	"testing"

	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patterntest"
	"github.com/stretchr/testify/assert"
)

func TestValueSetDriftTSListCopiesGoCaseClause(t *testing.T) {
	files := map[string]string{
		"backend/models/withdrawal.go": `package models

type WithdrawalStatus string

const (
	WithdrawalStatusPending WithdrawalStatus = "pending"
	WithdrawalStatusApproved WithdrawalStatus = "approved"
	WithdrawalStatusRejected WithdrawalStatus = "rejected"
	WithdrawalStatusCancelled WithdrawalStatus = "cancelled"
	WithdrawalStatusProcessing WithdrawalStatus = "processing"
	WithdrawalStatusCompleted WithdrawalStatus = "completed"
	WithdrawalStatusFailed WithdrawalStatus = "failed"
)

func bucket(status WithdrawalStatus) {
	switch status {
	case WithdrawalStatusFailed, WithdrawalStatusRejected, WithdrawalStatusCancelled:
	}
}
`,
		"frontend/withdrawals.ts": `export const UNSUCCESSFUL_STATUSES = ['rejected', 'failed', 'cancelled']
`,
	}
	found := valueSetDriftFindings(t, files)
	assert.Equal(t, []string{"frontend/withdrawals.ts:1"}, patterntest.FoundLines(found))
	assert.Contains(t, found[0].Message, "backend/models/withdrawal.go:")
}

func TestValueSetDriftTSListCopiesGoListVar(t *testing.T) {
	files := map[string]string{
		"backend/models/statuses.go": `package models

type WithdrawalStatus string

const (
	WithdrawalStatusPending WithdrawalStatus = "pending"
	WithdrawalStatusApproved WithdrawalStatus = "approved"
	WithdrawalStatusProcessing WithdrawalStatus = "processing"
)

var OpenWithdrawalStatuses = []string{WithdrawalStatusPending, WithdrawalStatusApproved, WithdrawalStatusProcessing}

const (
	AdminActionPending = "admin_pending"
	AdminActionApproved = "admin_approved"
)

var AdminActionStatuses = []string{AdminActionPending, AdminActionApproved}

type QueueStatus string

const (
	QueueStatusQueued QueueStatus = "queued"
	QueueStatusRunning QueueStatus = "running"
	QueueStatusFinished QueueStatus = "finished"
)

func jobState(QueueStatus, QueueStatus, QueueStatus) {}

func useQueue() { jobState(QueueStatusQueued, QueueStatusRunning, QueueStatusFinished) }
`,
		"frontend/statuses.ts": `export const OPEN = new Set(['pending', 'approved', 'processing'])
export const ADMIN_ACTIONS = ['admin_pending', 'admin_approved']
export const QUEUE = ['queued', 'running', 'finished']
`,
	}
	found := valueSetDriftFindings(t, files)
	assert.Equal(t, []string{"frontend/statuses.ts:1", "frontend/statuses.ts:2", "frontend/statuses.ts:3"}, patterntest.FoundLines(found))
}

func TestValueSetDriftTSSpreadList(t *testing.T) {
	files := map[string]string{
		"backend/models/statuses.go": `package models

type WithdrawalStatus string

const (
	WithdrawalStatusCompleted WithdrawalStatus = "completed"
	WithdrawalStatusFailed WithdrawalStatus = "failed"
	WithdrawalStatusRejected WithdrawalStatus = "rejected"
	WithdrawalStatusCancelled WithdrawalStatus = "cancelled"
)

func bucket(status WithdrawalStatus) {
	switch status {
	case WithdrawalStatusCompleted, WithdrawalStatusFailed, WithdrawalStatusRejected, WithdrawalStatusCancelled:
	}
}
`,
		"frontend/statuses.ts": `const UNSUCCESSFUL_STATUSES = ['failed', 'rejected', 'cancelled']
export const FINAL = new Set<WithdrawalStatus>(['completed', ...UNSUCCESSFUL_STATUSES])
export const UNKNOWN = new Set(['completed', ...MISSING_STATUSES])
`,
	}
	found := valueSetDriftFindings(t, files)
	assert.Equal(t, []string{"frontend/statuses.ts:2"}, patterntest.FoundLines(found))
}

func TestValueSetDriftTSListNotGroupCopy(t *testing.T) {
	files := map[string]string{
		"backend/models/statuses.go": `package models

type FlowStatus string

const (
	FlowStatusPending FlowStatus = "pending"
	FlowStatusApproved FlowStatus = "approved"
	FlowStatusProcessing FlowStatus = "processing"
	FlowStatusCompleted FlowStatus = "completed"
)

var FlowStatuses = []FlowStatus{FlowStatusPending, FlowStatusApproved, FlowStatusProcessing, FlowStatusCompleted}

func classify(status FlowStatus) {
	switch status {
	case FlowStatusPending, FlowStatusApproved:
	}
}

type OtherStatus string

const (
	OtherStatusRejected OtherStatus = "rejected"
	OtherStatusFailed OtherStatus = "failed"
)
`,
		"backend/models/statuses_test.go": `package models

const (
	TestStatusA = "test_a"
	TestStatusB = "test_b"
	TestStatusC = "test_c"
)

var TestStatuses = []string{TestStatusA, TestStatusB, TestStatusC}
`,
		"frontend/statuses.ts": `export const PART = ['pending', 'approved', 'processing']
export const WIDE = ['pending', 'approved', 'processing', 'completed', 'failed']
export const MIXED = ['pending', 'approved', 'rejected']
export const SAME_TWO = ['pending', 'approved']
`,
		"frontend/statuses.test.ts": `export const COPIED = ['test_a', 'test_b', 'test_c']
`,
	}
	found := valueSetDriftFindings(t, files)
	for _, finding := range found {
		assert.NotContains(t, finding.Message, "Go group")
	}
}

func TestValueSetDriftTSListKeepsDriftFinding(t *testing.T) {
	files := map[string]string{
		"backend/models/statuses.go": `package models

const (
	StatusPending = "pending"
	StatusApproved = "approved"
	StatusProcessing = "processing"
	StatusCompleted = "completed"
	StatusFailed = "failed"
)

var WorkflowStatuses = []string{StatusPending, StatusApproved, StatusProcessing, StatusCompleted, StatusFailed}
`,
		"frontend/statuses.ts": `export const ACTIVE = ['pending', 'approved', 'processing', 'completed']
`,
	}
	found := valueSetDriftFindings(t, files)
	assert.Equal(t, []string{"frontend/statuses.ts:1"}, patterntest.FoundLines(found))
	assert.Contains(t, found[0].Message, "Set of values copies")
	assert.NotContains(t, found[0].Message, "Go group")
}

func TestValueSetDriftSQLListCopiesGoClassifierCase(t *testing.T) {
	files := map[string]string{
		"models/funding.go": `package models

type FundingStatus string

const (
	FundingStatusAwaitingPayment FundingStatus = "awaiting_payment"
	FundingStatusUnderpaid FundingStatus = "underpaid"
	FundingStatusPaid FundingStatus = "paid"
	FundingStatusFailed FundingStatus = "failed"
	GroupPending = "pending"
)

func FundingStatusGroup(s FundingStatus) string {
	switch s {
	case FundingStatusAwaitingPayment, FundingStatusUnderpaid:
		return GroupPending
	case FundingStatusFailed:
		return "failed"
	}
	return "unknown"
}
`,
		"repository/funding.go": "package repository\nconst q = `SELECT COUNT(*) FROM funding_orders WHERE status IN ('awaiting_payment', 'underpaid')`\n",
	}
	found := valueSetDriftFindings(t, files)
	assert.Equal(t, []string{"repository/funding.go:2"}, patterntest.FoundLines(found))
	assert.Contains(t, found[0].Message, "Go group FundingStatus")
	assert.Contains(t, found[0].Message, "models/funding.go:")
	assert.Contains(t, found[0].Suggestion, "ANY($1)")
}

func TestValueSetDriftSQLListCopiesGoListVar(t *testing.T) {
	files := map[string]string{
		"models/statuses.go": `package models

const (
	StatusOpen = "a"
	StatusQueued = "b"
	StatusRetrying = "c"
)

var OpenStatuses = []string{StatusOpen, StatusQueued, StatusRetrying}
`,
		"repository/statuses.go": "package repository\nconst q = `SELECT * FROM jobs WHERE status IN ('a','b','c')`\n",
	}
	found := valueSetDriftFindings(t, files)
	assert.Equal(t, []string{"repository/statuses.go:2"}, patterntest.FoundLines(found))
	assert.Contains(t, found[0].Message, "Go group OpenStatuses")
}

func TestValueSetDriftSQLListConcatenated(t *testing.T) {
	files := map[string]string{
		"models/funding.go": `package models

type FundingStatus string

const (
	FundingStatusAwaitingPayment FundingStatus = "awaiting_payment"
	FundingStatusUnderpaid FundingStatus = "underpaid"
	FundingStatusPaid FundingStatus = "paid"
	FundingStatusFailed FundingStatus = "failed"
	GroupPending = "pending"
)

func FundingStatusGroup(s FundingStatus) string {
	switch s {
	case FundingStatusAwaitingPayment, FundingStatusUnderpaid:
		return GroupPending
	case FundingStatusFailed:
		return "failed"
	}
	return "unknown"
}
`,
		"repository/funding.go": `package repository

const batchClause = "kind = 'campaign'"

func stats() {
	query := "WITH codes AS (SELECT c.status FROM gift_codes c WHERE c." + batchClause + ") " +
		"SELECT (SELECT COUNT(*) FROM codes) AS total, " +
		"(SELECT COUNT(*) FROM funding_orders WHERE status IN ('awaiting_payment', 'underpaid')) AS pending_funding"
	_ = query
}
`,
	}
	found := valueSetDriftFindings(t, files)
	assert.Equal(t, []string{"repository/funding.go:8"}, patterntest.FoundLines(found))
	assert.Contains(t, found[0].Message, "Go group FundingStatus")
}

func TestValueSetDriftSQLConstantPredicateCopiesGoGroup(t *testing.T) {
	files := map[string]string{
		"models/funding.go": `package models

type FundingStatus string

const (
	FundingStatusAwaitingPayment FundingStatus = "awaiting_payment"
	FundingStatusUnderpaid FundingStatus = "underpaid"
	FundingStatusPaid FundingStatus = "paid"
	FundingStatusFailed FundingStatus = "failed"
)

func FundingStatusGroup(s FundingStatus) string {
	switch s {
	case FundingStatusAwaitingPayment, FundingStatusUnderpaid:
		return "pending"
	case FundingStatusFailed:
		return "failed"
	}
	return "unknown"
}
`,
		"repository/funding.go": `package repository

const pendingPredicate = "IN ('awaiting_payment', 'underpaid')"

func count() {
	query := "SELECT COUNT(*) FROM funding_orders WHERE status " + pendingPredicate
	_ = query
}
`,
	}
	found := valueSetDriftFindings(t, files)
	assert.Equal(t, []string{"repository/funding.go:3"}, patterntest.FoundLines(found))
	assert.Contains(t, found[0].Message, "Go group FundingStatus")
	assert.NotContains(t, found[0].Message, "written by hand")
}

func TestValueSetDriftSQLListNotGroupCopy(t *testing.T) {
	files := map[string]string{
		"models/statuses.go": `package models

const (
	StatusA = "a"
	StatusB = "b"
	StatusC = "c"
)

var Statuses = []string{StatusA, StatusB, StatusC}

func classify(status string) string {
	switch status {
	case StatusA, StatusB:
		return status
	}
	return "unknown"
}
`,
		"repository/subset.go":        "package repository\nconst q = `SELECT * FROM jobs WHERE status IN ('a','b')`\n",
		"repository/wide.go":          "package repository\nconst q = `SELECT * FROM jobs WHERE status IN ('a','b','c','d')`\n",
		"repository/statuses_test.go": "package repository\nconst q = `SELECT * FROM jobs WHERE status IN ('a','b','c')`\n",
		"migrations/001_statuses.sql": "SELECT * FROM jobs WHERE status IN ('a','b','c');\n",
	}
	for _, finding := range valueSetDriftFindings(t, files) {
		assert.NotContains(t, finding.Message, "Go group")
	}
}

func TestValueSetDriftTSListGoLaterPath(t *testing.T) {
	files := map[string]string{
		"server/models/statuses.go": `package models

const (
	StatusPending = "pending"
	StatusApproved = "approved"
	StatusProcessing = "processing"
)

var WorkflowStatuses = []string{StatusPending, StatusApproved, StatusProcessing}
`,
		"admin/lib/statuses.ts": `export const ACTIVE = ['pending', 'approved', 'processing']
`,
	}
	found := valueSetDriftFindings(t, files)
	assert.Equal(t, []string{"admin/lib/statuses.ts:1"}, patterntest.FoundLines(found))
	assert.Contains(t, found[0].Message, "server/models/statuses.go:")
}
