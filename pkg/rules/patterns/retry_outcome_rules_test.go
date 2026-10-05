package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// uuidStub is the part of github.com/google/uuid the tests call.
const uuidStub = `package uuid

type UUID [16]byte

func New() UUID                 { return UUID{} }
func NewString() string         { return "" }
func (u UUID) String() string   { return "" }
`

// keyedFindings runs a typed rule over a module that has the uuid stub.
func keyedFindings(t *testing.T, rule rules.GoProjectRule, files map[string]string) []string {
	t.Helper()
	all := map[string]string{
		"go.mod": "module example.com/rulestest\n\ngo 1.24\n\n" +
			"require github.com/google/uuid v0.0.0\n\n" +
			"replace github.com/google/uuid => ./third_party/uuid\n",
		"third_party/uuid/go.mod":  "module github.com/google/uuid\n\ngo 1.24\n",
		"third_party/uuid/uuid.go": uuidStub,
	}
	for name, content := range files {
		all[name] = content
	}
	violations, err := rule.AnalyzeGoProject(rulestest.Project(t, all))
	require.NoError(t, err)
	return foundLines(violations)
}

// A reference minted fresh for every row of a batch differs on every attempt:
// a batch resumed after a crash sends the rows already sent under new
// references, and the provider pays them twice.
func TestRetryKeyMintedPerAttempt(t *testing.T) {
	assert.Equal(t, []string{"bulk/bulk.go:27", "bulk/bulk.go:68", "bulk/convert.go:25"}, keyedFindings(t, NewRetryKeyMintedPerAttemptRule(), map[string]string{
		"bulk/bulk.go": `package bulk

import (
	"fmt"

	"github.com/google/uuid"
)

type Row struct {
	Num    int
	Fields map[string]string
}

type Batch struct {
	ID   string
	Rows []Row
}

type Transfer struct {
	Reference string
	Amount    string
}

func buildTransfer(batch Batch, row Row) Transfer {
	ref := row.Fields["reference"]
	if ref == "" {
		ref = fmt.Sprintf("BULK-%s-%d", uuid.New().String()[:8], row.Num)
	}
	return Transfer{Reference: ref, Amount: row.Fields["amount"]}
}

func executeRow(batch Batch, row Row) Transfer {
	return buildTransfer(batch, row)
}

func Execute(batch Batch) []Transfer {
	var out []Transfer
	for _, row := range batch.Rows {
		out = append(out, executeRow(batch, row))
	}
	return out
}

// stableTransfer derives the reference from the batch and the row.
func stableTransfer(batch Batch, row Row) Transfer {
	return Transfer{Reference: fmt.Sprintf("BULK-%s-%d", batch.ID, row.Num)}
}

func ExecuteStable(batch Batch) []Transfer {
	var out []Transfer
	for _, row := range batch.Rows {
		out = append(out, stableTransfer(batch, row))
	}
	return out
}

// NewBatch mints the identity of a new batch once, outside any loop.
func NewBatch(rows []Row) Batch {
	return Batch{ID: uuid.NewString(), Rows: rows}
}

// ConvertSheet reads the rows by index: the reference still goes out with
// each row.
func ConvertSheet(cells [][]string) []Result {
	var out []Result
	for i := 1; i < len(cells); i++ {
		row := Row{Num: i}
		out = append(out, Mutate(row, uuid.New().String(), 2026))
	}
	return out
}

type Approval struct {
	ID     string
	Status string
}

// approve mints a reference only for an approval still waiting: a repeat
// finds the status moved on and stops before the reference.
func approve(a Approval) (Transfer, bool) {
	if a.Status != "WAITING" {
		return Transfer{}, false
	}
	ref := "MOCK-" + uuid.NewString()
	return Transfer{Reference: ref}, true
}

func ApproveAll(lines []Row, approvals []Approval) {
	for _, line := range lines {
		_, _ = approve(approvals[line.Num])
	}
}

// Split creates new transfers, one per amount: each new entity gets its own
// reference once, there is no stored item to send again.
func Split(amounts []string) []Transfer {
	var out []Transfer
	for _, amount := range amounts {
		out = append(out, Transfer{Reference: "MANUAL-" + uuid.NewString(), Amount: amount})
	}
	return out
}

// Each row of a new import gets its own record id: an id, not a reference.
func Records(rows []Row) []string {
	var ids []string
	for range rows {
		ids = append(ids, uuid.NewString())
	}
	return ids
}
`,
		"bulk/convert.go": `package bulk

import (
	"github.com/google/uuid"
)

type Result struct{ Ref string }

func Mutate(row Row, txnRef string, year int) Result { return Result{Ref: txnRef} }

func Convert(rows []Row) []Result {
	var out []Result
	for _, row := range rows {
		if row.Num == 0 {
			continue
		}
		out = append(out, Mutate(row, "", 2026))
	}
	return out
}

func ConvertMinted(rows []Row) []Result {
	var out []Result
	for _, row := range rows {
		out = append(out, Mutate(row, uuid.New().String(), 2026))
	}
	return out
}
`,
	}))
}

// A job that picked rows by status and then changes each by id alone acts on
// a row that moved on since the pick: a payout completed meanwhile is
// cancelled.
func TestStaleBatchRowActedWithoutStatusRecheck(t *testing.T) {
	assert.Equal(t, []string{"jobs/timeout.go:46"}, typedFuncFindings(t, NewStaleBatchRowActedWithoutStatusRecheckRule(), map[string]string{
		"jobs/timeout.go": `package jobs

import (
	"context"
	"time"
)

type Status string

const StatusSent Status = "SENT"

type Txn struct {
	ID      string
	Status  Status
	Version int
}

type Repo struct{}

func (r *Repo) GetTimedOutSent(ctx context.Context, age time.Duration) ([]*Txn, error) { return nil, nil }

type Canceller struct{}

func (c *Canceller) CancelExpired(ctx context.Context, id string) error { return nil }
func (c *Canceller) CancelIfStatus(ctx context.Context, id string, status Status) error {
	return nil
}
func (c *Canceller) CancelVersion(ctx context.Context, id string, version int) error { return nil }

type Job struct {
	repo      *Repo
	canceller *Canceller
}

func (j *Job) Run(ctx context.Context) {
	txs, err := j.repo.GetTimedOutSent(ctx, time.Hour)
	if err != nil {
		return
	}
	for _, tx := range txs {
		j.processOne(ctx, tx)
	}
}

func (j *Job) processOne(ctx context.Context, tx *Txn) {
	_ = j.canceller.CancelExpired(ctx, tx.ID)
}

func (j *Job) RunChecked(ctx context.Context) {
	txs, err := j.repo.GetTimedOutSent(ctx, time.Hour)
	if err != nil {
		return
	}
	for _, tx := range txs {
		_ = j.canceller.CancelIfStatus(ctx, tx.ID, StatusSent)
		_ = j.canceller.CancelVersion(ctx, tx.ID, tx.Version)
	}
}
`,
	}))
}

// An idempotency key built from the request alone collides across callers:
// two partners sending the same payment id share one transaction, and the
// second gets the first one's payment back.
func TestIdempotencyKeyNotScopedToCaller(t *testing.T) {
	assert.Equal(t, []string{"api/create.go:47"}, typedFuncFindings(t, NewIdempotencyKeyNotScopedToCallerRule(), map[string]string{
		"api/create.go": `package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

type Partner struct{ ID string }

type ctxKey struct{}

func authenticatedPartner(ctx context.Context) (*Partner, error) {
	p, _ := ctx.Value(ctxKey{}).(*Partner)
	return p, nil
}

type Request struct {
	ProjectID int
	PaymentID string
}

type Transaction struct {
	IdempotencyKey string
	PaymentID      string
}

type Handler struct{}

func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	partner, err := authenticatedPartner(r.Context())
	if err != nil {
		return
	}
	var req Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return
	}
	_ = partner
	tx := h.toTransaction(req)
	_ = tx
}

func (h *Handler) toTransaction(req Request) *Transaction {
	return &Transaction{
		IdempotencyKey: fmt.Sprintf("ext:%d:%s", req.ProjectID, req.PaymentID),
		PaymentID:      req.PaymentID,
	}
}

func (h *Handler) CreateScoped(w http.ResponseWriter, r *http.Request) {
	partner, err := authenticatedPartner(r.Context())
	if err != nil {
		return
	}
	var req Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return
	}
	tx := h.toScopedTransaction(req, partner.ID)
	_ = tx
}

func (h *Handler) toScopedTransaction(req Request, partnerID string) *Transaction {
	return &Transaction{IdempotencyKey: fmt.Sprintf("ext:%s:%d:%s", partnerID, req.ProjectID, req.PaymentID)}
}

// An internal job has no caller to scope by.
func ImportKey(req Request) string {
	key := fmt.Sprintf("import:%s", req.PaymentID)
	return key
}
`,
	}))
}

// A delivery that answers every non-2xx with the same error is retried on a
// 404 as on a 503: the recipient that refuses the request is hammered for the
// whole schedule and the delivery never succeeds.
func TestOutboundDeliveryRetriesPermanent4xx(t *testing.T) {
	assert.Equal(t, []string{"hooks/worker.go:32"}, typedFuncFindings(t, NewOutboundDeliveryRetriesPermanent4xxRule(), map[string]string{
		"hooks/worker.go": `package hooks

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"
)

type Item struct {
	ID       string
	URL      string
	Attempts int
}

type Worker struct {
	client    *http.Client
	markRetry func(ctx context.Context, id string, next time.Time) error
}

func (w *Worker) deliver(ctx context.Context, item Item) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, item.URL, nil)
	resp, err := w.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	return fmt.Errorf("http status %d", resp.StatusCode)
}

func (w *Worker) handleFailure(ctx context.Context, item Item, err error) error {
	return w.markRetry(ctx, item.ID, time.Now().Add(time.Minute))
}

func (w *Worker) Process(ctx context.Context, item Item) {
	if err := w.deliver(ctx, item); err != nil {
		_ = w.handleFailure(ctx, item, err)
	}
}

var errRejected = errors.New("recipient rejected delivery")

func (w *Worker) deliverClassified(ctx context.Context, item Item) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, item.URL, nil)
	resp, err := w.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	if resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != http.StatusTooManyRequests {
		return fmt.Errorf("%w: status %d", errRejected, resp.StatusCode)
	}
	return fmt.Errorf("http status %d", resp.StatusCode)
}

func (w *Worker) ProcessClassified(ctx context.Context, item Item) {
	if err := w.deliverClassified(ctx, item); err != nil {
		_ = w.handleFailure(ctx, item, err)
	}
}

// fetch is not retried: its failure goes to the caller.
func (w *Worker) fetch(ctx context.Context, url string) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := w.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("http status %d", resp.StatusCode)
	}
	return nil
}

func (w *Worker) Fetch(ctx context.Context) error {
	if err := w.fetch(ctx, "https://example.com"); err != nil {
		return err
	}
	return nil
}
`,
	}))
}

// A check that refuses an entity after the insert that committed it leaves
// the refused row behind: the caller gets a conflict, the table keeps an
// empty transaction that shows up in reports.
func TestValidationAfterCommittedInsert(t *testing.T) {
	assert.Equal(t, []string{"txn/create.go:31"}, typedFuncFindings(t, NewValidationAfterCommittedInsertRule(), map[string]string{
		"txn/create.go": `package txn

import (
	"context"
	"errors"
)

type Transaction struct {
	ID        string
	Reference string
}

type Repo struct{}

func (r *Repo) CreateOrGet(ctx context.Context, tx *Transaction) (bool, error) { return true, nil }
func (r *Repo) Delete(ctx context.Context, id string) error                      { return nil }
func (r *Repo) ReferenceTaken(ctx context.Context, ref, id string) (bool, error) { return false, nil }

func ensureReferenceIsFree(ctx context.Context, repo *Repo, tx *Transaction) error {
	taken, err := repo.ReferenceTaken(ctx, tx.Reference, tx.ID)
	if err != nil || taken {
		return errors.New("reference taken")
	}
	return nil
}

func Create(ctx context.Context, repo *Repo, tx *Transaction) error {
	if _, err := repo.CreateOrGet(ctx, tx); err != nil {
		return err
	}
	if err := ensureReferenceIsFree(ctx, repo, tx); err != nil {
		return err
	}
	return nil
}

func CreateChecked(ctx context.Context, repo *Repo, tx *Transaction) error {
	if err := ensureReferenceIsFree(ctx, repo, tx); err != nil {
		return err
	}
	_, err := repo.CreateOrGet(ctx, tx)
	return err
}

func CreateCompensated(ctx context.Context, repo *Repo, tx *Transaction) error {
	if _, err := repo.CreateOrGet(ctx, tx); err != nil {
		return err
	}
	if err := ensureReferenceIsFree(ctx, repo, tx); err != nil {
		_ = repo.Delete(ctx, tx.ID)
		return err
	}
	return nil
}
`,
	}))
}
