package gorules

import (
	"testing"

	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patterntest"
	"github.com/stretchr/testify/assert"
)

// The webhook stores the provider's raw status next to the mapped one; the
// poller maps the same response and stores only the mapped status, so a
// transaction the poller moved keeps a stale provider status.
func TestAlternateSyncPathDropsFields(t *testing.T) {
	assert.Equal(t, []string{"poll/poller.go:23"}, patterntest.TypedFuncFindings(t, NewAlternateSyncPathDropsFieldsRule(), map[string]string{
		"domain/status.go": `package domain

type Status string

func MapProviderStatus(status, subStatus string) Status { return Status(status + subStatus) }

func Normalize(code string) string { return code }
`,
		"store/repo.go": `package store

import "example.com/rulestest/domain"

type Repo struct{}

func (r *Repo) UpdateStatus(id string, status domain.Status) error { return nil }

func (r *Repo) UpdateFromCallback(id string, status domain.Status, raw, subStatus, errorCode string) error {
	return nil
}

func (r *Repo) SaveCode(id, code string) error { return nil }
`,
		"hook/handler.go": `package hook

import (
	"example.com/rulestest/domain"
	"example.com/rulestest/store"
)

type Payload struct{ Status, SubStatus, ErrorCode string }

type Handler struct{ repo *store.Repo }

func (h *Handler) Apply(id string, payload Payload) error {
	status := domain.MapProviderStatus(payload.Status, payload.SubStatus)
	return h.repo.UpdateFromCallback(id, status, payload.Status, payload.SubStatus, payload.ErrorCode)
}
`,
		"poll/poller.go": `package poll

import (
	"example.com/rulestest/domain"
	"example.com/rulestest/store"
)

type Response struct{ Status, SubStatus, ErrorCode string }

type Client interface{ Status(ref string) (*Response, error) }

type Poller struct {
	client Client
	repo   *store.Repo
}

func (p *Poller) Check(id, ref string) error {
	resp, err := p.client.Status(ref)
	if err != nil {
		return err
	}
	status := domain.MapProviderStatus(resp.Status, resp.SubStatus)
	return p.repo.UpdateStatus(id, status)
}

// Recheck stores the raw status too: both paths keep the same columns.
func (p *Poller) Recheck(id, ref string) error {
	resp, err := p.client.Status(ref)
	if err != nil {
		return err
	}
	status := domain.MapProviderStatus(resp.Status, resp.SubStatus)
	return p.repo.UpdateFromCallback(id, status, resp.Status, resp.SubStatus, resp.ErrorCode)
}

// Code maps a value no other path stores raw.
func (p *Poller) Code(id string, resp Response) error {
	code := domain.Normalize(resp.ErrorCode)
	return p.repo.SaveCode(id, code)
}
`,
	}))
}

// Two mappers fill the same entity from the same keys: the bulk one misses
// three fields the form one reads, and bulk uploads lose them.
func TestParallelKeyToFieldMappingDrifts(t *testing.T) {
	assert.Equal(t, []string{"admin/bulk.go:5"}, patterntest.TypedFuncFindings(t, NewParallelKeyToFieldMappingDriftsRule(), map[string]string{
		"domain/order.go": `package domain

type Order struct {
	FirstName, LastName, Country, City, Address, ZipCode, Phone, Email, Note string
}
`,
		"admin/form.go": `package admin

import (
	"net/http"
	"strings"

	"example.com/rulestest/domain"
)

func mapForm(r *http.Request, o *domain.Order) {
	o.FirstName = r.FormValue("firstName")
	o.LastName = r.FormValue("lastName")
	o.Country = strings.ToUpper(r.FormValue("country"))
	o.City = r.FormValue("city")
	o.Address = r.FormValue("address")
	o.ZipCode = r.FormValue("zipCode")
	o.Phone = r.FormValue("phone")
	o.Email = r.FormValue("email")
}

// mapEdit lets an operator change the contact only: a deliberate subset.
func mapEdit(r *http.Request, o *domain.Order) {
	o.Phone = r.FormValue("phone")
	o.Email = r.FormValue("email")
}
`,
		"admin/bulk.go": `package admin

import "example.com/rulestest/domain"

func mapBulk(fields map[string]string, o *domain.Order) {
	o.FirstName = fields["firstName"]
	o.LastName = fields["lastName"]
	o.Country = fields["country"]
	o.City = fields["city"]
	o.Address = fields["address"]
	o.Note = fields["note"]
}

// mapImport sets the zip code and phone from a parsed column: nothing is
// missing.
func mapImport(fields map[string]string, o *domain.Order, phone string) {
	o.FirstName = fields["firstName"]
	o.LastName = fields["lastName"]
	o.Country = fields["country"]
	o.City = fields["city"]
	o.Address = fields["address"]
	o.ZipCode = fields["zip"]
	o.Phone = phone
	o.Email = fields["email"]
}
`,
	}))
}

// The form declares a field the handler never reads (it reads the prefixed
// spelling), and another one no read covers at all.
func TestFormFieldNameNotReadByHandler(t *testing.T) {
	assert.Equal(t, []string{"admin/fields.go:14", "admin/fields.go:21"}, patterntest.TypedFuncFindings(t, NewFormFieldNameNotReadByHandlerRule(), map[string]string{
		"admin/fields.go": `package admin

type FieldDef struct {
	Label string
	Name  string
	Type  int
}

func europe() []FieldDef {
	return []FieldDef{
		{Label: "First Name", Name: "customerFirstName", Type: 1},
		{Label: "Phone", Name: "customerPhone", Type: 1},
		{Label: "Referral Code", Name: "referralCode", Type: 2},
		{Label: "Zip Code", Name: "deliveryZipCode", Type: 1},
	}
}

func asia() []FieldDef {
	return []FieldDef{
		{Label: "First Name", Name: "customerFirstName", Type: 1},
		{Label: "Referral Code", Name: "referralCode", Type: 2},
	}
}
`,
		"admin/handler.go": `package admin

import "net/http"

type Order struct{ FirstName, Phone, ReferralCode, BillingZipCode string }

func mapForm(r *http.Request, o *Order) {
	o.FirstName = r.FormValue("customerFirstName")
	o.ReferralCode = r.FormValue("customerReferralCode")
	o.BillingZipCode = r.PostFormValue("billingZipCode")
	_ = r.Form.Get("customerPhone")
}

// validate only checks that every declared field is filled.
func validate(fields map[string]string, defs []FieldDef) bool {
	for _, f := range defs {
		if v, ok := fields[f.Name]; !ok || v == "" {
			return false
		}
	}
	return true
}
`,
		// Every declared name read through the definition: nothing to report.
		"dyn/fields.go": `package dyn

import "net/http"

type FieldDef struct {
	Label string
	Name  string
}

func fields() []FieldDef { return []FieldDef{{Label: "City", Name: "city"}} }

func read(r *http.Request) map[string]string {
	out := map[string]string{}
	for _, f := range fields() {
		out[f.Name] = r.FormValue(f.Name)
	}
	_ = r.FormValue("token")
	return out
}
`,
	}))
}

// The admin path passes zero placeholders for four values the live path
// computes: the admin-created row is stored without them.
func TestZeroPlaceholdersPassedForPersistedFields(t *testing.T) {
	assert.Equal(t, []string{"admin/quote.go:14"}, patterntest.TypedFuncFindings(t, NewZeroPlaceholdersPassedForPersistedFieldsRule(), map[string]string{
		"store/repo.go": `package store

import "time"

type Amount struct{ v int64 }

type TxRepo struct{}

func (r *TxRepo) StoreQuote(id string, amount Amount, local, rate Amount, source string, at *time.Time, actor string) error {
	return nil
}

func (r *TxRepo) RecordHistory(id, from, to string, raw []byte) error { return nil }

type LogRepo struct{}

func (r *LogRepo) LogAttempt(id string, status int, body string, failure string) error { return nil }
`,
		// A failed delivery has no status and no body to log: the zeros are
		// what happened, not placeholders.
		"hook/deliver.go": `package hook

import (
	"net/http"

	"example.com/rulestest/store"
)

type Worker struct {
	client *http.Client
	log    *store.LogRepo
}

func (w *Worker) Deliver(id string, req *http.Request) error {
	resp, err := w.client.Do(req)
	if err != nil {
		_ = w.log.LogAttempt(id, 0, "", err.Error())
		return err
	}
	return w.log.LogAttempt(id, resp.StatusCode, resp.Status, "")
}

func (w *Worker) Fail(id string, failure error) error {
	if failure != nil {
		return w.log.LogAttempt(id, 0, "", failure.Error())
	}
	return nil
}
`,
		"live/quote.go": `package live

import (
	"time"

	"example.com/rulestest/store"
)

type Tx struct {
	ID          string
	Amount      store.Amount
	Local, Rate store.Amount
	Source      string
	At          *time.Time
}

type Service struct{ repo *store.TxRepo }

func (s *Service) Save(tx *Tx, raw []byte) error {
	if err := s.repo.StoreQuote(tx.ID, tx.Amount, tx.Local, tx.Rate, tx.Source, tx.At, "api"); err != nil {
		return err
	}
	return s.repo.RecordHistory(tx.ID, "a", "b", raw)
}
`,
		"admin/quote.go": `package admin

import "example.com/rulestest/store"

type Admin struct{ repo *store.TxRepo }

type Tx struct {
	ID     string
	Amount store.Amount
}

func (a *Admin) Save(tx *Tx) error {
	if err := a.repo.StoreQuote(tx.ID, tx.Amount,
		store.Amount{}, store.Amount{}, "", nil,
		"admin"); err != nil {
		return err
	}
	// One optional value left out: a history row without the raw body.
	return a.repo.RecordHistory(tx.ID, "a", "b", nil)
}
`,
	}))
}

// A repository helper that only reads writes no row: "" and nil for the
// window of a sum "over all time" are a filter left out, not placeholders.
// The same shape writing through UPDATE is still reported.
// A row lock (SELECT ... FOR UPDATE) still only reads. A helper is not taken
// for a reader when it writes through its own method or through UPDATE ...
// RETURNING kept in a package constant or variable.
func TestZeroPlaceholdersPassedForPersistedFieldsSkipsReads(t *testing.T) {
	assert.Equal(t, []string{
		"store/deposits.go:41", "store/hidden.go:26", "store/hidden.go:41", "store/hidden.go:56",
		"store/mixed.go:30", "store/mixed.go:43", "store/mixed.go:86",
	}, patterntest.TypedFuncFindings(t, NewZeroPlaceholdersPassedForPersistedFieldsRule(), map[string]string{
		// A write followed by a read in one expression is still a write; so is
		// an ORM Updates and a call of another store's method that is not a
		// read. A quoted 'DELETE', an error text and a leading SQL
		// comment do not make a reader write.
		"store/mixed.go": `package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

type Updater interface{ Updates(values map[string]any) error }

type AuditRepo struct {
	db  *sql.DB
	orm Updater
}

func (r *AuditRepo) touch(ctx context.Context, q string, args []any) error { return nil }

func (r *AuditRepo) countAndTouch(ctx context.Context, window string, args []any) (int64, error) {
	var total int64
	err := r.db.QueryRowContext(ctx, "SELECT count(*) FROM audit WHERE true"+window, args...).Scan(&total)
	return total, errors.Join(err, r.touch(ctx, window, args), ctx.Err())
}

func (r *AuditRepo) CountTouchPeriod(ctx context.Context, from, to time.Time) (int64, error) {
	window, args := periodWindow(from, to)
	return r.countAndTouch(ctx, window, args)
}

func (r *AuditRepo) CountTouchAll(ctx context.Context) (int64, error) { return r.countAndTouch(ctx, "", nil) }

func (r *AuditRepo) countAndMark(ctx context.Context, window string, args []any) (int64, error) {
	var total int64
	err := r.db.QueryRowContext(ctx, "SELECT count(*) FROM audit WHERE true"+window, args...).Scan(&total)
	return total, errors.Join(err, r.orm.Updates(map[string]any{"seen": true}))
}

func (r *AuditRepo) CountMarkPeriod(ctx context.Context, from, to time.Time) (int64, error) {
	window, args := periodWindow(from, to)
	return r.countAndMark(ctx, window, args)
}

func (r *AuditRepo) CountMarkAll(ctx context.Context) (int64, error) { return r.countAndMark(ctx, "", nil) }

func (r *AuditRepo) countLive(ctx context.Context, window string, args []any) (int64, error) {
	var total int64
	q := "-- live rows only\nSELECT count(*) FROM audit WHERE op <> 'DELETE'" + window
	if err := r.db.QueryRowContext(ctx, q, args...).Scan(&total); err != nil {
		return 0, errors.Join(errors.New("count before update failed"), err)
	}
	return total, nil
}

func (r *AuditRepo) CountLivePeriod(ctx context.Context, from, to time.Time) (int64, error) {
	window, args := periodWindow(from, to)
	return r.countLive(ctx, window, args)
}

func (r *AuditRepo) CountLiveAll(ctx context.Context) (int64, error) { return r.countLive(ctx, "", nil) }

type TotalsRepo struct{ db *sql.DB }

func (t *TotalsRepo) Add(ctx context.Context, total int64) error {
	_, err := t.db.ExecContext(ctx, "INSERT INTO totals (v) VALUES ($1)", total)
	return err
}

type ReportRepo struct {
	db     *sql.DB
	totals *TotalsRepo
}

func (r *ReportRepo) sumAndKeep(ctx context.Context, window string, args []any) (int64, error) {
	var total int64
	if err := r.db.QueryRowContext(ctx, "SELECT SUM(v) FROM audit WHERE true"+window, args...).Scan(&total); err != nil {
		return 0, err
	}
	return total, r.totals.Add(ctx, total)
}

func (r *ReportRepo) KeepPeriod(ctx context.Context, from, to time.Time) (int64, error) {
	window, args := periodWindow(from, to)
	return r.sumAndKeep(ctx, window, args)
}

func (r *ReportRepo) KeepAll(ctx context.Context) (int64, error) { return r.sumAndKeep(ctx, "", nil) }
`,
		"store/hidden.go": `package store

import (
	"context"
	"database/sql"
	"time"
)

type LedgerRepo struct{ db *sql.DB }

func (r *LedgerRepo) apply(ctx context.Context, id int64) error { return nil }

func (r *LedgerRepo) settle(ctx context.Context, window string, args []any) error {
	var id int64
	if err := r.db.QueryRowContext(ctx, "SELECT id FROM ledger WHERE open"+window, args...).Scan(&id); err != nil {
		return err
	}
	return r.apply(ctx, id)
}

func (r *LedgerRepo) SettlePeriod(ctx context.Context, from, to time.Time) error {
	window, args := periodWindow(from, to)
	return r.settle(ctx, window, args)
}

func (r *LedgerRepo) SettleAll(ctx context.Context) error { return r.settle(ctx, "", nil) }

const closeLedger = "UPDATE ledger SET open = false WHERE open RETURNING id"

func (r *LedgerRepo) closeOpen(ctx context.Context, window string, args []any) (int64, error) {
	var id int64
	err := r.db.QueryRowContext(ctx, closeLedger+window, args...).Scan(&id)
	return id, err
}

func (r *LedgerRepo) ClosePeriod(ctx context.Context, from, to time.Time) (int64, error) {
	window, args := periodWindow(from, to)
	return r.closeOpen(ctx, window, args)
}

func (r *LedgerRepo) CloseAll(ctx context.Context) (int64, error) { return r.closeOpen(ctx, "", nil) }

var freezeLedger = "UPDATE ledger SET frozen = true WHERE open RETURNING id"

func (r *LedgerRepo) freezeOpen(ctx context.Context, window string, args []any) (int64, error) {
	var id int64
	err := r.db.QueryRowContext(ctx, freezeLedger+window, args...).Scan(&id)
	return id, err
}

func (r *LedgerRepo) FreezePeriod(ctx context.Context, from, to time.Time) (int64, error) {
	window, args := periodWindow(from, to)
	return r.freezeOpen(ctx, window, args)
}

func (r *LedgerRepo) FreezeAll(ctx context.Context) (int64, error) { return r.freezeOpen(ctx, "", nil) }

func (r *LedgerRepo) lockOpen(ctx context.Context, window string, args []any) (int64, error) {
	var id int64
	err := r.db.QueryRowContext(ctx, "SELECT id FROM ledger WHERE open"+window+" FOR UPDATE", args...).Scan(&id)
	return id, err
}

func (r *LedgerRepo) LockPeriod(ctx context.Context, from, to time.Time) (int64, error) {
	window, args := periodWindow(from, to)
	return r.lockOpen(ctx, window, args)
}

func (r *LedgerRepo) LockAll(ctx context.Context) (int64, error) { return r.lockOpen(ctx, "", nil) }
`,
		"store/deposits.go": `package store

import (
	"context"
	"database/sql"
	"time"
)

type DepositRepo struct{ db *sql.DB }

func periodWindow(from, to time.Time) (string, []any) {
	return " AND created_at BETWEEN $1 AND $2", []any{from, to}
}

func (r *DepositRepo) sumDeposits(ctx context.Context, window string, args []any) (int64, error) {
	var total int64
	err := r.db.QueryRowContext(ctx, "SELECT COALESCE(SUM(amount), 0) FROM deposits WHERE status = 'done'"+window, args...).Scan(&total)
	return total, err
}

func (r *DepositRepo) PeriodTotal(ctx context.Context, from, to time.Time) (int64, error) {
	window, args := periodWindow(from, to)
	return r.sumDeposits(ctx, window, args)
}

func (r *DepositRepo) Total(ctx context.Context) (int64, error) {
	return r.sumDeposits(ctx, "", nil)
}

func (r *DepositRepo) closeDeposits(ctx context.Context, window string, args []any) error {
	_, err := r.db.ExecContext(ctx, "UPDATE deposits SET status = 'closed' WHERE status = 'done'"+window, args...)
	return err
}

func (r *DepositRepo) ClosePeriod(ctx context.Context, from, to time.Time) error {
	window, args := periodWindow(from, to)
	return r.closeDeposits(ctx, window, args)
}

func (r *DepositRepo) CloseAll(ctx context.Context) error {
	return r.closeDeposits(ctx, "", nil)
}
`,
	}))
}
