package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// The webhook stores the provider's raw status next to the mapped one; the
// poller maps the same response and stores only the mapped status, so a
// transaction the poller moved keeps a stale provider status.
func TestAlternateSyncPathDropsFields(t *testing.T) {
	assert.Equal(t, []string{"poll/poller.go:23"}, typedFuncFindings(t, NewAlternateSyncPathDropsFieldsRule(), map[string]string{
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
	assert.Equal(t, []string{"admin/bulk.go:5"}, typedFuncFindings(t, NewParallelKeyToFieldMappingDriftsRule(), map[string]string{
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
	assert.Equal(t, []string{"admin/fields.go:14", "admin/fields.go:21"}, typedFuncFindings(t, NewFormFieldNameNotReadByHandlerRule(), map[string]string{
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
	assert.Equal(t, []string{"admin/quote.go:14"}, typedFuncFindings(t, NewZeroPlaceholdersPassedForPersistedFieldsRule(), map[string]string{
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
