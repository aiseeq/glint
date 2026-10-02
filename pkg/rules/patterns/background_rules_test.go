package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// A polling goroutine with no recover dies with the whole server on one bad
// provider response; so does a goroutine an HTTP handler leaves running after
// it answered, outside the middleware's recover.
func TestBackgroundGoroutineWithoutRecover(t *testing.T) {
	assert.Equal(t, []string{"svc/poll.go:24", "svc/poll.go:34", "svc/poll.go:61"}, typedFuncFindings(t, NewBackgroundGoroutineWithoutRecoverRule(), map[string]string{
		"guard/guard.go": `package guard

func Recover(name string) {
	if r := recover(); r != nil {
		println(name)
	}
}

func Run(name string, f func()) {
	defer Recover(name)
	f()
}
`,
		"svc/poll.go": `package svc

import (
	"net/http"
	"time"

	"example.com/rulestest/guard"
)

type Service struct {
	ticker *time.Ticker
	done   chan struct{}
}

func (s *Service) refresh() {}

func (s *Service) loop() {
	for range s.ticker.C {
		s.refresh()
	}
}

func (s *Service) Start() {
	go func() {
		for {
			select {
			case <-s.ticker.C:
				s.refresh()
			case <-s.done:
				return
			}
		}
	}()
	go s.loop()
	go func() {
		defer guard.Recover("guarded")
		for range s.ticker.C {
			s.refresh()
		}
	}()
	go func() {
		for range s.ticker.C {
			guard.Run("iteration", s.refresh)
		}
	}()
	go s.refresh()
	go func() {
		defer func() {
			if r := recover(); r != nil {
				println("recovered")
			}
		}()
		for {
			s.refresh()
		}
	}()
}

func (s *Service) Handle(w http.ResponseWriter, req *http.Request) {
	w.WriteHeader(http.StatusAccepted)
	go func() {
		s.refresh()
	}()
}
`,
	}))
}

// A getter that builds a package-level value on first use without sync races
// its concurrent first callers: two instances, a torn read.
func TestLazyGlobalInitWithoutSync(t *testing.T) {
	assert.Equal(t, []string{"logs/logs.go:26"}, typedFuncFindings(t, NewLazyGlobalInitWithoutSyncRule(), map[string]string{
		"logs/logs.go": `package logs

import "sync"

type Logger struct{ name string }

func newLogger() *Logger { return &Logger{name: "default"} }

var (
	shared     *Logger
	guarded    *Logger
	guardedMu  sync.Mutex
	once       *Logger
	onceGuard  sync.Once
	registry   map[string]*Logger
	configured *Logger
)

func init() {
	if configured == nil {
		configured = newLogger()
	}
}

func Shared() *Logger {
	if shared == nil {
		shared = newLogger()
	}
	return shared
}

func Guarded() *Logger {
	guardedMu.Lock()
	defer guardedMu.Unlock()
	if guarded == nil {
		guarded = newLogger()
	}
	return guarded
}

func Once() *Logger {
	onceGuard.Do(func() { once = newLogger() })
	return once
}

func Lookup(name string) *Logger {
	local := registry[name]
	if local == nil {
		local = newLogger()
	}
	return local
}
`,
	}))
}

// A calendar date cut from a time in the process's zone shifts by a day
// around midnight depending on where the binary runs; a date stored or
// compared with UTC-based dates takes it UTC.
func TestDateFromLocalClock(t *testing.T) {
	assert.Equal(t, []string{"ledger/ledger.go:23", "ledger/ledger.go:24", "ledger/ledger.go:26"}, typedFuncFindings(t, NewDateFromLocalClockRule(), map[string]string{
		"ledger/ledger.go": `package ledger

import "time"

type Transfer struct {
	ID        string    ` + "`db:\"id\"`" + `
	Timestamp time.Time ` + "`db:\"timestamp\"`" + `
}

type Window struct {
	From time.Time
}

type Entry struct {
	Date string
}

const stamp = "2006-01-02 15:04:05"

func record(tr *Transfer, w Window, loc *time.Location) []Entry {
	now := time.Now()
	entries := []Entry{
		{Date: time.Now().Format("2006-01-02")},
		{Date: time.Now().AddDate(0, 0, -1).Format(time.DateOnly)},
		{Date: time.Now().UTC().Format("2006-01-02")},
		{Date: now.Format("2006-01-02")},
		{Date: now.UTC().Format("2006-01-02")},
		{Date: time.Now().In(loc).Format("2006-01-02")},
		{Date: time.Now().Format(stamp)},
		{Date: w.From.Format("2006-01-02")},
		{Date: tr.Timestamp.Format("2006-01-02")},
		{Date: tr.Timestamp.UTC().Format("2006-01-02")},
	}
	return entries
}
`,
	}))
}

// A validator that fills defaults into the zero fields of what it checks
// restores the default over the operator's choice when an update path calls
// it: a cleared field comes back.
func TestValidatorFillsDefaultsOnUpdate(t *testing.T) {
	assert.Equal(t, []string{"core/core.go:32"}, typedFuncFindings(t, NewValidatorFillsDefaultsOnUpdateRule(), map[string]string{
		"core/core.go": `package core

import "errors"

const defaultZone = "UTC"

type Account struct {
	ID       string
	Limit    float64
	Zone     string
	Currency string
}

type Service struct{}

func (s *Service) save(a *Account) error { return nil }

func (s *Service) CreateAccount(a *Account) error {
	if err := validateAccount(a); err != nil {
		return err
	}
	return s.save(a)
}

func (s *Service) UpdateAccount(a *Account) error {
	if a.ID == "" {
		return errors.New("id is required")
	}
	if err := checkCurrency(a); err != nil {
		return err
	}
	if err := validateAccount(a); err != nil {
		return err
	}
	return s.save(a)
}

func validateAccount(a *Account) error {
	if a.Limit == 0 {
		a.Limit = 30
	}
	if a.Zone == "" {
		a.Zone = defaultZone
	}
	if a.Limit < 0 {
		return errors.New("limit must be positive")
	}
	return nil
}

func checkCurrency(a *Account) error {
	if a.Currency == "" {
		return errors.New("currency is required")
	}
	return nil
}
`,
	}))
}

// A date glued into a reference or a file name, or only logged, carries the
// host's day harmlessly.
func TestDateFromLocalClockText(t *testing.T) {
	assert.Empty(t, typedFuncFindings(t, NewDateFromLocalClockRule(), map[string]string{
		"refs/refs.go": `package refs

import (
	"fmt"
	"log/slog"
	"time"
)

func Reference(id string) string {
	return "REF-" + time.Now().Format("20060102") + "-" + id
}

func StateFile(dir string) string {
	today := time.Now().Format("2006-01-02")
	slog.Info("state file", "day", today)
	return fmt.Sprintf("%s/state-%s.json", dir, today)
}
`,
	}))
}

// An update handler that decodes value fields and builds the entity from
// scratch overwrites every field the request left out with its zero value.
func TestUpdateHandlerResetsOmittedFields(t *testing.T) {
	assert.Equal(t, []string{"api/api.go:46"}, typedFuncFindings(t, NewUpdateHandlerResetsOmittedFieldsRule(), map[string]string{
		"api/api.go": `package api

import (
	"encoding/json"
	"net/http"
)

type Position struct {
	ID     string
	Name   string
	Amount float64
	Status string
}

func NewPosition(name string, amount float64) *Position {
	return &Position{Name: name, Amount: amount}
}

type Service struct{}

func (s *Service) UpdatePosition(p *Position) error         { return nil }
func (s *Service) GetPosition(id string) (*Position, error) { return &Position{ID: id}, nil }

type Router struct{ svc *Service }

type updateRequest struct {
	Name   string  ` + "`json:\"name\"`" + `
	Amount float64 ` + "`json:\"amount\"`" + `
	Status string  ` + "`json:\"status\"`" + `
}

type patchRequest struct {
	Name   *string  ` + "`json:\"name\"`" + `
	Amount *float64 ` + "`json:\"amount\"`" + `
}

func (r *Router) update(w http.ResponseWriter, req *http.Request) {
	var body updateRequest
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	pos := NewPosition(body.Name, body.Amount)
	pos.ID = req.PathValue("id")
	pos.Status = body.Status
	if err := r.svc.UpdatePosition(pos); err != nil {
		http.Error(w, "update failed", http.StatusInternalServerError)
	}
}

func (r *Router) updateLoaded(w http.ResponseWriter, req *http.Request) {
	var body updateRequest
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	pos, err := r.svc.GetPosition(req.PathValue("id"))
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	pos.Name = body.Name
	_ = r.svc.UpdatePosition(pos)
}

func (r *Router) patch(w http.ResponseWriter, req *http.Request) {
	var body patchRequest
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	pos := &Position{ID: req.PathValue("id")}
	if body.Name != nil {
		pos.Name = *body.Name
	}
	_ = r.svc.UpdatePosition(pos)
}
`,
	}))
}

// A fee sized for one period and dated today, written from a polling loop
// with no check that today's entry exists, is booked on every tick: several
// times a day.
func TestDatedEntryEveryTick(t *testing.T) {
	assert.Equal(t, []string{"fees/poll.go:24"}, typedFuncFindings(t, NewDatedEntryEveryTickRule(), map[string]string{
		"fees/fees.go": `package fees

import "time"

type Entry struct {
	Account string
	Amount  float64
	Date    string
}

type Ledger struct{}

func (l *Ledger) RecordEntry(e *Entry) error { return nil }
func (l *Ledger) LatestDate(account string) string { return "" }

type Fees struct{ ledger *Ledger }

func (f *Fees) Accrue(account string, rate float64) error {
	today := time.Now().UTC().Format("2006-01-02")
	entry := &Entry{Account: account, Amount: rate / 365, Date: today}
	return f.ledger.RecordEntry(entry)
}

func (f *Fees) AccrueOnce(account string, rate float64) error {
	today := time.Now().UTC().Format("2006-01-02")
	if f.ledger.LatestDate(account) == today {
		return nil
	}
	return f.ledger.RecordEntry(&Entry{Account: account, Amount: rate / 365, Date: today})
}
`,
		"fees/poll.go": `package fees

import "time"

type Poller struct {
	fees     *Fees
	accounts []string
	ledger   *Ledger
}

func (p *Poller) refreshPrices() {}

func (p *Poller) snapshots() {
	for _, account := range p.accounts {
		_ = p.fees.Accrue(account, 0.02)
	}
}

func (p *Poller) Start(interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			p.refreshPrices()
			p.snapshots()
			for _, account := range p.accounts {
				_ = p.fees.AccrueOnce(account, 0.02)
			}
		}
	}()
}

func (p *Poller) Daily() {
	today := time.Now().UTC().Format("2006-01-02")
	ticker := time.NewTicker(time.Hour)
	for {
		select {
		case <-ticker.C:
			for _, account := range p.accounts {
				if p.ledger.LatestDate(account) != today {
					_ = p.fees.Accrue(account, 0.02)
				}
			}
		}
	}
}
`,
	}))
}
