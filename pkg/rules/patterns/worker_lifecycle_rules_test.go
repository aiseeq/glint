package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// A client that caches under a lock built twice from the same arguments in
// one wiring function keeps two caches: the second instance warms its own and
// whatever the first learned is lost to its users.
func TestStatefulClientConstructedTwice(t *testing.T) {
	assert.Equal(t, []string{"app/main.go:26"}, typedFuncFindings(t, NewStatefulClientConstructedTwiceRule(), map[string]string{
		"rates/client.go": `package rates

import "sync"

type Client struct {
	key   string
	mu    sync.Mutex
	cache map[string]float64
}

func NewClient(account, key string) *Client { return &Client{key: key, cache: map[string]float64{}} }

type Repo struct{ dsn string }

func NewRepo(dsn string) *Repo { return &Repo{dsn: dsn} }

// Limiter counts failures per key; every user gets an instance of its own.
type Limiter struct {
	mu     sync.Mutex
	counts map[string]int
}

func NewLimiter(limit int) *Limiter { return &Limiter{counts: map[string]int{}} }
`,
		"app/main.go": `package app

import "example.com/rulestest/rates"

type Config struct{ Account, Key, DSN string }

type Admin struct{ client *rates.Client }

type Refresher struct{ client *rates.Client }

func Run(cfg Config, admin bool) {
	if admin {
		var client *rates.Client
		if cfg.Key != "" {
			client = rates.NewClient(cfg.Account, cfg.Key)
		}
		_ = &Admin{client: client}
		_ = rates.NewRepo(cfg.DSN)
	}
	if cfg.Key != "" {
		_ = rates.NewRepo(cfg.DSN)
		other := rates.NewClient(cfg.Account, "readonly")
		_ = other
	}
	if cfg.Key != "" {
		client := rates.NewClient(cfg.Account, cfg.Key)
		_ = &Refresher{client: client}
	}
}

// Two limiters with the same settings are two budgets on purpose.
func Limiters() (*rates.Limiter, *rates.Limiter) {
	return rates.NewLimiter(10), rates.NewLimiter(10)
}

// Either branch builds the client once.
func Pick(cfg Config, admin bool) *rates.Client {
	if admin {
		return rates.NewClient(cfg.Account, cfg.Key)
	} else {
		return rates.NewClient(cfg.Account, cfg.Key)
	}
}
`,
	}))
}

// A non-blocking enqueue that drops the item when the queue is full counts on
// a rescan of the stored work; a worker that rescans only once, before its
// receive loop, picks the dropped item up only after a restart.
func TestDroppedEnqueueReliesOnStartupOnlyRescan(t *testing.T) {
	assert.Equal(t, []string{"batch/worker.go:24"}, typedFuncFindings(t, NewDroppedEnqueueReliesOnStartupOnlyRescanRule(), map[string]string{
		"batch/worker.go": `package batch

import (
	"context"
	"log/slog"
	"time"
)

type Repo struct{}

func (r *Repo) ListUnfinished(ctx context.Context) ([]string, error) { return nil, nil }

type Worker struct {
	queue  chan string
	wake   chan struct{}
	ticked chan string
	repo   *Repo
	logger *slog.Logger
}

func (w *Worker) Enqueue(id string) {
	select {
	case w.queue <- id:
	default:
		w.logger.Warn("queue full; batch deferred to the resume scan", "id", id)
	}
}

func (w *Worker) Run(ctx context.Context) {
	ids, _ := w.repo.ListUnfinished(ctx)
	for _, id := range ids {
		w.process(ctx, id)
	}
	for {
		select {
		case <-ctx.Done():
			return
		case id := <-w.queue:
			w.process(ctx, id)
		}
	}
}

func (w *Worker) process(ctx context.Context, id string) {}

// A wake-up signal coalesces: a pending one already wakes the worker.
func (w *Worker) Wake() {
	select {
	case w.wake <- struct{}{}:
	default:
	}
}

func (w *Worker) RunWake(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-w.wake:
		}
	}
}

// The worker rescans on a ticker: a dropped item is picked up within a tick.
func (w *Worker) EnqueueTicked(id string) {
	select {
	case w.ticked <- id:
	default:
		w.logger.Warn("queue full", "id", id)
	}
}

func (w *Worker) RunTicked(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case id := <-w.ticked:
			w.process(ctx, id)
		case <-ticker.C:
			ids, _ := w.repo.ListUnfinished(ctx)
			for _, id := range ids {
				w.process(ctx, id)
			}
		}
	}
}
`,
	}))
}

// The write that records an outbound command's success on the caller's
// cancellable context fails when the caller gives up right after the send:
// the command went out, the record of it did not, and a retry sends it again.
func TestPostSideEffectWriteUsesRequestContext(t *testing.T) {
	assert.Equal(t, []string{"payout/send.go:31", "payout/worker.go:21"}, typedFuncFindings(t, NewPostSideEffectWriteUsesRequestContextRule(), map[string]string{
		"payout/send.go": `package payout

import (
	"context"
	"fmt"
	"time"
)

type Response struct{ Ref string }

type Gateway struct{}

func (g *Gateway) SendTransfer(id string) (*Response, error) { return &Response{}, nil }

type Repo struct{}

func (r *Repo) UpdateSent(ctx context.Context, id, ref string) error { return nil }
func (r *Repo) RecordError(ctx context.Context, id string, err error) error { return nil }

type Service struct {
	gateway *Gateway
	repo    *Repo
}

func (s *Service) Send(ctx context.Context, id string) error {
	resp, err := s.gateway.SendTransfer(id)
	if err != nil {
		_ = s.repo.RecordError(ctx, id, err)
		return fmt.Errorf("send: %w", err)
	}
	if err := s.repo.UpdateSent(ctx, id, resp.Ref); err != nil {
		return err
	}
	return nil
}

// The record of the send outlives the caller.
func (s *Service) SendDetached(ctx context.Context, id string) error {
	resp, err := s.gateway.SendTransfer(id)
	if err != nil {
		_ = s.repo.RecordError(ctx, id, err)
		return err
	}
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()
	return s.repo.UpdateSent(writeCtx, id, resp.Ref)
}
`,
		"payout/noise.go": `package payout

import (
	"context"
	"fmt"
)

type Alerter struct{}

func (a *Alerter) SendStuckAlert(ids []string) error { return nil }

type Store struct{}

func (s *Store) MarkAlerted(ctx context.Context, ids []string) error { return nil }

type Batch struct{}

type Results struct{}

func (r *Results) Close() error { return nil }

type Tx struct{}

func (t *Tx) SendBatch(ctx context.Context, b *Batch) *Results { return &Results{} }
func (t *Tx) Commit(ctx context.Context) error             { return nil }

type Key struct{ ID string }

func TransferKeyOf(id string) Key { return Key{ID: id} }

type Monitor struct {
	alerter *Alerter
	store   *Store
	repo    *Repo
}

// A duplicate alert after a restart is accepted: it is not a command.
func (m *Monitor) Alert(ctx context.Context, ids []string) error {
	if err := m.alerter.SendStuckAlert(ids); err != nil {
		return fmt.Errorf("send alert: %w", err)
	}
	return m.store.MarkAlerted(ctx, ids)
}

// A database batch is not an outbound command.
func (m *Monitor) StorePage(ctx context.Context, tx *Tx, b *Batch) error {
	results := tx.SendBatch(ctx, b)
	if err := results.Close(); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// A key built from a transfer sends nothing.
func (m *Monitor) Classify(ctx context.Context, id string) error {
	key := TransferKeyOf(id)
	return m.repo.UpdateSent(ctx, key.ID, "")
}
`,
		"payout/worker.go": `package payout

import "context"

type Item struct{ ID, Lease string }

type Worker struct{ repo *Repo }

func (w *Worker) deliver(ctx context.Context, item Item) error { return nil }
func (w *Worker) finalizeLease(ctx context.Context, id string, mark func(context.Context) error) error {
	return mark(ctx)
}
func (w *Worker) markSent(ctx context.Context, id, lease string) error { return nil }
func (w *Worker) handleFailure(ctx context.Context, item Item, err error) error { return nil }

func (w *Worker) Process(ctx context.Context, item Item) {
	if err := w.deliver(ctx, item); err != nil {
		if ferr := w.handleFailure(ctx, item, err); ferr != nil {
			return
		}
	} else if markErr := w.finalizeLease(ctx, item.ID, func(attemptCtx context.Context) error {
		return w.markSent(attemptCtx, item.ID, item.Lease)
	}); markErr != nil {
		return
	}
}

func (w *Worker) ProcessDetached(ctx context.Context, item Item) {
	if err := w.deliver(ctx, item); err != nil {
		_ = w.handleFailure(ctx, item, err)
		return
	}
	_ = w.finalizeLease(context.WithoutCancel(ctx), item.ID, func(attemptCtx context.Context) error {
		return w.markSent(attemptCtx, item.ID, item.Lease)
	})
}
`,
	}))
}

// A mark written before a send is taken back on the send's failure with the
// caller's context: when the send failed because the caller went away, the
// removal fails too, the mark stays, and every redelivery is dropped as a
// duplicate. The confirm callback after the send records the outcome the same
// way.
func TestPostSideEffectCompensationUsesRequestContext(t *testing.T) {
	assert.Equal(t, []string{"relay/forward.go:27", "relay/forward.go:32"}, typedFuncFindings(t, NewPostSideEffectWriteUsesRequestContextRule(), map[string]string{
		"relay/forward.go": `package relay

import (
	"context"
	"fmt"
	"time"
)

type Request struct{ Text string }

type Client struct{}

func (c *Client) Send(ctx context.Context, req Request) (int64, error) { return 1, nil }

type Repo struct{}

func (r *Repo) DeletePendingMark(ctx context.Context, id string) error { return nil }

type Relay struct {
	client *Client
	repo   *Repo
}

func (s *Relay) Forward(ctx context.Context, id string, req Request, confirm func(ctx context.Context, sentID int64) error) (int64, error) {
	sentID, err := s.client.Send(ctx, req)
	if err != nil {
		if delErr := s.repo.DeletePendingMark(ctx, id); delErr != nil {
			return 0, fmt.Errorf("send: %w; mark kept: %w", err, delErr)
		}
		return 0, fmt.Errorf("send: %w", err)
	}
	if err := confirm(ctx, sentID); err != nil {
		return 0, err
	}
	return sentID, nil
}

func (s *Relay) ForwardSettled(ctx context.Context, id string, req Request, confirm func(ctx context.Context, sentID int64) error) (int64, error) {
	sentID, err := s.client.Send(ctx, req)
	settleCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err != nil {
		if delErr := s.repo.DeletePendingMark(settleCtx, id); delErr != nil {
			return 0, delErr
		}
		return 0, err
	}
	return sentID, confirm(settleCtx, sentID)
}
`,
	}))
}

// Cancelling the workers' context before the HTTP server drains takes the
// workers away from the requests still being served.
func TestWorkersCancelledBeforeHTTPDrain(t *testing.T) {
	assert.Equal(t, []string{"app/run.go:24"}, typedFuncFindings(t, NewWorkersCancelledBeforeHTTPDrainRule(), map[string]string{
		"app/run.go": `package app

import (
	"context"
	"net/http"
	"time"
)

func startWorkers(ctx context.Context) {}

func shutdown(server *http.Server) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return server.Shutdown(ctx)
}

func Run() error {
	workerCtx, workerCancel := context.WithCancel(context.Background())
	defer workerCancel()
	startWorkers(workerCtx)
	server := &http.Server{}
	_ = server.ListenAndServe()

	workerCancel()
	return shutdown(server)
}

func RunDrained() error {
	workerCtx, workerCancel := context.WithCancel(context.Background())
	defer workerCancel()
	startWorkers(workerCtx)
	server := &http.Server{}
	_ = server.ListenAndServe()
	if err := shutdown(server); err != nil {
		return err
	}
	workerCancel()
	return nil
}
`,
	}))
}

// A router-wide request timeout cuts an upload handler that reads a file for
// longer than a page takes: the import dies halfway with a deadline error.
func TestGlobalRequestTimeoutCutsUploadHandler(t *testing.T) {
	files := map[string]string{
		"middleware/middleware.go": `package middleware

import (
	"net/http"
	"time"
)

func Timeout(d time.Duration) func(http.Handler) http.Handler { return nil }
`,
		"web/router.go": `package web

import (
	"net/http"
	"time"

	"example.com/rulestest/middleware"
)

type Router struct{}

func (r *Router) Use(mw func(http.Handler) http.Handler) {}

func Setup() *Router {
	r := &Router{}
	r.Use(middleware.Timeout(30 * time.Second))
	return r
}
`,
		"web/upload.go": `package web

import (
	"context"
	"net/http"
	"time"
)

type Admin struct{}

func (a *Admin) handleImport(w http.ResponseWriter, r *http.Request) {
	path, err := a.saveUpload(r)
	if err != nil || path == "" {
		return
	}
}

func (a *Admin) saveUpload(r *http.Request) (string, error) {
	reader, err := r.MultipartReader()
	if err != nil {
		return "", err
	}
	_ = reader
	return "file", nil
}

func (a *Admin) handleParse(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		return
	}
}

func (a *Admin) handleOwnDeadline(w http.ResponseWriter, r *http.Request) {
	var cancel context.CancelFunc
	r, cancel = a.withUploadDeadline(r)
	defer cancel()
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		return
	}
}

func (a *Admin) withUploadDeadline(r *http.Request) (*http.Request, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 15*time.Minute)
	return r.WithContext(ctx), cancel
}

func (a *Admin) handlePage(w http.ResponseWriter, r *http.Request) {
	_ = r.URL.Query().Get("q")
}
`,
	}
	assert.Equal(t, []string{"web/upload.go:11", "web/upload.go:27"}, typedFuncFindings(t, NewGlobalRequestTimeoutCutsUploadHandlerRule(), files))

	// Without a router-wide timeout an upload handler has nothing to outlive.
	delete(files, "web/router.go")
	assert.Empty(t, typedFuncFindings(t, NewGlobalRequestTimeoutCutsUploadHandlerRule(), files))
}

// An expiry handed to the client that no code compares with the clock is a
// promise the server never keeps: an expired quote is still accepted.
func TestExpiryIssuedNeverEnforced(t *testing.T) {
	assert.Equal(t, []string{"api/quotes.go:24"}, typedFuncFindings(t, NewExpiryIssuedNeverEnforcedRule(), map[string]string{
		"api/quotes.go": `package api

import (
	"encoding/json"
	"net/http"
	"time"
)

type QuoteResponse struct {
	ID        string ` + "`json:\"id\"`" + `
	ExpiresAt string ` + "`json:\"expires_at\"`" + `
}

type OfferResponse struct {
	ID        string    ` + "`json:\"id\"`" + `
	ExpiresAt time.Time ` + "`json:\"expires_at\"`" + `
}

// OfferTTL is how long an offer holds; Confirm refuses an older one.
const OfferTTL = 10 * time.Minute

func createQuote(w http.ResponseWriter, r *http.Request) {
	// Quote expires in 15 minutes.
	expiresAt := time.Now().Add(15 * time.Minute)
	_ = json.NewEncoder(w).Encode(QuoteResponse{ID: "q1", ExpiresAt: expiresAt.Format(time.RFC3339)})
}

func createOffer(w http.ResponseWriter, r *http.Request) {
	_ = json.NewEncoder(w).Encode(OfferResponse{ID: "o1", ExpiresAt: time.Now().Add(OfferTTL)})
}

type Links struct{}

func (l *Links) Issue(token string, expiresAt time.Time) error { return nil }

var links = &Links{}

const linkTTL = 24 * time.Hour

// The expiry is stored with the link; the lookup refuses an expired one.
func issueLink(w http.ResponseWriter, r *http.Request) {
	expiresAt := time.Now().Add(linkTTL)
	if err := links.Issue("t", expiresAt); err != nil {
		return
	}
	_ = json.NewEncoder(w).Encode(QuoteResponse{ID: "t", ExpiresAt: expiresAt.Format(time.RFC3339)})
}

func confirmOffer(createdAt time.Time) bool {
	return time.Since(createdAt) <= OfferTTL
}
`,
	}))
}
