package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// periodicRepo is the store of daily rates the refresher tests share: rows
// keyed by pair and date, and the attempt markers of the daily run.
const periodicRepo = `package rates

import (
	"context"
	"time"
)

type Repo struct{}

func (r *Repo) HasRatesForDate(ctx context.Context, date time.Time) (bool, error)  { return false, nil }
func (r *Repo) CountForDate(ctx context.Context, date time.Time) (int, error)      { return 0, nil }
func (r *Repo) CountPairsForDate(ctx context.Context, date time.Time, pairs []string) (int, error) {
	return 0, nil
}
func (r *Repo) HasRate(ctx context.Context, pair string, date time.Time) (bool, error) { return false, nil }
func (r *Repo) HasRefreshAttempt(ctx context.Context, date time.Time) (bool, error)  { return false, nil }
func (r *Repo) Upsert(ctx context.Context, pair string, rate float64, date time.Time) error {
	return nil
}
func (r *Repo) TryStartRefreshAttempt(ctx context.Context, date time.Time, source string) (bool, error) {
	return true, nil
}
func (r *Repo) DeleteRefreshAttempt(ctx context.Context, date time.Time, source string) error {
	return nil
}

type Source struct{}

func (s *Source) Fetch(ctx context.Context, pairs []string) (map[string]float64, error) {
	return nil, nil
}

type Config struct{}

func (c *Config) ActivePairs(ctx context.Context) ([]string, error) { return nil, nil }

var staticPairs = []string{"USD/EUR", "USD/GBP"}

func today() time.Time { return time.Now().UTC().Truncate(24 * time.Hour) }

func fingerprint(pairs []string) string { return "" }
`

// periodicLoop runs check of the refresher on every tick, the way every
// refresher of the tests is driven.
func periodicLoop(typeName string) string {
	return `
func (r *` + typeName + `) Run(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.check(ctx)
		}
	}
}
`
}

// A daily job that skips its whole run when any row for today exists stays
// skipped after a partial run (or a lazy write of one key): the keys that
// are missing are never fetched that day.
func TestPeriodicJobDoneCheckByAnyRow(t *testing.T) {
	assert.Equal(t, []string{"rates/any_row.go:15", "rates/count.go:15"}, typedFuncFindings(t, NewPeriodicJobDoneCheckByAnyRowRule(), map[string]string{
		"rates/repo.go": periodicRepo,
		"rates/any_row.go": `package rates

import (
	"context"
	"time"
)

type AnyRow struct {
	repo   *Repo
	source *Source
}

func (r *AnyRow) check(ctx context.Context) {
	date := today()
	exists, err := r.repo.HasRatesForDate(ctx, date)
	if err != nil {
		return
	}
	if exists {
		return
	}
	r.fetchAll(ctx, date)
}

func (r *AnyRow) fetchAll(ctx context.Context, date time.Time) {
	rates, err := r.source.Fetch(ctx, staticPairs)
	if err != nil {
		return
	}
	for pair, rate := range rates {
		_ = r.repo.Upsert(ctx, pair, rate, date)
	}
}
` + periodicLoop("AnyRow"),
		"rates/count.go": `package rates

import (
	"context"
	"time"
)

type Counted struct {
	repo   *Repo
	source *Source
}

func (r *Counted) check(ctx context.Context) {
	date := today()
	stored, err := r.repo.CountForDate(ctx, date)
	if err != nil {
		return
	}
	if stored > 0 {
		return
	}
	rates, err := r.source.Fetch(ctx, staticPairs)
	if err != nil {
		return
	}
	for pair, rate := range rates {
		_ = r.repo.Upsert(ctx, pair, rate, date)
	}
}
` + periodicLoop("Counted"),
		// Every pair counted, a key checked inside the loop, a marker of the
		// run checked: none skips keys that are missing.
		"rates/good.go": `package rates

import (
	"context"
	"time"
)

type AllPairs struct {
	repo   *Repo
	source *Source
}

func (r *AllPairs) check(ctx context.Context) {
	date := today()
	stored, err := r.repo.CountPairsForDate(ctx, date, staticPairs)
	if err != nil {
		return
	}
	if stored == len(staticPairs) {
		return
	}
	rates, err := r.source.Fetch(ctx, staticPairs)
	if err != nil {
		return
	}
	for pair, rate := range rates {
		_ = r.repo.Upsert(ctx, pair, rate, date)
	}
}
` + periodicLoop("AllPairs") + `
type PerKey struct {
	repo   *Repo
	source *Source
}

func (r *PerKey) check(ctx context.Context) {
	date := today()
	for _, pair := range staticPairs {
		has, err := r.repo.HasRate(ctx, pair, date)
		if err != nil || has {
			continue
		}
		_ = r.repo.Upsert(ctx, pair, 1, date)
	}
}
` + periodicLoop("PerKey") + `
type Marked struct {
	repo   *Repo
	source *Source
}

func (r *Marked) check(ctx context.Context) {
	date := today()
	done, err := r.repo.HasRefreshAttempt(ctx, date)
	if err != nil || done {
		return
	}
	rates, err := r.source.Fetch(ctx, staticPairs)
	if err != nil {
		return
	}
	for pair, rate := range rates {
		_ = r.repo.Upsert(ctx, pair, rate, date)
	}
}
` + periodicLoop("Marked"),
		// Not driven by a tick: a handler answering whether today is loaded.
		"rates/handler.go": `package rates

import "context"

type Loader struct {
	repo   *Repo
	source *Source
}

func (l *Loader) Load(ctx context.Context) error {
	date := today()
	exists, err := l.repo.HasRatesForDate(ctx, date)
	if err != nil || exists {
		return err
	}
	rates, err := l.source.Fetch(ctx, staticPairs)
	if err != nil {
		return err
	}
	for pair, rate := range rates {
		_ = l.repo.Upsert(ctx, pair, rate, date)
	}
	return nil
}
`,
	}))
}

// A once-a-day attempt marker keyed by the date alone covers the work list
// of the morning: a pair activated later that day finds the day attempted
// and is not fetched until tomorrow.
func TestPeriodAttemptMarkerIgnoresWorkSet(t *testing.T) {
	assert.Equal(t, []string{"rates/dynamic.go:20"}, typedFuncFindings(t, NewPeriodAttemptMarkerIgnoresWorkSetRule(), map[string]string{
		"rates/repo.go": periodicRepo,
		"rates/dynamic.go": `package rates

import (
	"context"
	"time"
)

type Dynamic struct {
	repo   *Repo
	source *Source
	config *Config
}

func (r *Dynamic) check(ctx context.Context) {
	date := today()
	pairs, err := r.config.ActivePairs(ctx)
	if err != nil {
		return
	}
	started, err := r.repo.TryStartRefreshAttempt(ctx, date, "primary")
	if err != nil || !started {
		return
	}
	r.fetch(ctx, date, pairs)
}

func (r *Dynamic) fetch(ctx context.Context, date time.Time, pairs []string) {
	rates, _ := r.source.Fetch(ctx, pairs)
	for pair, rate := range rates {
		_ = r.repo.Upsert(ctx, pair, rate, date)
	}
}
` + periodicLoop("Dynamic"),
		// The marker key carries the work set; a fixed work set needs none.
		"rates/good.go": `package rates

import (
	"context"
	"time"
)

type Keyed struct {
	repo   *Repo
	source *Source
	config *Config
}

func (r *Keyed) check(ctx context.Context) {
	date := today()
	pairs, err := r.config.ActivePairs(ctx)
	if err != nil {
		return
	}
	started, err := r.repo.TryStartRefreshAttempt(ctx, date, fingerprint(pairs))
	if err != nil || !started {
		return
	}
	rates, _ := r.source.Fetch(ctx, pairs)
	for pair, rate := range rates {
		_ = r.repo.Upsert(ctx, pair, rate, date)
	}
}
` + periodicLoop("Keyed") + `
type Fixed struct {
	repo   *Repo
	source *Source
}

func (r *Fixed) check(ctx context.Context) {
	date := today()
	pairs := staticPairs
	started, err := r.repo.TryStartRefreshAttempt(ctx, date, "primary")
	if err != nil || !started {
		return
	}
	rates, _ := r.source.Fetch(ctx, pairs)
	for pair, rate := range rates {
		_ = r.repo.Upsert(ctx, pair, rate, date)
	}
}
` + periodicLoop("Fixed"),
	}))
}

// A once-a-day marker written before the work it guards burns the day when
// the work fails: every later tick finds the day attempted and does nothing
// until tomorrow.
func TestAttemptMarkerWrittenBeforeWork(t *testing.T) {
	assert.Equal(t, []string{"rates/early.go:15"}, typedFuncFindings(t, NewAttemptMarkerWrittenBeforeWorkRule(), map[string]string{
		"rates/repo.go": periodicRepo,
		"rates/early.go": `package rates

import (
	"context"
	"time"
)

type Early struct {
	repo   *Repo
	source *Source
}

func (r *Early) check(ctx context.Context) {
	date := today()
	started, err := r.repo.TryStartRefreshAttempt(ctx, date, "primary")
	if err != nil {
		return
	}
	if !started {
		return
	}
	r.fetch(ctx, date)
}

func (r *Early) fetch(ctx context.Context, date time.Time) {
	rates, err := r.source.Fetch(ctx, staticPairs)
	if err != nil {
		return
	}
	for pair, rate := range rates {
		_ = r.repo.Upsert(ctx, pair, rate, date)
	}
}
` + periodicLoop("Early"),
		// The marker written after the work succeeded, and a marker taken
		// back when the work fails.
		"rates/good.go": `package rates

import (
	"context"
	"time"
)

type Late struct {
	repo   *Repo
	source *Source
}

func (r *Late) check(ctx context.Context) {
	date := today()
	done, err := r.repo.HasRefreshAttempt(ctx, date)
	if err != nil || done {
		return
	}
	if err := r.fetch(ctx, date); err != nil {
		return
	}
	_, _ = r.repo.TryStartRefreshAttempt(ctx, date, "primary")
}

func (r *Late) fetch(ctx context.Context, date time.Time) error {
	rates, err := r.source.Fetch(ctx, staticPairs)
	if err != nil {
		return err
	}
	for pair, rate := range rates {
		if err := r.repo.Upsert(ctx, pair, rate, date); err != nil {
			return err
		}
	}
	return nil
}
` + periodicLoop("Late") + `
type Released struct {
	repo   *Repo
	source *Source
}

func (r *Released) check(ctx context.Context) {
	date := today()
	started, err := r.repo.TryStartRefreshAttempt(ctx, date, "primary")
	if err != nil || !started {
		return
	}
	rates, err := r.source.Fetch(ctx, staticPairs)
	if err != nil {
		_ = r.repo.DeleteRefreshAttempt(ctx, date, "primary")
		return
	}
	for pair, rate := range rates {
		_ = r.repo.Upsert(ctx, pair, rate, date)
	}
}
` + periodicLoop("Released"),
	}))
}

// A feed read page by page from a cursor that rejects the whole page for one
// record the converter refuses never moves past that record.
func TestCursorFeedBlockedByRejectedRecord(t *testing.T) {
	assert.Equal(t, []string{"feed/client.go:30", "feed/sync.go:29"}, typedFuncFindings(t, NewCursorFeedBlockedByRejectedRecordRule(), map[string]string{
		"feed/client.go": `package feed

import (
	"context"
	"errors"
	"fmt"
)

type wireItem struct {
	ID     string ` + "`json:\"id\"`" + `
	Client string ` + "`json:\"client\"`" + `
}

type Item struct {
	ID     string
	Client string
}

type Page struct {
	Items      []Item
	NextCursor string
}

type Client struct{ wire []wireItem }

func (c *Client) List(ctx context.Context, cursor string) (*Page, error) {
	page := &Page{}
	for i, w := range c.wire {
		item, err := w.toItem()
		if err != nil {
			return nil, fmt.Errorf("item %d: %w", i, err)
		}
		page.Items = append(page.Items, item)
	}
	return page, nil
}

func (w wireItem) toItem() (Item, error) {
	if w.ID == "" {
		return Item{}, errors.New("empty id")
	}
	if w.Client == "" {
		return Item{}, errors.New("empty client")
	}
	return Item{ID: w.ID, Client: w.Client}, nil
}

// All lists a table that has no cursor: one bad row fails the read.
func (c *Client) All(ctx context.Context) ([]Item, error) {
	var items []Item
	for _, w := range c.wire {
		item, err := w.toItem()
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, nil
}
`,
		"feed/sync.go": `package feed

import (
	"context"
	"errors"
)

type Order struct{ ID string }

type Store struct{}

func (s *Store) SavePage(ctx context.Context, orders []Order, cursor string) error { return nil }

func toOrder(item Item) (Order, error) {
	if item.ID == "" {
		return Order{}, errors.New("empty id")
	}
	return Order{ID: item.ID}, nil
}

func Sync(ctx context.Context, c *Client, s *Store, cursor string) error {
	page, err := c.raw(ctx, cursor)
	if err != nil {
		return err
	}
	var orders []Order
	for _, item := range page.Items {
		o, err := toOrder(item)
		if err != nil {
			return err
		}
		orders = append(orders, o)
	}
	return s.SavePage(ctx, orders, page.NextCursor)
}

func (c *Client) raw(ctx context.Context, cursor string) (*Page, error) { return &Page{}, nil }
`,
		// The record that cannot be fully read is kept with its defect.
		"marked/client.go": `package marked

import (
	"context"
	"errors"
	"fmt"
)

type wireItem struct {
	ID     string
	Client string
}

type Item struct {
	ID        string
	Client    string
	DataIssue string
}

type Client struct{ wire []wireItem }

func (c *Client) List(ctx context.Context, cursor string) ([]Item, error) {
	var items []Item
	for i, w := range c.wire {
		item, err := w.toItem()
		if err != nil {
			return nil, fmt.Errorf("item %d: %w", i, err)
		}
		items = append(items, item)
	}
	return items, nil
}

func (w wireItem) toItem() (Item, error) {
	if w.ID == "" {
		return Item{}, errors.New("empty id")
	}
	item := Item{ID: w.ID, Client: w.Client}
	if w.Client == "" {
		item.DataIssue = "no client"
	}
	return item, nil
}
`,
	}))
}

// An event marked processed in its duplicate check, before the processing,
// stays marked when the processing fails: the sender's redelivery of the
// failed event is dropped as a duplicate.
func TestAttemptMarkerWrittenBeforeWorkDedup(t *testing.T) {
	assert.Equal(t, []string{"hooks/handler.go:39", "hooks/handler.go:66"}, typedFuncFindings(t, NewAttemptMarkerWrittenBeforeWorkRule(), map[string]string{
		"hooks/handler.go": `package hooks

import (
	"context"
	"sync"
	"time"
)

type dedup struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

func (d *dedup) isDuplicate(key string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	at, ok := d.seen[key]
	return ok && time.Since(at) < time.Minute
}

func (d *dedup) markProcessed(key string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.seen[key] = time.Now()
}

func (d *dedup) forget(key string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.seen, key)
}

type Handler struct{ d *dedup }

func (h *Handler) checkDuplicate(key string) bool {
	if h.d.isDuplicate(key) {
		return true
	}
	h.d.markProcessed(key)
	return false
}

func (h *Handler) Handle(key string) {
	if h.checkDuplicate(key) {
		return
	}
	go h.process(key)
}

func (h *Handler) process(key string) {}

type repo interface {
	IsProcessed(ctx context.Context, id string) (bool, error)
	MarkProcessed(ctx context.Context, id string) error
	Run(ctx context.Context, id string) error
}

func HandleEvent(ctx context.Context, r repo, id string) error {
	seen, err := r.IsProcessed(ctx, id)
	if err != nil {
		return err
	}
	if seen {
		return nil
	}
	if err := r.MarkProcessed(ctx, id); err != nil {
		return err
	}
	return r.Run(ctx, id)
}

func HandleAfter(ctx context.Context, r repo, id string) error {
	seen, err := r.IsProcessed(ctx, id)
	if err != nil || seen {
		return err
	}
	if err := r.Run(ctx, id); err != nil {
		return err
	}
	return r.MarkProcessed(ctx, id)
}

func (h *Handler) HandleReleased(key string) {
	if h.d.isDuplicate(key) {
		return
	}
	h.d.markProcessed(key)
	go func() {
		if !h.run(key) {
			h.d.forget(key)
		}
	}()
}

func (h *Handler) run(key string) bool { return key != "" }
`,
	}))
}
