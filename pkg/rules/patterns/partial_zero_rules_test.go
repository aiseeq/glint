package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules"
)

func typedFuncFindings(t *testing.T, rule rules.GoProjectRule, files map[string]string) []string {
	t.Helper()
	violations, err := rule.AnalyzeGoProject(decimalProject(t, files))
	require.NoError(t, err)
	return foundLines(violations)
}

// A sync that persists rows and then reports a later step's failures together
// with them is a partial success: a caller that drops the rows on the error
// loses what was written.
func TestPartialResultsDroppedOnError(t *testing.T) {
	assert.Equal(t, []string{"sync/run.go:9"}, typedFuncFindings(t, NewPartialResultsDroppedOnErrorRule(), map[string]string{
		"sync/sync.go": `package sync

import (
	"errors"
	"fmt"
)

type Result struct{ New int }

type Service struct{}

func (s *Service) Sync(account string) ([]*Result, error) {
	var results []*Result
	results = append(results, &Result{New: 1})
	return results, s.reconcile(account, results)
}

func (s *Service) reconcile(account string, results []*Result) error {
	var errs []error
	for _, r := range results {
		if r.New < 0 {
			errs = append(errs, fmt.Errorf("%s: negative", account))
		}
	}
	return errors.Join(errs...)
}

func (s *Service) Load(account string) ([]*Result, error) {
	var out []*Result
	var errs []error
	out = append(out, &Result{})
	if account == "" {
		errs = append(errs, errors.New("empty"))
	}
	return out, errors.Join(errs...)
}

func (s *Service) Plain(account string) ([]*Result, error) {
	out := []*Result{{}}
	return out, fmt.Errorf("plain %s", account)
}
`,
		"sync/run.go": `package sync

import "log"

func (s *Service) Run(accounts []string) int {
	total := 0
	for _, account := range accounts {
		results, err := s.Sync(account)
		if err != nil {
			log.Println("sync failed", err)
			continue
		}
		for _, r := range results {
			total += r.New
		}
	}
	return total
}

func (s *Service) Propagate(account string) (int, error) {
	results, err := s.Load(account)
	if err != nil {
		return 0, err
	}
	return len(results), nil
}

func (s *Service) Counted(account string) int {
	results, err := s.Sync(account)
	if err != nil {
		log.Println("partial", len(results))
		return len(results)
	}
	return len(results)
}

func (s *Service) Whole(account string) int {
	results, err := s.Plain(account)
	if err != nil {
		return 0
	}
	return len(results)
}
`,
	}))
}

// A batch over independent items that already skips some failed items but
// returns on another failure leaves every later item unprocessed.
func TestBatchAbortsOnItemError(t *testing.T) {
	assert.Equal(t, []string{"batch/run.go:24"}, typedFuncFindings(t, NewBatchAbortsOnItemErrorRule(), map[string]string{
		"batch/run.go": `package batch

import (
	"context"
	"errors"
	"fmt"
)

var errNotFound = errors.New("not found")

type client interface {
	Status(ctx context.Context, id string) (string, error)
	Mark(ctx context.Context, id, status string) error
}

func Reconcile(ctx context.Context, c client, ids []string) (int, error) {
	corrected := 0
	for _, id := range ids {
		status, err := c.Status(ctx, id)
		if errors.Is(err, errNotFound) {
			continue
		}
		if err != nil {
			return corrected, fmt.Errorf("status %s: %w", id, err)
		}
		if err := c.Mark(ctx, id, "seen"); err != nil {
			return corrected, err
		}
		if err := c.Mark(ctx, id, status); err != nil {
			failures := 0
			_ = failures
			continue
		}
		corrected++
	}
	return corrected, nil
}

func Strict(ctx context.Context, c client, ids []string) (int, error) {
	done := 0
	for _, id := range ids {
		if err := c.Mark(ctx, id, "x"); err != nil {
			return done, err
		}
		done++
	}
	return done, nil
}

func Collected(ctx context.Context, c client, ids []string) (int, error) {
	done := 0
	var failures []error
	for _, id := range ids {
		if err := c.Mark(ctx, id, "x"); err != nil {
			failures = append(failures, err)
			continue
		}
		done++
		if err := ctx.Err(); err != nil {
			return done, errors.Join(append(failures, err)...)
		}
	}
	return done, errors.Join(failures...)
}

func NoProgress(ctx context.Context, c client, ids []string) (int, error) {
	for _, id := range ids {
		_, err := c.Status(ctx, id)
		if errors.Is(err, errNotFound) {
			continue
		}
		if err != nil {
			return 0, err
		}
	}
	return len(ids), nil
}
`,
	}))
}

// A batch that leaves some items out with a report (no match, an ambiguous
// match) treats its items as independent too: a write failure of one item's
// part, returned with the progress, stops every later item.
func TestBatchAbortsOnItemErrorAfterReportedSkip(t *testing.T) {
	assert.Equal(t, []string{"link/run.go:36", "link/run.go:67"}, typedFuncFindings(t, NewBatchAbortsOnItemErrorRule(), map[string]string{
		"link/run.go": `package link

import (
	"context"
	"log/slog"
)

type Row struct{ ID string }

type Position struct{ ID string }

type Match struct {
	Position  *Position
	Ambiguous bool
}

type store interface {
	Find(ctx context.Context, rows []*Row) (Match, error)
	Link(ctx context.Context, row *Row, positionID string) (bool, error)
}

type Service struct {
	store  store
	logger *slog.Logger
}

func (s *Service) reportAmbiguous(rows []*Row) {
	s.logger.Warn("ambiguous", "rows", len(rows))
}

func (s *Service) LinkGroups(ctx context.Context, groups map[string][]*Row) (int, error) {
	var linked int
	for _, rows := range groups {
		match, err := s.store.Find(ctx, rows)
		if err != nil {
			return linked, err
		}
		if match.Position == nil {
			if match.Ambiguous {
				s.reportAmbiguous(rows)
			}
			continue
		}
		for _, row := range rows {
			changed, err := s.store.Link(ctx, row, match.Position.ID)
			if err != nil {
				return linked, err
			}
			if changed {
				linked++
			}
		}
	}
	return linked, nil
}

func (s *Service) LinkParts(ctx context.Context, groups map[string][]*Row) (int, error) {
	var linked int
	for _, rows := range groups {
		if len(rows) == 0 {
			s.logger.Warn("empty group")
			continue
		}
		for _, row := range rows {
			changed, err := s.store.Link(ctx, row, "p")
			if err != nil {
				return linked, err
			}
			if changed {
				linked++
			}
		}
	}
	return linked, nil
}

func (s *Service) PlainSkip(ctx context.Context, groups map[string][]*Row) (int, error) {
	var linked int
	for _, rows := range groups {
		if len(rows) == 0 {
			continue
		}
		for _, row := range rows {
			changed, err := s.store.Link(ctx, row, "p")
			if err != nil {
				return linked, err
			}
			if changed {
				linked++
			}
		}
	}
	return linked, nil
}

func (s *Service) OtherList(ctx context.Context, groups map[string][]*Row, extra []*Row) (int, error) {
	var linked int
	for _, rows := range groups {
		if len(rows) == 0 {
			s.logger.Warn("empty group")
			continue
		}
		linked += len(rows)
	}
	for _, row := range extra {
		if _, err := s.store.Link(ctx, row, "p"); err != nil {
			return linked, err
		}
	}
	return linked, nil
}
`,
	}))
}

// A periodic pass running two unrelated checks returns on the first one's
// failure: the second check is silent whenever the first fails.
func TestIndependentChecksAbortTogether(t *testing.T) {
	assert.Equal(t, []string{"monitor/monitor.go:22"}, typedFuncFindings(t, NewIndependentChecksAbortTogetherRule(), map[string]string{
		"monitor/monitor.go": `package monitor

import (
	"context"
	"log"
)

type Alert struct{}

type Monitor struct{}

func (m *Monitor) CheckYields(ctx context.Context) ([]Alert, error) { return nil, nil }
func (m *Monitor) CheckPegs(ctx context.Context) ([]Alert, error)   { return nil, nil }
func (m *Monitor) Load(ctx context.Context) (string, error)         { return "", nil }
func (m *Monitor) Use(ctx context.Context, s string) ([]Alert, error) { return nil, nil }
func (m *Monitor) notify(ctx context.Context, alerts []Alert)       {}

func (m *Monitor) Start(ctx context.Context) {
	go func() {
		for range make(chan struct{}) {
			yields, err := m.CheckYields(ctx)
			if err != nil {
				log.Println("yields failed", err)
				return
			}
			m.notify(ctx, yields)
			pegs, err := m.CheckPegs(ctx)
			if err != nil {
				log.Println("pegs failed", err)
				return
			}
			m.notify(ctx, pegs)
		}
	}()
}

func (m *Monitor) Dependent(ctx context.Context) {
	name, err := m.Load(ctx)
	if err != nil {
		log.Println("load failed", err)
		return
	}
	m.notify(ctx, nil)
	alerts, err := m.Use(ctx, name)
	if err != nil {
		log.Println("use failed", err)
		return
	}
	m.notify(ctx, alerts)
}

func (m *Monitor) Propagates(ctx context.Context) error {
	yields, err := m.CheckYields(ctx)
	if err != nil {
		return err
	}
	m.notify(ctx, yields)
	pegs, err := m.CheckPegs(ctx)
	if err != nil {
		return err
	}
	m.notify(ctx, pegs)
	return nil
}
`,
	}))
}

// An unlink that returns the entity untouched when a secondary record is
// missing answers "unlinked" while the entity still carries the link.
func TestUnlinkNoopReportsSuccess(t *testing.T) {
	assert.Equal(t, []string{"links/links.go:31", "links/links.go:34"}, typedFuncFindings(t, NewUnlinkNoopReportsSuccessRule(), map[string]string{
		"links/links.go": `package links

import (
	"context"
	"fmt"
)

type Tx struct {
	ID         string
	PositionID *string
}

type Record struct{ Allocation *string }

type Service struct{}

func (s *Service) GetTx(ctx context.Context, id string) (*Tx, error)         { return nil, nil }
func (s *Service) GetRecord(ctx context.Context, id string) (*Record, error) { return nil, nil }
func (s *Service) Detach(ctx context.Context, id string) error               { return nil }

func (s *Service) UnlinkTxFromPosition(ctx context.Context, id string) (*Tx, error) {
	tx, err := s.GetTx(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("get: %w", err)
	}
	rec, err := s.GetRecord(ctx, id)
	if err != nil {
		return nil, err
	}
	if rec == nil {
		return tx, nil
	}
	if rec.Allocation == nil {
		return tx, nil
	}
	if err := s.Detach(ctx, id); err != nil {
		return nil, err
	}
	return tx, nil
}

func (s *Service) UnlinkChecked(ctx context.Context, id string) (*Tx, error) {
	tx, err := s.GetTx(ctx, id)
	if err != nil {
		return nil, err
	}
	if tx.PositionID == nil {
		return tx, nil
	}
	rec, err := s.GetRecord(ctx, id)
	if err != nil {
		return nil, err
	}
	if rec == nil {
		return tx, nil
	}
	return tx, s.Detach(ctx, id)
}

func (s *Service) RemoveTxFromPosition(ctx context.Context, id string) (*Tx, error) {
	tx, err := s.GetTx(ctx, id)
	if err != nil {
		return nil, err
	}
	if err := s.Detach(ctx, id); err != nil {
		return nil, err
	}
	return tx, nil
}
`,
	}))
}

// A value priced only in the cases of a switch with no default is zero for
// every other asset, and the zero goes into the total.
func TestValuationZeroWhenNoCaseMatches(t *testing.T) {
	assert.Equal(t, []string{"prices/total.go:18"}, typedFuncFindings(t, NewValuationZeroWhenNoCaseMatchesRule(), map[string]string{
		"prices/total.go": `package prices

import (
	"strings"

	"github.com/shopspring/decimal"
)

type Balance struct {
	Kind   string
	Symbol string
	Amount decimal.Decimal
}

func Total(balances []Balance, nativePrice decimal.Decimal) decimal.Decimal {
	total := decimal.Zero
	for _, b := range balances {
		usdValue := decimal.Zero
		usdPrice := decimal.Zero
		switch {
		case b.Kind == "native":
			usdPrice = nativePrice
			usdValue = b.Amount.Mul(nativePrice)
		case strings.EqualFold(b.Symbol, "USDC"):
			usdPrice = decimal.NewFromInt(1)
			usdValue = b.Amount
		}
		total = total.Add(usdValue.Add(usdPrice.Sub(usdPrice)))
	}
	return total
}

func WithDefault(balances []Balance, nativePrice decimal.Decimal, lookup func(string) decimal.Decimal) decimal.Decimal {
	total := decimal.Zero
	for _, b := range balances {
		usdValue := decimal.Zero
		switch {
		case b.Kind == "native":
			usdValue = b.Amount.Mul(nativePrice)
		case strings.EqualFold(b.Symbol, "USDC"):
			usdValue = b.Amount
		default:
			usdValue = b.Amount.Mul(lookup(b.Symbol))
		}
		total = total.Add(usdValue)
	}
	return total
}

func Discount(tier string, amount decimal.Decimal) decimal.Decimal {
	discount := decimal.Zero
	switch tier {
	case "gold":
		discount = amount.Div(decimal.NewFromInt(10))
	case "silver":
		discount = amount.Div(decimal.NewFromInt(20))
	}
	return amount.Sub(discount)
}
`,
	}))
}

// A zero passed for a parameter the callee returns as the answer of a case
// makes that case always answer zero.
func TestZeroArgumentAnsweredByCallee(t *testing.T) {
	assert.Equal(t, []string{"fees/fees.go:26"}, typedFuncFindings(t, NewZeroArgumentAnsweredByCalleeRule(), map[string]string{
		"fees/fees.go": `package fees

import "github.com/shopspring/decimal"

func basis(kind string, assets, committed, called decimal.Decimal) decimal.Decimal {
	switch kind {
	case "assets":
		return assets
	case "committed":
		return committed
	case "called":
		return called
	default:
		return assets
	}
}

func valueOr(v *decimal.Decimal, fallback decimal.Decimal) decimal.Decimal {
	if v == nil {
		return fallback
	}
	return *v
}

func Fee(kind string, assets decimal.Decimal, v *decimal.Decimal) decimal.Decimal {
	b := basis(kind, assets, decimal.Zero, decimal.Zero)
	return b.Add(valueOr(v, decimal.Zero))
}
`,
	}))
}

// One loop merges the colliding keys of one map and overwrites them in its
// sibling: the second entry of a key silently replaces the first.
func TestSiblingMapOverwritesOnCollision(t *testing.T) {
	assert.Equal(t, []string{"tokens/split.go:25"}, typedFuncFindings(t, NewSiblingMapOverwritesOnCollisionRule(), map[string]string{
		"tokens/split.go": `package tokens

import "github.com/shopspring/decimal"

type Token struct {
	Chain, Symbol, Protocol, Kind string
	Value                         decimal.Decimal
}

type key struct{ chain, symbol string }

func Split(items []Token) (map[key]Token, map[key]Token) {
	wallet := make(map[key]Token)
	protocol := make(map[key]Token)
	for _, t := range items {
		k := key{t.Chain, t.Symbol}
		if t.Kind == "wallet" {
			if existing, ok := wallet[k]; ok {
				t.Value = existing.Value.Add(t.Value)
			}
			wallet[k] = t
			continue
		}
		pk := key{t.Chain, t.Symbol + "@" + t.Protocol}
		protocol[pk] = t
	}
	return wallet, protocol
}

func Both(items []Token) (map[key]Token, map[key]Token) {
	wallet := make(map[key]Token)
	protocol := make(map[key]Token)
	for _, t := range items {
		k := key{t.Chain, t.Symbol}
		if existing, ok := wallet[k]; ok {
			t.Value = existing.Value.Add(t.Value)
		}
		wallet[k] = t
		if existing, ok := protocol[k]; ok {
			t.Value = existing.Value.Add(t.Value)
		}
		protocol[k] = t
	}
	return wallet, protocol
}
`,
	}))
}

// A decimal product carried through a loop without rounding grows its
// mantissa by every factor's digits: dozens of quotients make it hundreds of
// digits long, and every operation on it slows down.
func TestDecimalProductUnrounded(t *testing.T) {
	assert.Equal(t, []string{"growth/growth.go:12"}, typedFuncFindings(t, NewDecimalProductUnroundedRule(), map[string]string{
		"growth/growth.go": `package growth

import "github.com/shopspring/decimal"

type Step struct{ Start, End decimal.Decimal }

var one = decimal.NewFromInt(1)

func Compound(steps []Step) decimal.Decimal {
	growth := one
	for _, s := range steps {
		growth = growth.Mul(s.End.Div(s.Start))
	}
	return growth
}

func Rounded(steps []Step) decimal.Decimal {
	growth := one
	for _, s := range steps {
		growth = growth.Mul(s.End.Div(s.Start)).Round(18)
	}
	return growth
}

func Doubling(n int) decimal.Decimal {
	v := one
	for i := 0; i < n; i++ {
		v = v.Mul(decimal.NewFromInt(2))
	}
	return v
}

func Scale(d decimal.Decimal) decimal.Decimal {
	ten := decimal.NewFromInt(10)
	for d.LessThan(one) {
		d = d.Mul(ten)
	}
	return d
}
`,
	}))
}

// The position of an item in a provider's list is not its identity: when the
// list changes order, a key built from the ordinal moves stored history onto
// another item.
func TestOrdinalInPersistentKey(t *testing.T) {
	assert.Equal(t, []string{"provider/items.go:36"}, typedFuncFindings(t, NewOrdinalInPersistentKeyRule(), map[string]string{
		"provider/items.go": `package provider

import "fmt"

type Token struct {
	ID string ` + "`json:\"id\"`" + `
}

type Item struct {
	Name   string  ` + "`json:\"name\"`" + `
	Tokens []Token ` + "`json:\"tokens\"`" + `
}

type Protocol struct {
	ID    string ` + "`json:\"id\"`" + `
	Items []Item ` + "`json:\"items\"`" + `
}

func protocolTokens(p Protocol) []string {
	var ids []string
	for i := range p.Items {
		ids = append(ids, itemTokens(p.ID, i, &p.Items[i])...)
	}
	return ids
}

func itemTokens(protocolID string, itemIndex int, item *Item) []string {
	var ids []string
	for _, t := range item.Tokens {
		ids = append(ids, sourceID(protocolID, itemIndex, t))
	}
	return ids
}

func sourceID(protocolID string, itemIndex int, t Token) string {
	return fmt.Sprintf("p:%s:%d:%s", protocolID, itemIndex, t.ID)
}

func labels(names []string) []string {
	var out []string
	for i, n := range names {
		out = append(out, rowKey(i, n))
	}
	return out
}

func rowKey(index int, name string) string {
	return fmt.Sprintf("%d-%s", index, name)
}
`,
	}))
}

// A converter that takes the first movement of the wallet and breaks keeps one
// leg of a transaction that moved several coins.
func TestConverterKeepsFirstLeg(t *testing.T) {
	assert.Equal(t, []string{"chain/convert.go:25", "chain/convert.go:38"}, typedFuncFindings(t, NewConverterKeepsFirstLegRule(), map[string]string{
		"chain/convert.go": `package chain

import "github.com/shopspring/decimal"

type Change struct {
	Owner  string
	Coin   string
	Amount decimal.Decimal
}

type Block struct {
	Digest  string
	Changes []Change
}

type Tx struct {
	Hash   string
	Coin   string
	Amount decimal.Decimal
}

func Convert(wallet string, b *Block) *Tx {
	var amount decimal.Decimal
	var coin string
	for _, c := range b.Changes {
		if c.Owner == wallet {
			amount = c.Amount
			coin = c.Coin
			break
		}
	}
	return &Tx{Hash: b.Digest, Coin: coin, Amount: amount}
}

func ConvertSigned(wallet string, b *Block) *Tx {
	direction := "out"
	var amount decimal.Decimal
	for _, c := range b.Changes {
		if c.Owner == wallet {
			if c.Coin != "" {
				direction = "in"
			}
			amount = c.Amount
			break
		}
	}
	return &Tx{Hash: b.Digest, Coin: direction, Amount: amount}
}

func ConvertAll(wallet string, b *Block) []*Tx {
	var out []*Tx
	for _, c := range b.Changes {
		if c.Owner == wallet {
			out = append(out, &Tx{Hash: b.Digest, Coin: c.Coin, Amount: c.Amount})
		}
	}
	return out
}

func Owner(wallet string, b *Block) *Change {
	var found *Change
	for i := range b.Changes {
		if b.Changes[i].Owner == wallet {
			found = &b.Changes[i]
			break
		}
	}
	return found
}
`,
	}))
}
