package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// The rate is computed by a switch on the source, and the cache key leaves
// the source out; a key that carries it, a branch on a key part and a check
// that only refuses are fine.
func TestCacheKeyMissingDiscriminator(t *testing.T) {
	assert.Equal(t, []string{"fx/rate.go:27"}, typedFuncFindings(t, NewCacheKeyMissingDiscriminatorRule(), map[string]string{
		"fx/rate.go": `package fx

type Source string

type Cache struct{}

func (c *Cache) Get(pair, country string) (*float64, error)         { return nil, nil }
func (c *Cache) Upsert(pair, country string, rate float64) error    { return nil }
func (c *Cache) GetFor(pair, source string) (*float64, error)       { return nil, nil }
func (c *Cache) UpsertFor(pair, source string, rate float64) error { return nil }

type Service struct {
	fxCache *Cache
	sourceA func(string) float64
	sourceB func(string) float64
}

func (s *Service) rate(pair, country string, project Source) (float64, error) {
	source := Source("a")
	if project != "" {
		source = project
	}
	if cached, err := s.fxCache.Get(pair, country); err == nil && cached != nil {
		return *cached, nil
	}
	var rate float64
	switch source {
	case "b":
		rate = s.sourceB(pair)
	default:
		rate = s.sourceA(pair)
	}
	_ = s.fxCache.Upsert(pair, country, rate)
	return rate, nil
}

func (s *Service) keyed(pair string, source Source) (float64, error) {
	if cached, err := s.fxCache.GetFor(pair, string(source)); err == nil && cached != nil {
		return *cached, nil
	}
	var rate float64
	switch source {
	case "b":
		rate = s.sourceB(pair)
	default:
		rate = s.sourceA(pair)
	}
	_ = s.fxCache.UpsertFor(pair, string(source), rate)
	return rate, nil
}

func (s *Service) byCountry(pair, country string) (float64, error) {
	if cached, err := s.fxCache.Get(pair, country); err == nil && cached != nil {
		return *cached, nil
	}
	rate := s.sourceA(pair)
	if country == "X" {
		rate = s.sourceB(pair)
	}
	_ = s.fxCache.Upsert(pair, country, rate)
	return rate, nil
}

func (s *Service) checked(pair, country string, rates []float64) (float64, error) {
	if cached, err := s.fxCache.Get(pair, country); err == nil && cached != nil {
		return *cached, nil
	}
	count := len(rates)
	if count != 1 {
		return 0, nil
	}
	_ = s.fxCache.Upsert(pair, country, rates[0])
	return rates[0], nil
}
`,
	}))
}

// One package joins the currency fields with "/" twice and with ":" once:
// the odd one out is reported, a log line is not.
func TestCompositeKeySeparatorMismatch(t *testing.T) {
	assert.Equal(t, []string{"orders/keys.go:17"}, typedFuncFindings(t, NewCompositeKeySeparatorMismatchRule(), map[string]string{
		"orders/keys.go": `package orders

import "log/slog"

type Tx struct{ From, To, Country string }

func pair(tx *Tx) string {
	return tx.From + "/" + tx.To
}

func other(t Tx) string {
	return t.From + "/" + t.To
}

func cacheKey(tx *Tx, logger *slog.Logger) string {
	logger.Info("rate", "pair", tx.From+"-"+tx.To)
	return tx.From + ":" + tx.To
}

func place(tx *Tx) string {
	return tx.Country + ":" + tx.To
}
`,
	}))
}

// Bank lists are fetched per country, method and kind but kept and skipped
// by country alone; a store under the whole key is fine.
func TestCacheKeyCoarserThanFetchKey(t *testing.T) {
	assert.Equal(t, []string{"forms/banks.go:16"}, typedFuncFindings(t, NewCacheKeyCoarserThanFetchKeyRule(), map[string]string{
		"forms/banks.go": `package forms

type key struct {
	country, method, kind string
}

type Client struct{}

func (c *Client) Banks(country, method, kind string) ([]string, error) { return nil, nil }

type Admin struct{ client *Client }

func (a *Admin) banks(seen map[key]bool) map[string][]string {
	result := make(map[string][]string)
	for k := range seen {
		if _, ok := result[k.country]; ok {
			continue
		}
		banks, err := a.client.Banks(k.country, k.method, k.kind)
		if err != nil {
			continue
		}
		result[k.country] = banks
	}
	return result
}

func (a *Admin) exact(seen map[key]bool) map[key][]string {
	result := make(map[key][]string)
	for k := range seen {
		banks, err := a.client.Banks(k.country, k.method, k.kind)
		if err != nil {
			continue
		}
		result[k] = banks
	}
	return result
}

func (a *Admin) perCountry(seen map[key]bool) map[string][]string {
	result := make(map[string][]string)
	for k := range seen {
		banks, err := a.client.Banks(k.country, "", "")
		if err != nil {
			continue
		}
		result[k.country] = banks
	}
	return result
}
`,
	}))
}

// A containment match on the option's name returns the first option that
// fits; an exact match and a match that refuses a second fit are fine.
func TestFuzzyMatchReturnsFirstCandidate(t *testing.T) {
	assert.Equal(t, []string{"banks/resolve.go:18", "banks/resolve.go:36"}, typedFuncFindings(t, NewFuzzyMatchReturnsFirstCandidateRule(), map[string]string{
		"banks/resolve.go": `package banks

import "strings"

type Option struct{ ID, Name string }

func normalize(s string) string { return strings.ToLower(s) }

func Resolve(name string, opts []Option) (string, bool) {
	target := normalize(name)
	for _, o := range opts {
		if normalize(o.Name) == target {
			return o.ID, true
		}
	}
	for _, o := range opts {
		n := normalize(o.Name)
		if n != "" && (strings.Contains(n, target) || strings.Contains(target, n)) {
			return o.ID, true
		}
	}
	return "", false
}

func Unique(name string, opts []Option) (string, bool) {
	match := ""
	for _, o := range opts {
		if strings.Contains(normalize(o.Name), name) {
			if match != "" {
				return "", false
			}
			match = o.ID
		}
	}
	for _, o := range opts {
		if strings.HasPrefix(o.Name, name) {
			return o.ID, true
		}
	}
	return match, match != ""
}

func Allowed(path string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}
`,
	}))
}

// The pair's rate is parsed and refused before the pair is compared with
// the wanted one: a broken rate of another pair fails the lookup. The
// fixed order and a function not called per element are fine.
func TestLookupValidatesBeforeMatchFilter(t *testing.T) {
	assert.Equal(t, []string{"fx/pairs.go:24"}, typedFuncFindings(t, NewLookupValidatesBeforeMatchFilterRule(), map[string]string{
		"fx/pairs.go": `package fx

import (
	"fmt"
	"strings"

	"github.com/shopspring/decimal"
)

type Rate struct{ Pair, Value string }

func pairRate(pair, value, from, to string) (decimal.Decimal, bool, error) {
	parts := strings.Split(pair, "/")
	if len(parts) != 2 {
		return decimal.Decimal{}, false, nil
	}
	rate, err := decimal.NewFromString(value)
	if err != nil {
		return decimal.Decimal{}, false, fmt.Errorf("parse %q: %w", value, err)
	}
	if rate.IsZero() {
		return decimal.Decimal{}, false, fmt.Errorf("zero rate %q", pair)
	}
	if strings.EqualFold(parts[0], from) && strings.EqualFold(parts[1], to) {
		return rate, true, nil
	}
	return decimal.Decimal{}, false, nil
}

func matchFirst(pair, value, from, to string) (decimal.Decimal, bool, error) {
	parts := strings.Split(pair, "/")
	if len(parts) != 2 || !strings.EqualFold(parts[0], from) || !strings.EqualFold(parts[1], to) {
		return decimal.Decimal{}, false, nil
	}
	rate, err := decimal.NewFromString(value)
	if err != nil {
		return decimal.Decimal{}, false, fmt.Errorf("parse %q: %w", value, err)
	}
	return rate, true, nil
}

func single(value, from string) (decimal.Decimal, bool, error) {
	rate, err := decimal.NewFromString(value)
	if err != nil {
		return decimal.Decimal{}, false, err
	}
	if from == "x" {
		return rate, true, nil
	}
	return decimal.Decimal{}, false, nil
}

func Find(rates []Rate, from, to string) (decimal.Decimal, error) {
	_, _, _ = single("1", from)
	for _, r := range rates {
		rate, ok, err := pairRate(r.Pair, r.Value, from, to)
		if err != nil {
			return decimal.Decimal{}, err
		}
		if ok {
			return rate, nil
		}
		if rate, ok, err = matchFirst(r.Pair, r.Value, from, to); ok && err == nil {
			return rate, nil
		}
	}
	return decimal.Decimal{}, fmt.Errorf("not found")
}
`,
	}))
}

// Two fields of one form group share a label; the same label in another
// group's list and distinct labels are fine.
func TestDuplicateKeyInDefinitionList(t *testing.T) {
	assert.Equal(t, []string{"forms/fields.go:14"}, deployFindings(t, "duplicate-key-in-definition-list", map[string]string{
		"forms/fields.go": `package forms

type Field struct{ Label, Name string }

type Group struct {
	Title  string
	Fields []Field
}

var india = []Group{
	{Title: "Receiver", Fields: []Field{
		{Label: "Account Number", Name: "accountNumber"},
		{Label: "Bank Branch Code", Name: "corporateBranchCode"},
		{Label: "Bank Branch Code", Name: "branchCode"},
	}},
	{Title: "Sender", Fields: []Field{
		{Label: "Bank Branch Code", Name: "senderBranchCode"},
	}},
}
`,
		"forms/fields_test.go": `package forms

var cases = []Field{{Name: "a"}, {Name: "a"}}
`,
	}))
}

// The template is dropped and created under a fixed name behind a
// sync.Once only; a helper holding an advisory lock is fine.
func TestTestSharedDBRecreatedWithoutCrossProcessLock(t *testing.T) {
	assert.Equal(t, []string{"testdb/testdb.go:23"}, deployFindings(t, "test-shared-db-recreated-without-cross-process-lock", map[string]string{
		"testdb/testdb.go": `package testdb

import (
	"database/sql"
	"fmt"
	"sync"
	"testing"
)

const templateName = "app_test_template"

var once sync.Once

func Template(t *testing.T, db *sql.DB) {
	once.Do(func() {
		if err := create(db); err != nil {
			t.Fatal(err)
		}
	})
}

func create(db *sql.DB) error {
	if _, err := db.Exec(fmt.Sprintf("DROP DATABASE IF EXISTS %s", templateName)); err != nil {
		return err
	}
	_, err := db.Exec(fmt.Sprintf("CREATE DATABASE %s TEMPLATE %s", templateName, "app"))
	return err
}
`,
		"locked/testdb.go": `package locked

import (
	"database/sql"
	"fmt"
	"testing"
)

const templateName = "app_test_template"

func Template(t *testing.T, db *sql.DB) {
	db.Exec("SELECT pg_advisory_lock(1)")
	db.Exec(fmt.Sprintf("DROP DATABASE IF EXISTS %s", templateName))
	db.Exec(fmt.Sprintf("CREATE DATABASE %s TEMPLATE %s", templateName, "app"))
}
`,
	}))
}
