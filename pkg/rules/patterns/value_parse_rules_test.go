package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// A comma deleted before parsing reads a comma-decimal "1,5" as 15; a space
// deleted is harmless, a parse of the raw text is the fix, and a number a
// regular expression scraped from a page comes in its source's one notation.
func TestDecimalInputSeparatorNormalizedByReplace(t *testing.T) {
	assert.Equal(t, []string{"upload/rows.go:13", "upload/rows.go:20"}, typedFuncFindings(t, NewDecimalInputSeparatorNormalizedByReplaceRule(), map[string]string{
		"upload/rows.go": `package upload

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/shopspring/decimal"
)

func rowAmount(fields map[string]string) (decimal.Decimal, error) {
	amountStr := fields["amount"]
	return decimal.NewFromString(strings.ReplaceAll(amountStr, ",", ""))
}

func cellAmount(cell string) (float64, error) {
	cleaned := strings.ReplaceAll(cell, " ", "")
	cleaned = strings.TrimSpace(cleaned)
	digits := cleaned
	digits = strings.Replace(digits, ".", "", -1)
	return strconv.ParseFloat(digits, 64)
}

func spaced(cell string) (decimal.Decimal, error) {
	return decimal.NewFromString(strings.ReplaceAll(cell, " ", ""))
}

func label(cell string) string {
	return strings.ReplaceAll(cell, ",", "")
}

func raw(cell string) (decimal.Decimal, error) {
	return decimal.NewFromString(cell)
}

var lastPrice = regexp.MustCompile("data-last=([0-9.,]+)")

func scraped(page string) (decimal.Decimal, error) {
	match := lastPrice.FindStringSubmatch(page)
	cleaned := strings.ReplaceAll(match[1], ",", "")
	return decimal.NewFromString(cleaned)
}
`,
	}))
}

// The head of a value cut at its first space is parsed and the tail dropped:
// "1 000.50" becomes 1. A function that checks the tail is not reported.
func TestParseTruncatesInputAtSeparator(t *testing.T) {
	assert.Equal(t, []string{"feed/values.go:15", "feed/values.go:23"}, typedFuncFindings(t, NewParseTruncatesInputAtSeparatorRule(), map[string]string{
		"feed/values.go": `package feed

import (
	"fmt"
	"strings"

	"github.com/shopspring/decimal"
)

func ParseOptional(value string) (*decimal.Decimal, error) {
	if value == "" {
		return nil, nil
	}
	if index := strings.IndexByte(value, ' '); index > 0 {
		value = value[:index]
	}
	parsed, err := decimal.NewFromString(value)
	return &parsed, err
}

func headOnly(value string) (decimal.Decimal, error) {
	i := strings.Index(value, ";")
	head := value[:i]
	return decimal.NewFromString(head)
}

func withUnit(value string) (decimal.Decimal, error) {
	index := strings.IndexByte(value, ' ')
	if index > 0 {
		if unit := value[index+1:]; unit != "USD" {
			return decimal.Zero, fmt.Errorf("unexpected %q", unit)
		}
		value = value[:index]
	}
	return decimal.NewFromString(value)
}

func name(value string) string {
	if i := strings.IndexByte(value, ' '); i > 0 {
		return value[:i]
	}
	return value
}
`,
	}))
}

// A rate decoded from a feed and stored without a positivity check reaches
// quotes as zero; a checked rate and a rate from a local computation are
// fine.
func TestExternalRateAcceptedWithoutPositivityCheck(t *testing.T) {
	assert.Equal(t, []string{"fx/feed.go:32"}, typedFuncFindings(t, NewExternalRateAcceptedWithoutPositivityCheckRule(), map[string]string{
		"fx/feed.go": `package fx

import (
	"encoding/xml"
	"io"
	"strings"

	"github.com/shopspring/decimal"
)

type entry struct {
	Code  string ` + "`xml:\"CharCode\"`" + `
	Value string ` + "`xml:\"Value\"`" + `
}

type doc struct {
	Entries []entry ` + "`xml:\"Valute\"`" + `
}

func fetch(body io.Reader) (map[string]decimal.Decimal, error) {
	var d doc
	if err := xml.NewDecoder(body).Decode(&d); err != nil {
		return nil, err
	}
	rates := make(map[string]decimal.Decimal)
	for _, v := range d.Entries {
		rateStr := strings.ReplaceAll(v.Value, ",", ".")
		rate, err := decimal.NewFromString(rateStr)
		if err != nil {
			continue
		}
		rates[v.Code] = rate
	}
	return rates, nil
}

func fetchChecked(d doc) map[string]decimal.Decimal {
	rates := make(map[string]decimal.Decimal)
	for _, v := range d.Entries {
		rate, err := decimal.NewFromString(v.Value)
		if err != nil || !rate.IsPositive() {
			continue
		}
		rates[v.Code] = rate
	}
	return rates
}

func local(text string) map[string]decimal.Decimal {
	rates := make(map[string]decimal.Decimal)
	rate, _ := decimal.NewFromString(text)
	rates["x"] = rate
	return rates
}
`,
	}))
}

// A setting read as == "true" turns TRUE or 1 into false; a value parsed by
// strconv.ParseBool or handled by a switch is fine.
func TestEnvBoolParsedByStringEquality(t *testing.T) {
	assert.Equal(t, []string{"config/load.go:16", "config/load.go:18", "config/load.go:19"}, typedFuncFindings(t, NewEnvBoolParsedByStringEqualityRule(), map[string]string{
		"config/load.go": `package config

import (
	"os"
	"strconv"
	"strings"
)

type Config struct {
	Admin, Debug, Mock, Strict, Mode bool
}

func Load() (*Config, error) {
	cfg := &Config{}
	if value := os.Getenv("ADMIN_ENABLED"); value != "" {
		cfg.Admin = value == "true"
	}
	cfg.Debug = os.Getenv("DEBUG") == "1"
	cfg.Mock = strings.EqualFold(os.Getenv("MOCK"), "true")
	strict, err := strconv.ParseBool(os.Getenv("STRICT"))
	if err != nil {
		return nil, err
	}
	cfg.Strict = strict
	switch mode := os.Getenv("MODE"); mode {
	case "true":
		cfg.Mode = true
	case "false", "":
	}
	region := os.Getenv("REGION")
	if region == "true" || region == "false" {
		cfg.Mode = region == "true"
	}
	return cfg, nil
}
`,
	}))
}

// A layout list holding 02/01/2006 and 01/02/2006 reads 03/04 by order; a
// list of unambiguous layouts is fine. A package-level list is out of reach
// of a function check.
func TestAmbiguousDateLayoutsFirstMatch(t *testing.T) {
	assert.Equal(t, []string{"rows/dates.go:12"}, typedFuncFindings(t, NewAmbiguousDateLayoutsFirstMatchRule(), map[string]string{
		"rows/dates.go": `package rows

import (
	"strings"
	"time"
)

func normalize(value string) string {
	if value == "" {
		return ""
	}
	for _, layout := range []string{"2006-01-02", "02.01.2006", "02/01/2006", "01/02/2006"} {
		if parsed, err := time.Parse(layout, strings.TrimSpace(value)); err == nil {
			return parsed.Format("2006-01-02")
		}
	}
	return value
}

func strict(value string) (time.Time, error) {
	for _, layout := range []string{"2006-01-02", "02.01.2006"} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed, nil
		}
	}
	return time.Time{}, nil
}

var layouts = []string{"01-02-2006", "02-01-2006"}

func pkgList(value string) time.Time {
	for _, layout := range layouts {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed
		}
	}
	return time.Time{}
}
`,
	}))
}

// The time of a provider's answer, when missing, is replaced with now; a
// field of a value the function built itself is not a provider's answer.
func TestMissingTimestampDefaultedToNow(t *testing.T) {
	assert.Equal(t, []string{"rates/convert.go:25"}, typedFuncFindings(t, NewMissingTimestampDefaultedToNowRule(), map[string]string{
		"rates/convert.go": `package rates

import "time"

type Response struct {
	Timestamp string
	Rate      float64
	Note      string
}

type Client struct{}

func (c *Client) Convert(from, to string) (*Response, error) { return &Response{}, nil }

type Handler struct{ client *Client }

type Event struct{ CreatedAt time.Time }

func (h *Handler) convert(from, to string) (*Response, error) {
	resp, err := h.client.Convert(from, to)
	if err != nil {
		return nil, err
	}
	if resp.Timestamp == "" {
		resp.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	if resp.Note == "" {
		resp.Note = time.Now().String()
	}
	return resp, nil
}

func newEvent(e Event) Event {
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now()
	}
	return e
}
`,
	}))
}

// A caller literal omits a field the constructor refuses when zero, or one
// the constructor copies over a pool default; the loader that sets every
// field is fine.
func TestConfigLiteralOmitsRequiredField(t *testing.T) {
	assert.Equal(t, []string{"cmd/seed/main.go:6", "cmd/tool/main.go:6"}, typedFuncFindings(t, NewConfigLiteralOmitsRequiredFieldRule(), map[string]string{
		"store/config.go": `package store

import (
	"errors"
	"time"
)

type Config struct {
	DSN      string
	MaxConns int
	Lifetime time.Duration
	Idle     time.Duration
}

type DB struct{}

func Open(cfg Config) (*DB, error) {
	if cfg.MaxConns <= 0 {
		return nil, errors.New("max conns must be positive")
	}
	if cfg.Lifetime <= 0 {
		return nil, errors.New("lifetime must be positive")
	}
	return &DB{}, nil
}

func Load() Config {
	return Config{DSN: "x", MaxConns: 4, Lifetime: time.Minute}
}
`,
		"cmd/seed/main.go": `package main

import "example.com/rulestest/store"

func main() {
	_, _ = store.Open(store.Config{
		DSN:      "x",
		MaxConns: 2,
	})
	_, _ = store.Open(store.Load())
}
`,
		"cmd/tool/main.go": `package main

import "example.com/rulestest/store"

func main() {
	_, _ = store.Open(store.Config{DSN: "x", Lifetime: 1})
}
`,
	}))
}
