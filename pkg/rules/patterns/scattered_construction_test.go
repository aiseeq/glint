package patterns

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules"
)

func scatteredServerFile(name string) string {
	return `package projecta

import (
	"net/http"
	"time"
)

func ` + name + `(h http.Handler) *http.Server {
	return &http.Server{Addr: ":80", Handler: h, ReadTimeout: time.Second}
}
`
}

// Every site of a scattered type is reported, whatever the order the files
// are seen in, with the project-relative path.
func TestScatteredConstructionReportsEverySite(t *testing.T) {
	rule := NewScatteredConstructionRule()
	_, isProjectRule := any(rule).(rules.GoProjectRule)
	require.True(t, isProjectRule, "sites are collected over the whole project before reporting")

	violations := runRuleOnFiles(t, rule, map[string]string{
		"srv/a.go": scatteredServerFile("serverA"),
		"srv/b.go": scatteredServerFile("serverB"),
		"srv/c.go": scatteredServerFile("serverC"),
	})

	require.Len(t, violations, 3)
	var files []string
	for _, v := range violations {
		files = append(files, v.File)
		assert.Equal(t, 9, v.Line)
		assert.Contains(t, v.Message, "http.Server constructed in 3 places")
	}
	assert.Equal(t, []string{"srv/a.go", "srv/b.go", "srv/c.go"}, files)
}

func TestScatteredConstructionBelowThreshold(t *testing.T) {
	violations := runRuleOnFiles(t, NewScatteredConstructionRule(), map[string]string{
		"srv/a.go": scatteredServerFile("serverA"),
		"srv/b.go": scatteredServerFile("serverB"),
	})
	assert.Empty(t, violations)
}

// Two runs of the same rule instance do not share sites.
func TestScatteredConstructionRunsAreIndependent(t *testing.T) {
	rule := NewScatteredConstructionRule()
	files := map[string]string{
		"srv/a.go": scatteredServerFile("serverA"),
		"srv/b.go": scatteredServerFile("serverB"),
	}
	assert.Empty(t, runRuleOnFiles(t, rule, files))
	assert.Empty(t, runRuleOnFiles(t, rule, files))
}

// Fixtures of a test-helper package (srvtest: the name ends in test, it imports
// testing) are test code like _test.go files: their literals are not
// construction sites of the program.
func TestScatteredConstructionSkipsTestHelperPackage(t *testing.T) {
	violations := runRuleOnFiles(t, NewScatteredConstructionRule(), map[string]string{
		"srv/a.go":              scatteredServerFile("serverA"),
		"srv/b.go":              scatteredServerFile("serverB"),
		"srv/srvtest/server.go": strings.Replace(scatteredServerFile("Server"), "package projecta", "package srvtest", 1),
		"srv/srvtest/t.go":      "package srvtest\n\nimport \"testing\"\n\nfunc Helper(t *testing.T) { t.Helper() }\n",
	})
	assert.Empty(t, violations)
}

const scatteredFilterModel = `package model

type PaymentFilter struct {
	WalletAddress *string
	Category   *string
	TxType        *string
	Limit         int
}

type Lookup struct {
	Wallet   *string
	Category *string
	Kind     *string
	Chain    *string
}

type Settlement struct {
	Wallet   string
	Category string
	Kind     string
}
`

// A filter or options struct names what each call asks for: every site sets
// its own fields and leaves the rest unset on purpose, so a new field is not
// silently missing anywhere. A struct whose fields are all optional (pointers)
// reads the same way. A filter built with one set of fields everywhere, and an
// ordinary struct, stay reported.
func TestScatteredConstructionSkipsPerCallFilters(t *testing.T) {
	use := func(name, lit string) string {
		return `package svc

import "example.com/rulestest/model"

func ` + name + `(w, c, k *string, n int) any {
	return ` + lit + `
}
`
	}
	t.Run("filter with different fields per call", func(t *testing.T) {
		violations := runRuleOnFiles(t, NewScatteredConstructionRule(), map[string]string{
			"model/model.go": scatteredFilterModel,
			"svc/a.go":       use("a", `&model.PaymentFilter{WalletAddress: w, Category: c, Limit: n}`),
			"svc/b.go":       use("b", `&model.PaymentFilter{WalletAddress: w, TxType: k, Limit: n}`),
			"svc/c.go":       use("c", `&model.PaymentFilter{Category: c, TxType: k, Limit: n}`),
		})
		assert.Empty(t, violations)
	})
	t.Run("all-optional struct with different fields per call", func(t *testing.T) {
		violations := runRuleOnFiles(t, NewScatteredConstructionRule(), map[string]string{
			"model/model.go": scatteredFilterModel,
			"svc/a.go":       use("a", `&model.Lookup{Wallet: w, Category: c, Kind: k}`),
			"svc/b.go":       use("b", `&model.Lookup{Wallet: w, Kind: k, Chain: c}`),
			"svc/c.go":       use("c", `model.Lookup{Category: c, Kind: k, Chain: w}`),
		})
		assert.Empty(t, violations)
	})
	t.Run("filter built with the same fields everywhere", func(t *testing.T) {
		violations := runRuleOnFiles(t, NewScatteredConstructionRule(), map[string]string{
			"model/model.go": scatteredFilterModel,
			"svc/a.go":       use("a", `&model.PaymentFilter{WalletAddress: w, Category: c, Limit: n}`),
			"svc/b.go":       use("b", `&model.PaymentFilter{WalletAddress: w, Category: c, Limit: n}`),
			"svc/c.go":       use("c", `&model.PaymentFilter{Category: c, WalletAddress: w, Limit: n}`),
		})
		assert.Len(t, violations, 3)
	})
	t.Run("ordinary struct with different fields per call", func(t *testing.T) {
		violations := runRuleOnFiles(t, NewScatteredConstructionRule(), map[string]string{
			"model/model.go": scatteredFilterModel,
			"svc/a.go":       use("a", `model.Settlement{Wallet: *w, Category: *c, Kind: "x"}`),
			"svc/b.go":       use("b", `model.Settlement{Wallet: *w, Kind: *k, Category: "y"}`),
			"svc/c.go":       use("c", `model.Settlement{Category: *c, Kind: *k, Wallet: "z"}`),
		})
		assert.Len(t, violations, 3)
	})
}
