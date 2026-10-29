package errrules

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
)

func TestPartialFlagUnread(t *testing.T) {
	assert.Equal(t, []string{"balance/calc.go:2", "balance/calc.go:3"}, rulestest.ProjectRulePlaces(t, NewPartialFlagUnreadRule(), map[string]string{
		"balance/types.go": `package balance
type Vault struct { Usd int; Incomplete bool }
type Breakdown struct { TotalUsd int; VaultIncomplete bool; Vault Vault }
func loadBreakdown() (Breakdown, error) { return Breakdown{}, nil }
func loadNested() (Breakdown, error) { return Breakdown{}, nil }
`,
		"balance/calc.go": `package balance
func total() (int, error) { b, err := loadBreakdown(); if err != nil { return 0, err }; return b.TotalUsd, nil }
func nested() int { b, _ := loadNested(); return b.Vault.Usd }
`,
	}))
}

func TestPartialFlagUnreadGenericResult(t *testing.T) {
	assert.Equal(t, []string{"handler/capital.go:15"}, rulestest.ProjectRulePlaces(t, NewPartialFlagUnreadRule(), map[string]string{
		"go.mod": "module example.com/genericflag\n\ngo 1.24\n",
		"model/breakdown.go": `package model

type Breakdown struct {
	TotalUsd       int
	VaultIncomplete bool
}
`,
		"cache/cache.go": `package cache

import "context"

type Cache[T any] struct{ value T }

func (c *Cache[T]) Get(context.Context) (T, error) { return c.value, nil }
`,
		"handler/capital.go": `package handler

import (
	"context"

	"example.com/genericflag/cache"
	"example.com/genericflag/model"
)

type Handler struct { cache *cache.Cache[*model.Breakdown] }

func (h *Handler) TotalCapital(ctx context.Context) (int, error) {
	b, err := h.cache.Get(ctx)
	if err != nil { return 0, err }
	return b.TotalUsd, nil
}
`,
	}))
}

func TestPartialFlagUnreadMissingListRead(t *testing.T) {
	assert.Empty(t, rulestest.ProjectRulePlaces(t, NewPartialFlagUnreadRule(), map[string]string{
		"result/types.go": `package result
type Valuation struct { TotalUsd int; Incomplete bool; MissingFeeds []string }
func load() Valuation { return Valuation{} }
`,
		"result/positions.go": `package result
func positions() int {
	v := load()
	warnings := make([]string, 0, len(v.MissingFeeds))
	for _, source := range v.MissingFeeds { warnings = append(warnings, "incomplete: "+source) }
	return len(warnings)
}
`,
	}))
}

func TestPartialFlagUnreadPrefixedFlagScope(t *testing.T) {
	assert.Equal(t, []string{"balance/calc.go:3", "balance/calc.go:4"}, rulestest.ProjectRulePlaces(t, NewPartialFlagUnreadRule(), map[string]string{
		"balance/types.go": `package balance
type Breakdown struct { TotalUsd, VaultUsd, CashUsd int; VaultIncomplete bool }
func load() Breakdown { return Breakdown{} }
`,
		"balance/calc.go": `package balance
func cash() int { b := load(); return b.CashUsd }
func total() int { b := load(); return b.TotalUsd }
func vault() int { b := load(); return b.VaultUsd }
`,
	}))
}

func TestPartialFlagUnreadNegatives(t *testing.T) {
	assert.Empty(t, rulestest.ProjectRulePlaces(t, NewPartialFlagUnreadRule(), map[string]string{
		"balance/types.go": `package balance
type Breakdown struct { TotalUsd int; VaultIncomplete bool }
type State struct { Incomplete bool }
type Builder struct { state State; Output int }
func loadBreakdown() (Breakdown, error) { return Breakdown{}, nil }
func loadBuilder() Builder { return Builder{} }
func NewBreakdown() Breakdown { b, _ := loadBreakdown(); b.VaultIncomplete = false; return b }
`,
		"balance/calc.go": `package balance
func checked() (int, error) { b, err := loadBreakdown(); if err != nil { return 0, err }; if b.VaultIncomplete { return 0, nil }; return b.TotalUsd, nil }
func passed() { b, _ := loadBreakdown(); consume(b) }
func returned() (Breakdown, error) { b, err := loadBreakdown(); return b, err }
func parameter(b Breakdown) int { return b.TotalUsd }
func (b Breakdown) Total() int { return b.TotalUsd }
func consume(Breakdown) {}
func unrelatedNestedState() int { b := loadBuilder(); return b.Output }
`,
	}))
}

func TestPartialFlagUnread_Metadata(t *testing.T) {
	rule := NewPartialFlagUnreadRule()
	assert.Equal(t, "partial-flag-unread", rule.Name())
	assert.Equal(t, core.SeverityHigh, rule.DefaultSeverity())
}
