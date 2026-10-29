package errrules

import (
	"fmt"
	"go/token"
	"go/types"
	"testing"
	"time"

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

func TestPartialFlagUnreadBudgetNotSet(t *testing.T) {
	assert.Equal(t, []string{"history/limited.go:3", "history/unconditional.go:3"}, rulestest.ProjectRulePlaces(t, NewPartialFlagUnreadRule(), map[string]string{
		"go.mod": "module example.com/budgetflag\n\ngo 1.24\n",
		"history/types.go": `package history

import (
	"context"
	"time"
)

type Range struct { Since time.Time; Pages int }
type Message struct{}
type Chunk struct { Messages []Message; Partial bool }
type Service struct{}

func (s *Service) Fetch(ctx context.Context, r Range) (Chunk, error) {
	var c Chunk
	for page := 0; ; page++ {
		if r.Pages > 0 && page == r.Pages { c.Partial = true; break }
		if page == 100 { return Chunk{}, nil }
	}
	return c, nil
}
func (s *Service) FetchUnconditional(ctx context.Context, r Range) (Chunk, error) {
	var c Chunk
	c.Partial = true
	return c, nil
}
`,
		"history/omitted.go": `package history
import ("context"; "time")
func omitted(s *Service, ctx context.Context, since time.Time) ([]Message, error) { c, err := s.Fetch(ctx, Range{Since: since}); if err != nil { return nil, err }; return c.Messages, err }
`,
		"history/limited.go": `package history
import ("context"; "time")
func limited(s *Service, ctx context.Context, since time.Time, n int) ([]Message, error) { c, err := s.Fetch(ctx, Range{Since: since, Pages: n}); if err != nil { return nil, err }; return c.Messages, err }
`,
		"history/unconditional.go": `package history
import ("context"; "time")
func unconditional(s *Service, ctx context.Context, since time.Time) ([]Message, error) { c, err := s.FetchUnconditional(ctx, Range{Since: since}); if err != nil { return nil, err }; return c.Messages, err }
`,
		// The literal of a caller in another package is typed by its own package.
		"client/client.go": `package client
import ("context"; "time"; "example.com/budgetflag/history")
func Recent(s *history.Service, ctx context.Context, since time.Time) ([]history.Message, error) { c, err := s.Fetch(ctx, history.Range{Since: since}); if err != nil { return nil, err }; return c.Messages, err }
`,
	}))
}

func TestPartialFlagUnreadSeveralResults(t *testing.T) {
	assert.Equal(t, []string{"result/use.go:5", "result/use.go:6"}, rulestest.ProjectRulePlaces(t, NewPartialFlagUnreadRule(), map[string]string{
		"result/types.go": `package result
type Result struct { Total int; Incomplete bool }
func load() Result { return Result{} }
`,
		"result/use.go": `package result
func totals() int {
	a := load()
	b := load()
	_ = a.Total
	_ = b.Total
	return 0
}
`,
	}))
}

func TestPartialFlagUnreadPerFlag(t *testing.T) {
	assert.Equal(t, []string{"result/use.go:2"}, rulestest.ProjectRulePlaces(t, NewPartialFlagUnreadRule(), map[string]string{
		"result/types.go": `package result
type Mixed struct { FirstIncomplete bool; FirstTotal int; SecondIncomplete bool; SecondTotal int }
func loadMixed() Mixed { return Mixed{} }
`,
		"result/use.go": `package result
func incomplete() int { x := loadMixed(); _ = x.FirstIncomplete; return x.SecondTotal }
func firstComplete() int { x := loadMixed(); _ = x.FirstIncomplete; return x.FirstTotal }
`,
	}))
}

func TestPartialFlagUnreadPerFlagLaterRead(t *testing.T) {
	assert.Equal(t, []string{"result/use.go:5"}, rulestest.ProjectRulePlaces(t, NewPartialFlagUnreadRule(), map[string]string{
		"result/types.go": `package result
type Mixed struct { FirstIncomplete bool; FirstTotal int; SecondIncomplete bool; SecondTotal int }
func loadMixed() Mixed { return Mixed{} }
`,
		"result/use.go": `package result
func both() int {
	x := loadMixed()
	_ = x.FirstIncomplete
	return x.FirstTotal + x.SecondTotal
}
`,
	}))
}

func TestPartialFlagUnreadCyclicTypeCache(t *testing.T) {
	assert.Equal(t, []string{"cycle/use.go:5", "cycle/use.go:6"}, rulestest.ProjectRulePlaces(t, NewPartialFlagUnreadRule(), map[string]string{
		"cycle/types.go": `package cycle
type A struct { Next *B; Total int; Incomplete bool }
type B struct { Back *A; Count int }
func loadA() *A { return &A{} }
func loadB() *B { return &B{} }
`,
		"cycle/use.go": `package cycle
func use() int {
	a := loadA()
	b := loadB()
	_ = a.Total
	return b.Back.Total
}
`,
	}))
	pkg := types.NewPackage("example.com/cycle", "cycle")
	a := types.NewNamed(types.NewTypeName(token.NoPos, pkg, "A", nil), types.NewStruct(nil, nil), nil)
	b := types.NewNamed(types.NewTypeName(token.NoPos, pkg, "B", nil), types.NewStruct(nil, nil), nil)
	aPointer, bPointer := types.NewPointer(a), types.NewPointer(b)
	a.SetUnderlying(types.NewStruct([]*types.Var{
		types.NewField(token.NoPos, pkg, "Next", bPointer, false),
		types.NewField(token.NoPos, pkg, "Total", types.Typ[types.Int], false),
		types.NewField(token.NoPos, pkg, "Incomplete", types.Typ[types.Bool], false),
	}, nil))
	b.SetUnderlying(types.NewStruct([]*types.Var{
		types.NewField(token.NoPos, pkg, "Back", aPointer, false),
		types.NewField(token.NoPos, pkg, "Count", types.Typ[types.Int], false),
	}, nil))
	cache := make(map[types.Type]bool)
	assert.True(t, containsPartialFlag(aPointer, cache, make(map[types.Type]bool)))
	assert.True(t, containsPartialFlag(bPointer, cache, make(map[types.Type]bool)))
}

func TestPartialFlagUnreadDeepNestedType(t *testing.T) {
	pkg := types.NewPackage("example.com/result", "result")
	typeAtDepth := make([]types.Type, 26)
	base := types.NewStruct([]*types.Var{
		types.NewField(token.NoPos, pkg, "Incomplete", types.Typ[types.Bool], false),
		types.NewField(token.NoPos, pkg, "Total", types.Typ[types.Int], false),
	}, nil)
	typeAtDepth[0] = types.NewNamed(types.NewTypeName(token.NoPos, pkg, "T0", nil), base, nil)
	for depth := 1; depth <= 25; depth++ {
		fields := []*types.Var{
			types.NewField(token.NoPos, pkg, "A", typeAtDepth[depth-1], false),
			types.NewField(token.NoPos, pkg, "B", typeAtDepth[depth-1], false),
		}
		structure := types.NewStruct(fields, nil)
		name := fmt.Sprintf("T%d", depth)
		typeAtDepth[depth] = types.NewNamed(types.NewTypeName(token.NoPos, pkg, name, nil), structure, nil)
	}

	root := typeAtDepth[25]
	var path []*types.Var
	current := root
	for range 25 {
		field := structType(current).Field(0)
		path = append(path, field)
		current = field.Type()
	}

	started := time.Now()
	if !containsPartialFlag(root, make(map[types.Type]bool), make(map[types.Type]bool)) {
		t.Fatal("deep type should contain a partial flag")
	}
	flags := partialFlagsAlongPath(root, path)
	if len(flags) != 1 || flags[0].field.Name() != "Incomplete" || !partialFieldMatchesPrefix("Total", flags[0].prefix) {
		t.Fatalf("deep selector path did not resolve its flag: %#v", flags)
	}
	assert.Less(t, time.Since(started), time.Second)
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
