package patterns

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
)

func TestTombstoneCommentRule(t *testing.T) {
	rule := NewTombstoneCommentRule()

	tests := []struct {
		name      string
		filename  string
		code      string
		wantCount int
	}{
		{
			name:     "removed function tombstone",
			filename: "handler.go",
			code: `package routing

// GetDB removed — architectural boundary violation eliminated
func other() {}
`,
			wantCount: 1,
		},
		{
			name:     "russian tombstone with colon",
			filename: "labels.ts",
			code: `// УДАЛЕНО: processed статус (дубликат approved)
export const x = 1
`,
			wantCount: 1,
		},
		{
			name:     "russian tombstone lowercase",
			filename: "service.go",
			code: `package svc

// Удалён dead field balanceRepo
type Service struct{}
`,
			wantCount: 1,
		},
		{
			name:     "removed with count",
			filename: "repo.go",
			code: `package repo

// SIMPLIFIED: Removed 38 stub methods that returned "not implemented"
type Repo struct{}
`,
			wantCount: 1,
		},
		{
			name:     "trailing tombstone after dead assignment",
			filename: "config.go",
			code: `package config

func f(disableFixes bool) {
	_ = disableFixes // Crypto2B fixes removed
}
`,
			wantCount: 1,
		},
		{
			name:     "no longer used tombstone",
			filename: "helpers.go",
			code: `package svc

// Removed canonicalUserService parameter (was unused)
func helper() {}
`,
			wantCount: 1,
		},
		{
			name:     "behavior description is not a tombstone",
			filename: "cache.go",
			code: `package cache

// Entries are removed from the cache after TTL expires.
func (c *Cache) sweep() {}

// Stale sessions will be removed by the janitor goroutine.
func (c *Cache) janitor() {}

// The item gets removed when the user confirms deletion.
func (c *Cache) confirm() {}
`,
			wantCount: 0,
		},
		{
			name:     "russian behavior description is not a tombstone",
			filename: "session.go",
			code: `package session

// Старые сессии будут удалены фоновой задачей.
func cleanup() {}

// Записи удаляются по расписанию.
func schedule() {}
`,
			wantCount: 0,
		},
		{
			name:     "policy quote is not a tombstone",
			filename: "linter.go",
			code: `package rules

// CLAUDE.md: deprecated aliases must be removed immediately, never created.
func check() {}
`,
			wantCount: 0,
		},
		{
			name:     "deprecated marker is deprecated-comment territory",
			filename: "api.go",
			code: `package api

// Deprecated: use NewHandler instead; this alias will be removed in v5.
func OldHandler() {}
`,
			wantCount: 0,
		},
		{
			name:     "code that calls remove is not a comment",
			filename: "list.go",
			code: `package list

func f() {
	removed := list.Remove(el)
	_ = removed
}
`,
			wantCount: 0,
		},
		{
			name:     "data-flow and state-machine docs are not tombstones",
			filename: "capital.go",
			code: `package svc

// WithdrawalPipelineCapital returns principal removed from user investments.
func capital() {}

// deleted -> * (удаленные пользователи нельзя восстановить)
func transitions() {}

// Исключаем soft deleted транзакции
func filter() {}

// что удалено: {"wallets": 2, "user": 1}
func counts() {}
`,
			wantCount: 0,
		},
		{
			name:     "test files are skipped",
			filename: "handler_test.go",
			code: `package routing

// GetDB removed — check the new path
func TestX(t *testing.T) {}
`,
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := core.NewFileContext(tt.filename, ".", []byte(tt.code), nil)
			violations := rule.AnalyzeFile(ctx)
			if len(violations) != tt.wantCount {
				t.Errorf("got %d violations, want %d; violations: %+v",
					len(violations), tt.wantCount, violations)
			}
		})
	}
}

// Репро аудита 2026-07-02: реальные frontend-надгробия, пропущенные правилом
// (вычищены вручную в saga@8f7c1a6bd).
func TestTombstoneComment_RussianColonAndDashForms(t *testing.T) {
	rule := NewTombstoneCommentRule()
	code := `const LABEL_MAPPINGS = {
  // УДАЛЕНО: investmentStatuses теперь используется из централизованного модуля investment-status-validation.ts
  transactionStatuses: {},
  // networks: УДАЛЕНО - используйте getNetworkName из @shared/config/networks
  currencies: {},
}
`
	ctx := core.NewFileContext("frontend/shared/lib/label-utils.ts", ".", []byte(code), nil)
	violations := rule.AnalyzeFile(ctx)
	if len(violations) != 2 {
		t.Fatalf("want 2 violations (оба «УДАЛЕНО»-надгробия), got %d: %+v", len(violations), violations)
	}
}

// «если он был удалён cleanup-системой» — описание условия/поведения, не надгробие.
func TestTombstoneComment_PastConditionIsBehavior(t *testing.T) {
	rule := NewTombstoneCommentRule()
	code := `// Создаём пользователя заново если он был удалён cleanup системой
export const ensureUser = 1
`
	ctx := core.NewFileContext("e2e/utils/real-auth-helpers.ts", ".", []byte(code), nil)
	violations := rule.AnalyzeFile(ctx)
	if len(violations) != 0 {
		t.Fatalf("past-condition behavior must not be flagged, got: %+v", violations)
	}
}
