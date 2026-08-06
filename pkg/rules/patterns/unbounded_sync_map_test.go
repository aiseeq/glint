package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

func TestUnboundedSyncMapRule_Metadata(t *testing.T) {
	rule := NewUnboundedSyncMapRule()
	assert.Equal(t, "unbounded-sync-map", rule.Name())
	assert.Equal(t, "patterns", rule.Category())
	assert.Equal(t, core.SeverityMedium, rule.DefaultSeverity())
	assert.False(t, rule.RequiresSSA())
}

// Репро с ревью projectD 2026-08 (№22): пакетные sync.Map доменных расписаний и
// robots.txt росли неограниченно — Store на каждый новый домен, Delete нет
// нигде в пакете. За месяцы работы демона набор доменов только растёт.
func TestUnboundedSyncMapRule_Detection(t *testing.T) {
	tests := []struct {
		name    string
		files   map[string]string
		expects []string
	}{
		{
			name: "package-level sync.Map with Store and no Delete",
			files: map[string]string{
				"cache/cache.go": `package cache

import "sync"

var domainSchedules sync.Map

// Register запоминает расписание домена
func Register(domain string, value int) {
	domainSchedules.Store(domain, value)
}

// Get возвращает расписание
func Get(domain string) (any, bool) {
	return domainSchedules.Load(domain)
}
`,
			},
			expects: []string{"domainSchedules"},
		},
		{
			name: "LoadOrStore also grows the map",
			files: map[string]string{
				"cache/cache.go": `package cache

import "sync"

var states sync.Map

// State отдаёт состояние домена
func State(key string) any {
	value, _ := states.LoadOrStore(key, struct{}{})
	return value
}
`,
			},
			expects: []string{"states"},
		},
		{
			name: "Delete in another file of the package makes it bounded",
			files: map[string]string{
				"cache/cache.go": `package cache

import "sync"

var schedules sync.Map

// Register запоминает расписание
func Register(key string, value int) { schedules.Store(key, value) }
`,
				"cache/sweep.go": `package cache

// Sweep вытесняет устаревшие записи
func Sweep(cutoff int64) {
	schedules.Range(func(key, value any) bool {
		schedules.Delete(key)
		return true
	})
}
`,
			},
		},
		{
			name: "Delete only in tests does not bound production growth",
			files: map[string]string{
				"cache/cache.go": `package cache

import "sync"

var schedules sync.Map

// Register запоминает расписание
func Register(key string, value int) { schedules.Store(key, value) }
`,
				"cache/cache_test.go": `package cache

import "testing"

func TestRegister(t *testing.T) {
	Register("a", 1)
	schedules.Delete("a")
}
`,
			},
			expects: []string{"schedules"},
		},
		{
			name: "local sync.Map is scoped by its function lifetime",
			files: map[string]string{
				"cache/cache.go": `package cache

import "sync"

// Collect собирает значения в локальную карту
func Collect(keys []string) int {
	var seen sync.Map
	for _, key := range keys {
		seen.Store(key, struct{}{})
	}
	count := 0
	seen.Range(func(_, _ any) bool { count++; return true })
	return count
}
`,
			},
		},
		{
			name: "read-only package sync.Map does not grow",
			files: map[string]string{
				"cache/cache.go": `package cache

import "sync"

var lookups sync.Map

// Lookup читает без записи
func Lookup(key string) (any, bool) { return lookups.Load(key) }
`,
			},
		},
		{
			name: "map escaping by pointer is left alone",
			files: map[string]string{
				"cache/cache.go": `package cache

import "sync"

var shared sync.Map

// Register запоминает значение
func Register(key string, value int) { shared.Store(key, value) }

// Expose отдаёт карту наружу — судьбу записей отсюда не видно
func Expose() *sync.Map { return &shared }
`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := map[string]string{"go.mod": "module example.com/rulestest\n\ngo 1.24\n"}
			for name, source := range tt.files {
				files[name] = source
			}
			violations, err := NewUnboundedSyncMapRule().AnalyzeGoProject(rulestest.Project(t, files))
			require.NoError(t, err)

			var got []string
			for _, v := range violations {
				name, ok := v.Context["variable"].(string)
				require.True(t, ok, "context variable must be a string")
				got = append(got, name)
			}
			assert.ElementsMatch(t, tt.expects, got)
		})
	}
}
