package patterns

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
)

// Класс, вскрытый ревью projectA (REF-487): Go-тесты, которые «документируют»
// поведение через t.Logf и не могут упасть никогда. Пять функций в
// safe_decimal_security_test.go годами числились зелёным покрытием и печатали
// «⚠️ VULNERABILITY: no overflow detection», ничего не проверяя.
// unfalsifiable-test-case это не ловил: он работает только по TS/JS и требует
// хотя бы одной ассерции, а здесь их ноль.
func TestTestWithoutAssertionRule(t *testing.T) {
	tests := []struct {
		name      string
		code      string
		wantCount int
	}{
		{
			name: "test only logs and never asserts",
			code: `package models

import "testing"

func TestOverflowProtection(t *testing.T) {
	result := maxInt64.Mul(million)
	t.Logf("Result: %s", result.String())
	t.Logf("VULNERABILITY: No overflow detection on Mul()")
}
`,
			wantCount: 1,
		},
		{
			name: "require assertion present",
			code: `package models

import "testing"

func TestMul(t *testing.T) {
	result := maxInt64.Mul(million)
	require.Equal(t, "42", result.String())
}
`,
			wantCount: 0,
		},
		{
			name: "t.Fatalf counts as an assertion",
			code: `package models

import "testing"

func TestLoad(t *testing.T) {
	got, err := load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	t.Logf("loaded %v", got)
}
`,
			wantCount: 0,
		},
		{
			name: "assertions delegated to a helper receiving t",
			code: `package models

import "testing"

func TestBalance(t *testing.T) {
	db := setupIsolatedDB(t)
	assertBalanceMatches(t, db, "750")
}
`,
			wantCount: 0,
		},
		{
			name: "assertions inside subtest closure",
			code: `package models

import "testing"

func TestGroups(t *testing.T) {
	t.Run("zero", func(t *testing.T) {
		require.True(t, value.IsZero())
	})
}
`,
			wantCount: 0,
		},
		{
			name: "subtest that only logs is still unfalsifiable",
			code: `package models

import "testing"

func TestGroups(t *testing.T) {
	t.Run("documented vulnerability", func(t *testing.T) {
		t.Logf("no validation here")
	})
}
`,
			wantCount: 1,
		},
		{
			// Тест падает, если код паникует, — он фальсифицируем, просто без
			// явного ассерта. Репро: safego_test.go в projectA ловит панику в
			// горутине, где require.NotPanics неприменим.
			name: "smoke call without logs is a panic check, not a stub",
			code: `package models

import "testing"

func TestGo_PanicDoesNotEscapeGoroutine(t *testing.T) {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		Run("escaping-task", nil, func() { panic("must not crash") })
	}()
	wg.Wait()
}
`,
			wantCount: 0,
		},
		{
			// Проверка соответствия интерфейсу выполняется компилятором: тест
			// «падает» несобираемостью пакета. Репро: adapter_batch_check_test.go.
			name: "compile-time interface assertion is enforced by the compiler",
			code: `package models

import "testing"

func TestAdapter_HasGetUsersByIDs(t *testing.T) {
	var _ batchUsersByIDsCheck = (*repository.UserDomainRepositoryAdapter)(nil)
}
`,
			wantCount: 0,
		},
		{
			name: "skipped test is out of scope",
			code: `package models

import "testing"

func TestPending(t *testing.T) {
	t.Skip("blocked by REF-999")
	t.Logf("unreachable")
}
`,
			wantCount: 0,
		},
		{
			name: "assert.Panics counts as an assertion",
			code: `package models

import "testing"

func TestDivByZero(t *testing.T) {
	assert.Panics(t, func() { _ = amount.Div(zero) })
}
`,
			wantCount: 0,
		},
		{
			name: "benchmark is not a test function",
			code: `package models

import "testing"

func BenchmarkAdd(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = amount1.Add(amount2)
	}
}
`,
			wantCount: 0,
		},
		{
			name: "TestMain is infrastructure, not a test case",
			code: `package models

import "testing"

func TestMain(m *testing.M) {
	os.Exit(tests.RunMain(m))
}
`,
			wantCount: 0,
		},
	}

	rule := NewTestWithoutAssertionRule()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := core.NewFileContext("svc_test.go", ".", []byte(tt.code), core.DefaultConfig())
			fset, astFile, err := core.NewParser().ParseGoFile("svc_test.go", []byte(tt.code))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			ctx.SetGoAST(fset, astFile)

			violations := rule.AnalyzeFile(ctx)
			if len(violations) != tt.wantCount {
				t.Errorf("got %d violations, want %d; violations: %+v",
					len(violations), tt.wantCount, violations)
			}
		})
	}
}
