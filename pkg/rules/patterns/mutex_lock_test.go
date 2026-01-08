package patterns

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMutexLockRule_Metadata(t *testing.T) {
	rule := NewMutexLockRule()

	assert.Equal(t, "mutex-lock", rule.Name())
	assert.Equal(t, "patterns", rule.Category())
	assert.Equal(t, core.SeverityHigh, rule.DefaultSeverity())
}

func TestMutexLockRule_Detection(t *testing.T) {
	rule := NewMutexLockRule()

	tests := []struct {
		name        string
		code        string
		expectMatch bool
	}{
		{
			name: "lock with regular unlock - acceptable",
			code: `package main

import "sync"

func example() {
	var mu sync.Mutex
	mu.Lock()
	// do something
	mu.Unlock()
}
`,
			expectMatch: false, // Regular unlock is acceptable (early-unlock pattern)
		},
		{
			name: "lock with defer unlock",
			code: `package main

import "sync"

func example() {
	var mu sync.Mutex
	mu.Lock()
	defer mu.Unlock()
	// do something
}
`,
			expectMatch: false,
		},
		{
			name: "lock without any unlock - violation",
			code: `package main

import "sync"

func example() {
	var mu sync.Mutex
	mu.Lock()
	// do something but no unlock!
}
`,
			expectMatch: true, // No unlock at all - real problem
		},
		{
			name: "rlock with regular runlock - acceptable",
			code: `package main

import "sync"

func example() {
	var mu sync.RWMutex
	mu.RLock()
	// do something
	mu.RUnlock()
}
`,
			expectMatch: false, // Regular unlock is acceptable
		},
		{
			name: "rlock with defer runlock",
			code: `package main

import "sync"

func example() {
	var mu sync.RWMutex
	mu.RLock()
	defer mu.RUnlock()
	// do something
}
`,
			expectMatch: false,
		},
		{
			name: "rlock without any runlock - violation",
			code: `package main

import "sync"

func example() {
	var mu sync.RWMutex
	mu.RLock()
	// do something but no unlock!
}
`,
			expectMatch: true, // No unlock at all - real problem
		},
		{
			name: "struct field mutex with defer",
			code: `package main

import "sync"

type Service struct {
	mu sync.Mutex
}

func (s *Service) Method() {
	s.mu.Lock()
	defer s.mu.Unlock()
}
`,
			expectMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := createMutexContext(t, "service.go", tt.code)
			violations := rule.AnalyzeFile(ctx)

			if tt.expectMatch {
				require.NotEmpty(t, violations, "Expected violation for: %s", tt.name)
				assert.Equal(t, "mutex_no_unlock", violations[0].Context["pattern"])
			} else {
				assert.Empty(t, violations, "Expected no violations for: %s", tt.name)
			}
		})
	}
}

// Helper function
func createMutexContext(t *testing.T, path, code string) *core.FileContext {
	t.Helper()
	ctx := &core.FileContext{
		Path:    "/" + path,
		RelPath: path,
		Lines:   splitMutexLines(code),
		Content: []byte(code),
	}

	if len(path) > 3 && path[len(path)-3:] == ".go" {
		parser := core.NewParser()
		fset, ast, err := parser.ParseGoFile(path, []byte(code))
		if err != nil {
			t.Fatalf("Failed to parse Go code: %v", err)
		}
		ctx.SetGoAST(fset, ast)
	}

	return ctx
}

func splitMutexLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}
