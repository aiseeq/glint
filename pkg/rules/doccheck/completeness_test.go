package doccheck

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/core"
)

func TestDocCompletenessRule(t *testing.T) {
	tests := []struct {
		name           string
		code           string
		wantViolations int
	}{
		{
			name: "documented type - ok",
			code: `package main

// User represents a user in the system.
type User struct {
	Name string
}`,
			wantViolations: 0,
		},
		{
			name: "undocumented exported type",
			code: `package main

type User struct {
	Name string
}`,
			wantViolations: 1,
		},
		{
			name: "undocumented private type - ok",
			code: `package main

type user struct {
	Name string
}`,
			wantViolations: 0,
		},
		{
			name: "documented function - ok",
			code: `package main

// GetUser returns a user by ID.
func GetUser(id string) {}`,
			wantViolations: 0,
		},
		{
			name: "undocumented exported function",
			code: `package main

func GetUser(id string) {}`,
			wantViolations: 1,
		},
		{
			name: "documented function wrong format",
			code: `package main

// Returns a user by ID.
func GetUser(id string) {}`,
			wantViolations: 1, // Doc doesn't start with function name
		},
		{
			name: "main and init - ok without doc",
			code: `package main

func main() {}
func init() {}`,
			wantViolations: 0,
		},
		{
			name: "documented method - ok",
			code: `package main

type Service struct{}

// Start starts the service.
func (s *Service) Start() {}`,
			wantViolations: 1, // Type is undocumented
		},
		{
			name: "undocumented exported const",
			code: `package main

const MaxSize = 100`,
			wantViolations: 1,
		},
		{
			name: "documented const - ok",
			code: `package main

// MaxSize is the maximum allowed size.
const MaxSize = 100`,
			wantViolations: 0,
		},
		{
			name: "const group with doc - ok",
			code: `package main

// Status codes.
const (
	StatusOK = 200
	StatusNotFound = 404
)`,
			wantViolations: 0,
		},
		{
			name: "undocumented exported var",
			code: `package main

var GlobalConfig = "config"`,
			wantViolations: 1,
		},
		{
			name: "private function - ok without doc",
			code: `package main

func getUser(id string) {}`,
			wantViolations: 0,
		},
		{
			name: "interface without doc",
			code: `package main

type Reader interface {
	Read() error
}`,
			wantViolations: 1,
		},
		{
			name: "documented interface - ok",
			code: `package main

// Reader defines the reading interface.
type Reader interface {
	Read() error
}`,
			wantViolations: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewDocCompletenessRule()

			parser := core.NewParser()
			ctx := core.NewFileContext("/src/main.go", "/src", []byte(tt.code), core.DefaultConfig())
			fset, astFile, err := parser.ParseGoFile("/src/main.go", []byte(tt.code))
			if err != nil {
				t.Fatalf("Parse error: %v", err)
			}
			ctx.SetGoAST(fset, astFile)

			violations := rule.AnalyzeFile(ctx)

			assert.Len(t, violations, tt.wantViolations, "Code:\n%s", tt.code)
		})
	}
}

func TestDocCompletenessSkipsTestFiles(t *testing.T) {
	rule := NewDocCompletenessRule()

	code := `package main

type User struct {}
func GetUser() {}`

	parser := core.NewParser()
	ctx := core.NewFileContext("/src/main_test.go", "/src", []byte(code), core.DefaultConfig())
	fset, astFile, err := parser.ParseGoFile("/src/main_test.go", []byte(code))
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	ctx.SetGoAST(fset, astFile)

	violations := rule.AnalyzeFile(ctx)

	assert.Empty(t, violations, "Should skip test files")
}
