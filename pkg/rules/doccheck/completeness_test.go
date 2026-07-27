package doccheck

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/core"
)

func docContext(t *testing.T, path, code string) *core.FileContext {
	t.Helper()
	parser := core.NewParser()
	ctx := core.NewFileContext(path, "/src", []byte(code), core.DefaultConfig())
	fset, astFile, err := parser.ParseGoFile(path, []byte(code))
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	ctx.SetGoAST(fset, astFile)
	return ctx
}

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
			name: "type alias - ok without doc",
			code: `package main

type Violation = core.Violation`,
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
			name: "undocumented function with a common verb name",
			code: `package main

func GetUser(id string) {}`,
			wantViolations: 1, // a familiar verb says nothing about what the function does
		},
		{
			name: "doc not starting with the name",
			code: `package main

// Returns a user by ID.
func GetUser(id string) {}`,
			wantViolations: 1,
		},
		{
			name: "main and init - ok without doc",
			code: `package main

func main() {}
func init() {}`,
			wantViolations: 0,
		},
		{
			name: "undocumented const without a type",
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
			name: "undocumented interface",
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
			violations := rule.AnalyzeFile(docContext(t, "/src/main.go", tt.code))
			assert.Len(t, violations, tt.wantViolations, "Code:\n%s", tt.code)
		})
	}
}

// Repro from glint itself: every rule file declares a constructor and the
// interface methods, and the name heuristics hid the ones missing a comment.
func TestDocCompletenessReportsUndocumentedRuleAPI(t *testing.T) {
	rule := NewDocCompletenessRule()

	violations := rule.AnalyzeFile(docContext(t, "/src/rule.go", `package patterns

// FinancialFPRoundingRule detects float rounding of money.
type FinancialFPRoundingRule struct {
	threshold int
}

func NewFinancialFPRoundingRule() *FinancialFPRoundingRule {
	return &FinancialFPRoundingRule{}
}

func (r *FinancialFPRoundingRule) Configure(settings map[string]any) error {
	return nil
}

func (r *FinancialFPRoundingRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	return nil
}
`))

	assert.Len(t, violations, 3)
}

// Methods whose contract is written in the standard library need no repeat.
func TestDocCompletenessSkipsStandardInterfaceMethods(t *testing.T) {
	rule := NewDocCompletenessRule()

	violations := rule.AnalyzeFile(docContext(t, "/src/severity.go", `package core

// Severity represents the severity level of a violation.
type Severity int

func (s Severity) String() string {
	switch s {
	case SeverityLow:
		return "low"
	}
	return ""
}

func (s Severity) MarshalJSON() ([]byte, error) {
	return nil, nil
}
`))

	assert.Empty(t, violations)
}

// A method that only hands a field over says everything in its signature.
func TestDocCompletenessSkipsFieldAccessors(t *testing.T) {
	rule := NewDocCompletenessRule()

	violations := rule.AnalyzeFile(docContext(t, "/src/user.go", `package main

// User is a system user.
type User struct {
	name string
}

func (u *User) Name() string {
	return u.name
}

func (u *User) SetName(name string) {
	u.name = name
}
`))

	assert.Empty(t, violations)
}

// A method that does work is not an accessor, however short its parameter list.
func TestDocCompletenessReportsShortMethodThatDoesWork(t *testing.T) {
	rule := NewDocCompletenessRule()

	violations := rule.AnalyzeFile(docContext(t, "/src/user.go", `package main

// User is a system user.
type User struct {
	name string
}

func (u *User) Rename(name string) error {
	if name == "" {
		return errors.New("empty name")
	}
	u.name = strings.TrimSpace(name)
	return nil
}
`))

	assert.Len(t, violations, 1)
}

// Repro from glint itself: a typed const group names its own meaning, so the
// members repeat the type rather than document anything.
func TestDocCompletenessSkipsTypedEnumMembers(t *testing.T) {
	rule := NewDocCompletenessRule()

	violations := rule.AnalyzeFile(docContext(t, "/src/severity.go", `package core

// Severity represents the severity level of a violation.
type Severity int

const (
	SeverityLow Severity = iota
	SeverityMedium
	SeverityHigh
	SeverityCritical
)
`))

	assert.Empty(t, violations)
}

// A typed group whose members do not carry the type name is not an enum.
func TestDocCompletenessReportsTypedConstsUnrelatedToTheType(t *testing.T) {
	rule := NewDocCompletenessRule()

	violations := rule.AnalyzeFile(docContext(t, "/src/limits.go", `package core

// Threshold bounds an analysis.
type Threshold int

const (
	Magic Threshold = 42
	Other Threshold = 7
)
`))

	assert.Len(t, violations, 2)
}

func TestDocCompletenessSkipTrivialDisabled(t *testing.T) {
	rule := NewDocCompletenessRule()
	if err := rule.Configure(map[string]any{"skip_trivial": false}); err != nil {
		t.Fatalf("Configure: %v", err)
	}

	violations := rule.AnalyzeFile(docContext(t, "/src/user.go", `package main

// User is a system user.
type User struct {
	name string
}

func (u *User) Name() string {
	return u.name
}
`))

	assert.Len(t, violations, 1, "accessors are reported once the skip is off")
}

func TestDocCompletenessSkipsTestFiles(t *testing.T) {
	rule := NewDocCompletenessRule()

	violations := rule.AnalyzeFile(docContext(t, "/src/main_test.go", `package main

type User struct {}
func GetUser() {}`))

	assert.Empty(t, violations, "Should skip test files")
}
