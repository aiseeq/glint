package duplication

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDuplicateBlockRule_Metadata(t *testing.T) {
	rule := NewDuplicateBlockRule()

	assert.Equal(t, "duplicate-block", rule.Name())
	assert.Equal(t, "duplication", rule.Category())
	assert.Equal(t, core.SeverityMedium, rule.DefaultSeverity())
}

func TestDuplicateBlockRule_DetectsDuplicate(t *testing.T) {
	rule := NewDuplicateBlockRule()

	// Large duplicate block with 8+ substantial lines
	code := `package main

func processUserData(id int) error {
	connection := database.GetConnection()
	transaction := connection.BeginTransaction()
	validator := NewDataValidator(connection)
	processor := NewDataProcessor(validator)
	handler := processor.CreateHandler(id)
	results := handler.Execute()
	report := generateReport(results)
	saveResults(results, report)
}

func processAdminData(id int) error {
	connection := database.GetConnection()
	transaction := connection.BeginTransaction()
	validator := NewDataValidator(connection)
	processor := NewDataProcessor(validator)
	handler := processor.CreateHandler(id)
	results := handler.Execute()
	report := generateReport(results)
	saveResults(results, report)
}
`
	ctx := createTestContext(t, "backend/service.go", code)
	violations := rule.AnalyzeFile(ctx)

	require.NotEmpty(t, violations, "Expected violation for duplicate code block")
	assert.Contains(t, violations[0].Message, "Duplicate block")
}

func TestDuplicateBlockRule_NoDuplicates(t *testing.T) {
	rule := NewDuplicateBlockRule()

	code := `package main

func processUser(id int) error {
	user, err := getUser(id)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}
	return saveUser(user)
}

func processAdmin(id int) error {
	admin, err := getAdmin(id)
	if err != nil {
		return fmt.Errorf("failed to get admin: %w", err)
	}
	return saveAdmin(admin)
}
`
	ctx := createTestContext(t, "backend/service.go", code)
	violations := rule.AnalyzeFile(ctx)

	assert.Empty(t, violations, "Expected no violation for different code")
}

func TestDuplicateBlockRule_SmallBlocksIgnored(t *testing.T) {
	rule := NewDuplicateBlockRule()

	// Only 2 lines repeated - should be ignored
	code := `package main

func foo() {
	a := 1
	b := 2
}

func bar() {
	a := 1
	b := 2
}
`
	ctx := createTestContext(t, "backend/service.go", code)
	violations := rule.AnalyzeFile(ctx)

	assert.Empty(t, violations, "Small blocks should be ignored")
}

func TestDuplicateBlockRule_TestFilesExcluded(t *testing.T) {
	rule := NewDuplicateBlockRule()

	code := `package main

func TestA() {
	user, err := getUser(1)
	if err != nil {
		t.Fatal(err)
	}
	result := transform(user)
	assert.NotNil(t, result)
}

func TestB() {
	user, err := getUser(1)
	if err != nil {
		t.Fatal(err)
	}
	result := transform(user)
	assert.NotNil(t, result)
}
`
	ctx := createTestContext(t, "backend/service_test.go", code)
	violations := rule.AnalyzeFile(ctx)

	assert.Empty(t, violations, "Test files should be excluded")
}

func TestDuplicateBlockRule_TrivialLinesIgnored(t *testing.T) {
	rule := NewDuplicateBlockRule()

	// Only trivial lines (braces, returns) - should be ignored
	code := `package main

func foo() {
	if true {
		return
	}
}

func bar() {
	if true {
		return
	}
}
`
	ctx := createTestContext(t, "backend/service.go", code)
	violations := rule.AnalyzeFile(ctx)

	assert.Empty(t, violations, "Trivial line patterns should be ignored")
}

// Helper function to create test context
func createTestContext(t *testing.T, path, code string) *core.FileContext {
	t.Helper()

	ctx := &core.FileContext{
		Path:    "/" + path,
		RelPath: path,
		Lines:   splitLines(code),
		Content: []byte(code),
	}

	return ctx
}

func splitLines(s string) []string {
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
