package duplication

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
)

func TestDuplicateBlockRule_Metadata(t *testing.T) {
	rule := NewDuplicateBlockRule()

	assert.Equal(t, "duplicate-block", rule.Name())
	assert.Equal(t, "duplication", rule.Category())
	assert.Equal(t, core.SeverityMedium, rule.DefaultSeverity())
}

func TestDuplicateBlockRule_DetectsDuplicate(t *testing.T) {
	rule := NewDuplicateBlockRule()
	rule.minBlockSize = 8

	// Duplicate block with 8+ substantial lines.
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

func TestDuplicateBlockRule_TestFilesCompared(t *testing.T) {
	rule := NewDuplicateBlockRule()
	rule.minBlockSize = 8

	code := `package main

func TestUserData(t *testing.T) {
	connection := database.GetConnection()
	transaction := connection.BeginTransaction()
	validator := NewDataValidator(connection)
	processor := NewDataProcessor(validator)
	handler := processor.CreateHandler(id)
	results := handler.Execute()
	report := generateReport(results)
	saveResults(results, report)
}

func TestAdminData(t *testing.T) {
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
	ctx := createTestContext(t, "backend/service_test.go", code)
	violations := rule.AnalyzeFile(ctx)

	assert.NotEmpty(t, violations, "a block repeated inside a test file is the same debt as in production code")
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

// A backtick inside a regular quoted string is not a raw-string delimiter: it
// must not flip the raw-string state and hide every duplicate below it.
func TestDuplicateBlockRule_BacktickInQuotedStringDoesNotHideDuplicates(t *testing.T) {
	rule := NewDuplicateBlockRule()
	rule.minBlockSize = 8

	body := "\tconnection := database.GetConnection()\n" +
		"\ttransaction := connection.BeginTransaction()\n" +
		"\tvalidator := NewDataValidator(connection)\n" +
		"\tprocessor := NewDataProcessor(validator)\n" +
		"\thandler := processor.CreateHandler(id)\n" +
		"\tresults := handler.Execute()\n" +
		"\treport := generateReport(results)\n" +
		"\tsaveResults(results, report)\n"
	code := "package main\n\n" +
		"func markdownQuote() string {\n" +
		"\treturn \"`\"\n" +
		"}\n\n" +
		"func processUserData(id int) error {\n" + body + "}\n\n" +
		"func processAdminData(id int) error {\n" + body + "}\n"

	ctx := createTestContext(t, "backend/service.go", code)
	violations := rule.AnalyzeFile(ctx)

	require.NotEmpty(t, violations,
		"a backtick inside \"...\" must not mask the rest of the file as a raw string")
	assert.Contains(t, violations[0].Message, "Duplicate block")
}

// Helper function to create test context
func createTestContext(t *testing.T, path, code string) *core.FileContext {
	t.Helper()

	ctx := &core.FileContext{
		Path:    "/" + path,
		RelPath: path,
		Lines:   strings.Split(code, "\n"),
		Content: []byte(code),
	}

	return ctx
}
