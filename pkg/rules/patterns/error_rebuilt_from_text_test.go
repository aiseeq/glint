package patterns

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
)

// rebuiltErrorProject builds a typed project out of one file plus the shared
// declarations every case leans on.
func rebuiltErrorProject(t *testing.T, name, source string) *core.GoProjectContext {
	t.Helper()
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.com/rebuilt\n\ngo 1.24\n"), 0o644))

	files := map[string]string{
		name: source,
		"support.go": `package service

import "errors"

// ErrSignature is a category the boundary matches with errors.Is.
var ErrSignature = errors.New("signature")

type ServiceError struct {
	Code    string
	Message string
}

func (e *ServiceError) Error() string { return e.Message }

type Result struct {
	Error *ServiceError
}

// Envelope is a decoded provider answer: its Error is text, not a cause.
type Envelope struct {
	Success bool
	Code    string
	Error   string
}

type Response struct {
	Status int
}

type AlreadyLinkedError struct {
	Email string
}

func (e *AlreadyLinkedError) Error() string { return "already linked" }

func call() (*Response, error)  { return nil, nil }
func callResult() Result        { return Result{} }
func decode() (Envelope, error) { return Envelope{}, nil }
func closeIt() error            { return nil }
func record(message string)     {}
`,
	}

	var contexts []*core.FileContext
	for fileName, content := range files {
		path := filepath.Join(root, fileName)
		require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
		ctx, err := core.NewFileContextChecked(path, root, []byte(content), core.DefaultConfig())
		require.NoError(t, err)
		contexts = append(contexts, ctx)
	}

	project, err := core.LoadGoProject(root, contexts, core.GoProjectOptions{})
	require.NoError(t, err)
	return project
}

func analyzeRebuiltError(t *testing.T, source string) []*core.Violation {
	t.Helper()
	violations, err := NewErrorRebuiltFromTextRule().AnalyzeGoProject(rebuiltErrorProject(t, "service.go", source))
	require.NoError(t, err)
	return violations
}

func TestErrorRebuiltFromTextRule_Metadata(t *testing.T) {
	rule := NewErrorRebuiltFromTextRule()

	assert.Equal(t, "error-rebuilt-from-text", rule.Name())
	assert.Equal(t, "patterns", rule.Category())
	assert.Equal(t, core.SeverityMedium, rule.DefaultSeverity())
}

func TestErrorRebuiltFromTextRule_Detection(t *testing.T) {
	tests := []struct {
		name        string
		code        string
		expectMatch bool
	}{
		{
			// Repro (projectA, 2026-09): a cancelled browser request reached the
			// HTTP boundary as 500 because the cause was formatted into text with
			// %v and the chain ended there — errors.Is(err, context.Canceled) saw
			// nothing to match.
			name: "cause formatted with %v",
			code: `
func fetch() error {
	if _, err := call(); err != nil {
		return fmt.Errorf("fetch dashboard: %v", err)
	}
	return nil
}
`,
			expectMatch: true,
		},
		{
			name: "cause formatted with %s",
			code: `
func fetch() error {
	if _, err := call(); err != nil {
		return fmt.Errorf("fetch dashboard: %s", err.Error())
	}
	return nil
}
`,
			expectMatch: true,
		},
		{
			name: "cause wrapped with %w",
			code: `
func fetch() error {
	if _, err := call(); err != nil {
		return fmt.Errorf("fetch dashboard: %w", err)
	}
	return nil
}
`,
			expectMatch: false,
		},
		{
			name: "new error built from a formatted cause",
			code: `
func fetch() error {
	if _, err := call(); err != nil {
		message := fmt.Sprintf("fetch dashboard: %v", err)
		record(message)
		return errors.New(message)
	}
	return nil
}
`,
			expectMatch: true,
		},
		{
			name: "error rebuilt from a result object message",
			code: `
func fetch() error {
	result := callResult()
	if result.Error != nil {
		return fmt.Errorf("create user: %s", result.Error.Message)
	}
	return nil
}
`,
			expectMatch: true,
		},
		{
			name: "plain values formatted, no error involved",
			code: `
func fetch() error {
	response, _ := call()
	return fmt.Errorf("endpoint returned status %d", response.Status)
}
`,
			expectMatch: false,
		},
		{
			name: "message of an error printed in a log, not rebuilt",
			code: `
func fetch() error {
	_, err := call()
	if err != nil {
		record(fmt.Sprintf("fetch dashboard: %v", err))
		return err
	}
	return nil
}
`,
			expectMatch: false,
		},
		{
			// A pair of failures from one operation: the primary keeps the chain,
			// the secondary is deliberately reported as text.
			name: "cause wrapped, second failure printed beside it",
			code: `
func fetch() error {
	_, err := call()
	closeErr := closeIt()
	if err != nil {
		return fmt.Errorf("read rows: %w; close rows: %v", err, closeErr)
	}
	return nil
}
`,
			expectMatch: false,
		},
		{
			// The code of a result object printed next to the object itself: the
			// %w keeps the very same cause, so nothing is lost.
			name: "result code printed beside the wrapped result error",
			code: `
func fetch() error {
	result := callResult()
	if result.Error != nil {
		return fmt.Errorf("%s: %w", result.Error.Code, result.Error)
	}
	return nil
}
`,
			expectMatch: false,
		},
		{
			// A sentinel wrapped with %w keeps the category, not the cause:
			// errors.Is(err, ErrSignature) matches, and the transport failure
			// under it still arrives as text.
			name: "sentinel wrapped, real cause printed as text",
			code: `
func fetch() error {
	if _, err := call(); err != nil {
		return fmt.Errorf("%w: %s", ErrSignature, err.Error())
	}
	return nil
}
`,
			expectMatch: true,
		},
		{
			// errors.As found a typed error and the branch pulls a data field
			// out of it for the reader: that field is not the error's text.
			name: "data field of a typed error, not its message",
			code: `
func fetch() error {
	if _, err := call(); err != nil {
		var conflict *AlreadyLinkedError
		if errors.As(err, &conflict) {
			return fmt.Errorf("account already linked to %s", conflict.Email)
		}
	}
	return nil
}
`,
			expectMatch: false,
		},
		{
			// A decoded provider answer carries its failure as a string field:
			// there is no chain behind it to keep.
			name: "error field of a decoded payload is text of its own",
			code: `
func fetch() error {
	envelope, _ := decode()
	if !envelope.Success {
		return fmt.Errorf("vault report: %s (code %s)", envelope.Error, envelope.Code)
	}
	return nil
}
`,
			expectMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			source := "package service\n\nimport (\n\t\"errors\"\n\t\"fmt\"\n)\n\nvar _ = errors.New\n" + tt.code
			violations := analyzeRebuiltError(t, source)

			if tt.expectMatch {
				require.NotEmpty(t, violations, "Expected violation for: %s", tt.name)
				assert.Contains(t, violations[0].Message, "errors.Is")
			} else {
				assert.Empty(t, violations, "Expected no violations for: %s", tt.name)
			}
		})
	}
}

// One name holding a different message in every branch: only the branch whose
// message carries a cause is a finding, and it is reported on its own line.
func TestErrorRebuiltFromTextRule_MessageVariableReused(t *testing.T) {
	source := `package service

import (
	"errors"
	"fmt"
)

func fetch() error {
	response, err := call()
	if err != nil {
		errMsg := fmt.Sprintf("call failed: %v", err)
		record(errMsg)
		return errors.New(errMsg)
	}
	if response.Status != 200 {
		errMsg := fmt.Sprintf("endpoint returned status %d", response.Status)
		record(errMsg)
		return errors.New(errMsg)
	}
	return nil
}
`
	violations := analyzeRebuiltError(t, source)

	require.Len(t, violations, 1)
	assert.Equal(t, 13, violations[0].Line)
}

func TestErrorRebuiltFromTextRule_TestFilesExcluded(t *testing.T) {
	source := `package service

import (
	"fmt"
	"testing"
)

func TestFetch(t *testing.T) {
	_, err := call()
	record(fmt.Errorf("fetch: %v", err).Error())
	_ = t
}
`
	violations, err := NewErrorRebuiltFromTextRule().AnalyzeGoProject(rebuiltErrorProject(t, "service_test.go", source))
	require.NoError(t, err)
	assert.Empty(t, violations)
}
