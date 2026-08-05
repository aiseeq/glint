package patterns

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/stretchr/testify/require"
)

func TestSilentErrorHandlingRule_UserVisibleErrorStruct(t *testing.T) {
	code := `package main

type Result struct {
	Error string
}

func parse() (*Result, error) { return nil, nil }

func example() (*Result, *Result) {
	_, err := parse()
	if err != nil {
		return nil, &Result{Error: "failed to parse"}
	}
	return nil, nil
}
`

	ctx := createSilentErrorContext(t, "service.go", code)
	violations := NewSilentErrorHandlingRule().AnalyzeFile(ctx)
	require.Empty(t, violations)
}

func TestSilentErrorHandlingRule_ErrorSentToChannel(t *testing.T) {
	code := `package main

func walk(errorChan chan error) {
	err := visit()
	if err != nil {
		errorChan <- err
	}
}

`

	ctx := createSilentErrorContext(t, "walker.go", code)
	violations := NewSilentErrorHandlingRule().AnalyzeFile(ctx)
	require.Empty(t, violations)
}

func TestSilentErrorHandlingRule_ErrorIncludedInDiagnostic(t *testing.T) {
	code := `package main

func analyze() []*Violation {
	err := inspect()
	if err != nil {
		violation := NewViolation("analysis failed: " + err.Error())
		return []*Violation{violation}
	}
	return nil
}
`

	ctx := createSilentErrorContext(t, "analyzer.go", code)
	violations := NewSilentErrorHandlingRule().AnalyzeFile(ctx)
	require.Empty(t, violations)
}

func createSilentErrorContext(t *testing.T, path, code string) *core.FileContext {
	t.Helper()
	ctx := &core.FileContext{
		Path:    "/" + path,
		RelPath: path,
		Lines:   splitTimeEqualLines(code),
		Content: []byte(code),
	}
	parser := core.NewParser()
	fset, file, err := parser.ParseGoFile(path, []byte(code))
	require.NoError(t, err)
	ctx.SetGoAST(fset, file)
	return ctx
}

// Ошибка, отданная в хелпер, не проглочена: хелпер её и логирует, и печатает.
// Репро из projectC — writePreflightFailure(msg, report, err) и
// handleReconcileFailure(ctx, tx, err).
func TestSilentErrorHandlingRule_ErrorPassedToHelper(t *testing.T) {
	code := `package main

type Report struct{}

func writePreflightFailure(msg string, report Report, err error) {}

func backfill() (Report, error) { return Report{}, nil }

func run() int {
	report, err := backfill()
	if err != nil {
		writePreflightFailure("historical preflight failed", report, err)
		return 7
	}
	return 0
}
`

	ctx := createSilentErrorContext(t, "main.go", code)
	violations := NewSilentErrorHandlingRule().AnalyzeFile(ctx)
	require.Empty(t, violations, "ошибка передана обработчику: %v", violations)
}

// NewClient() в ветке err != nil — ровно тот silent fallback, который правило
// должно ловить: «new» в имени вызова не означает создание ошибки.
func TestSilentErrorHandlingRule_NewCallFallbackIsFlagged(t *testing.T) {
	code := `package main

type Client struct{}

func connect() (*Client, error) { return nil, nil }

func getClient() *Client {
	c, err := connect()
	if err != nil {
		return NewClient()
	}
	return c
}

func NewClient() *Client { return &Client{} }
`

	ctx := createSilentErrorContext(t, "client.go", code)
	violations := NewSilentErrorHandlingRule().AnalyzeFile(ctx)
	require.Len(t, violations, 1, "NewClient() — fallback, а не создание ошибки: %v", violations)
}

// Настоящее создание ошибки по-прежнему считается обработкой: errors.New,
// fmt.Errorf и функции с суффиксом Error/Errorf.
func TestSilentErrorHandlingRule_ErrorCreatingCallsStillHandle(t *testing.T) {
	code := `package main

import (
	"errors"
	"fmt"
)

func load() (int, error) { return 0, nil }

func NewValidationError(msg string) error { return errors.New(msg) }

func a() error {
	_, err := load()
	if err != nil {
		return errors.New("load failed")
	}
	return nil
}

func b() error {
	_, err := load()
	if err != nil {
		return fmt.Errorf("load failed")
	}
	return nil
}

func c() error {
	_, err := load()
	if err != nil {
		return NewValidationError("load failed")
	}
	return nil
}
`

	ctx := createSilentErrorContext(t, "loader.go", code)
	violations := NewSilentErrorHandlingRule().AnalyzeFile(ctx)
	require.Empty(t, violations, "создание ошибки — обработка: %v", violations)
}

// Замыкание внутри (T, bool)-функции не наследует её исключение: return false
// из closure с собственной сигнатурой func() bool молча глотает ошибку.
func TestSilentErrorHandlingRule_ClosureDoesNotInheritValueBoolException(t *testing.T) {
	code := `package main

func ping() error { return nil }

func lookup() (string, bool) {
	check := func() bool {
		err := ping()
		if err != nil {
			return false
		}
		return true
	}
	if !check() {
		return "", false
	}
	return "x", true
}
`

	ctx := createSilentErrorContext(t, "lookup.go", code)
	violations := NewSilentErrorHandlingRule().AnalyzeFile(ctx)
	require.Len(t, violations, 1, "closure не наследует (T, bool)-исключение: %v", violations)
}

// Обратная сторона: замыкание с собственной сигнатурой (T, bool) получает
// исключение по своей сигнатуре, а не по сигнатуре объемлющей функции.
func TestSilentErrorHandlingRule_ClosureWithOwnValueBoolSignature(t *testing.T) {
	code := `package main

func load(key string) (string, error) { return "", nil }

func process() error {
	get := func(key string) (string, bool) {
		v, err := load(key)
		if err != nil {
			return "", false
		}
		return v, true
	}
	_, _ = get("a")
	return nil
}
`

	ctx := createSilentErrorContext(t, "process.go", code)
	violations := NewSilentErrorHandlingRule().AnalyzeFile(ctx)
	require.Empty(t, violations, "у closure своя (T, bool)-сигнатура: %v", violations)
}

// Причина, положенная в отчёт как err.Error(), тоже не молчание: текст ошибки
// доезжает до читателя отчёта. Репро из projectC — бэкфилл отпечатков bulk.
func TestSilentErrorHandlingRule_ErrorTextPassedToReport(t *testing.T) {
	code := `package main

type Report struct{ Issues []string }

func appendIssue(report *Report, reason string) { report.Issues = append(report.Issues, reason) }

func parseKey(key string) (string, error) { return "", nil }

func classify(report *Report, keys []string) {
	for _, key := range keys {
		if _, err := parseKey(key); err != nil {
			appendIssue(report, err.Error())
			continue
		}
	}
}
`

	ctx := createSilentErrorContext(t, "backfill.go", code)
	violations := NewSilentErrorHandlingRule().AnalyzeFile(ctx)
	require.Empty(t, violations, "текст ошибки попал в отчёт: %v", violations)
}
