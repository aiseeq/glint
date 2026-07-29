package patterns

import (
	"strings"
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResponseTypeInFunctionRule_Metadata(t *testing.T) {
	rule := NewResponseTypeInFunctionRule()

	assert.Equal(t, "response-type-in-function", rule.Name())
	assert.Equal(t, "patterns", rule.Category())
	assert.Equal(t, core.SeverityHigh, rule.DefaultSeverity())
}

func TestResponseTypeInFunctionRule_Detection(t *testing.T) {
	rule := NewResponseTypeInFunctionRule()

	tests := []struct {
		name        string
		code        string
		expectMatch bool
	}{
		{
			// Репро с Saga: контракт дашборда жил в теле обработчика, генератор типов его не
			// видел, и на фронте выросли три рукописные копии с разными наборами полей.
			name: "контракт ответа объявлен в теле обработчика",
			code: `package handlers

import "net/http"

func sendDashboard(w http.ResponseWriter, req *http.Request) {
	type DashboardResponse struct {
		TotalValue       string ` + "`json:\"totalValue\"`" + `
		AvailableBalance string ` + "`json:\"availableBalance\"`" + `
	}
	sendSuccess(w, req, DashboardResponse{TotalValue: "1", AvailableBalance: "1"})
}
`,
			expectMatch: true,
		},
		{
			name: "контракт возвращается наружу из функции",
			code: `package handlers

func buildPayload() any {
	type Payload struct {
		ID string ` + "`json:\"id\"`" + `
	}
	return Payload{ID: "x"}
}
`,
			expectMatch: true,
		},
		{
			name: "контракт передаётся по указателю",
			code: `package handlers

import "encoding/json"

func encode(enc *json.Encoder) {
	type Item struct {
		Name string ` + "`json:\"name\"`" + `
	}
	_ = enc.Encode(&Item{Name: "a"})
}
`,
			expectMatch: true,
		},
		{
			// Разбор тела запроса — нормальный идиом Go: структуру заполняет декодер,
			// её никто не собирает по полям и не отдаёт наружу.
			name: "локальная структура для разбора запроса не считается",
			code: `package handlers

import (
	"encoding/json"
	"net/http"
)

func parse(req *http.Request) error {
	type body struct {
		Amount string ` + "`json:\"amount\"`" + `
	}
	var payload body
	return json.NewDecoder(req.Body).Decode(&payload)
}
`,
			expectMatch: false,
		},
		{
			name: "локальная структура без json-тегов — внутренний помощник",
			code: `package handlers

func group() int {
	type bucket struct {
		Total int
	}
	b := bucket{Total: 1}
	return use(b.Total)
}
`,
			expectMatch: false,
		},
		{
			name: "контракт на уровне пакета — так и должно быть",
			code: `package handlers

import "net/http"

type DashboardResponse struct {
	TotalValue string ` + "`json:\"totalValue\"`" + `
}

func sendDashboard(w http.ResponseWriter, req *http.Request) {
	sendSuccess(w, req, DashboardResponse{TotalValue: "1"})
}
`,
			expectMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := createPatternContext(t, "handler.go", tt.code)
			violations := rule.AnalyzeFile(ctx)

			if tt.expectMatch {
				require.NotEmpty(t, violations, "ожидалась находка: %s", tt.name)
				assert.Equal(t, "response_type_in_function", violations[0].Context["pattern"])
				assert.Contains(t, violations[0].Suggestion, "package scope")
			} else {
				assert.Empty(t, violations, "находок быть не должно: %s", tt.name)
			}
		})
	}
}

// Тестовые файлы правило не смотрит: локальный контракт в тесте — это фикстура.
func TestResponseTypeInFunctionRule_SkipsTestFiles(t *testing.T) {
	rule := NewResponseTypeInFunctionRule()
	code := `package handlers

func TestSomething(t *testing.T) {
	type Response struct {
		ID string ` + "`json:\"id\"`" + `
	}
	check(Response{ID: "x"})
}
`
	ctx := createPatternContext(t, "handler_test.go", code)
	assert.Empty(t, rule.AnalyzeFile(ctx))
}

// createPatternContext собирает FileContext с разобранным Go-AST.
func createPatternContext(t *testing.T, path, code string) *core.FileContext {
	t.Helper()
	ctx := &core.FileContext{
		Path:    "/" + path,
		RelPath: path,
		Lines:   strings.Split(code, "\n"),
		Content: []byte(code),
	}

	if strings.HasSuffix(path, ".go") {
		parser := core.NewParser()
		fset, file, err := parser.ParseGoFile(path, []byte(code))
		require.NoError(t, err, "разбор Go-кода")
		ctx.SetGoAST(fset, file)
	}

	return ctx
}
