package errrules

import (
	"strings"
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules/security"
)

func analyzeGoSnippet(t *testing.T, rule *ErrorCauseDroppedRule, code string) []*core.Violation {
	t.Helper()
	ctx := core.NewFileContext("/src/handler.go", "/src", []byte(code), core.DefaultConfig())
	parser := core.NewParser()
	fset, astFile, err := parser.ParseGoFile("/src/handler.go", []byte(code))
	require.NoError(t, err)
	ctx.SetGoAST(fset, astFile)
	return rule.AnalyzeFile(ctx)
}

func TestErrorCauseDropped_Go(t *testing.T) {
	rule := NewErrorCauseDroppedRule()

	tests := []struct {
		name     string
		code     string
		expected int
	}{
		{
			// The cause is in the server log and the client receives a fixed 5xx text.
			name: "logged cause then fixed 5xx response — ok",
			code: `package h
import ("net/http"; "log")
func complete(w http.ResponseWriter, r *http.Request) {
	if err := svc.Complete(r.Context(), id); err != nil {
		log.Printf("complete %s: %v", id, err)
		http.Error(w, "operation failed", http.StatusInternalServerError)
		return
	}
}`,
			expected: 0,
		},
		{
			name: "fresh errors.New replaces the cause in the chain — flagged",
			code: `package s
import ("errors"; "log")
func (s *Svc) Save(ctx context.Context) error {
	if err := s.repo.Save(ctx); err != nil {
		s.logger.Error("save failed", "error", err)
		return errors.New("save failed")
	}
	return nil
}`,
			expected: 1,
		},
		{
			name: "fmt.Errorf without the cause — flagged",
			code: `package s
import "fmt"
func (s *Svc) Load() error {
	if err := s.repo.Load(); err != nil {
		return fmt.Errorf("load failed")
	}
	return nil
}`,
			expected: 1,
		},
		{
			name: "project helper with logged cause and fixed 5xx text — ok",
			code: `package h
func handle(w http.ResponseWriter, req *http.Request) {
	if err := do(); err != nil {
		ar.logger.Error("do: " + err.Error())
		api.RespondError(w, req, 500, "Ошибка завершения", "COMPLETE_ERROR", "")
		return
	}
}`,
			expected: 0,
		},
		{
			name: "cause wrapped with %w — ok",
			code: `package s
import "fmt"
func (s *Svc) Load() error {
	if err := s.repo.Load(); err != nil {
		return fmt.Errorf("load failed: %w", err)
	}
	return nil
}`,
			expected: 0,
		},
		{
			name: "cause passed as details to the responder — ok",
			code: `package h
func handle(w http.ResponseWriter, req *http.Request) {
	if err := do(); err != nil {
		api.RespondError(w, req, 500, "Ошибка завершения", "COMPLETE_ERROR", err.Error())
		return
	}
}`,
			expected: 0,
		},
		{
			name: "cause classified with errors.Is before the text — ok",
			code: `package h
import ("errors"; "net/http")
func handle(w http.ResponseWriter, req *http.Request) {
	if err := do(); err != nil {
		if errors.Is(err, ErrNotFound) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		http.Error(w, "operation failed", http.StatusInternalServerError)
		return
	}
}`,
			expected: 0,
		},
		{
			name: "cause returned alongside — ok",
			code: `package s
func (s *Svc) Load() (int, error) {
	if err := s.repo.Load(); err != nil {
		s.logger.Warn("load failed")
		return 0, err
	}
	return 1, nil
}`,
			expected: 0,
		},
		{
			name: "panic and log.Fatal stop the process with the cause — ok",
			code: `package m
import "log"
func main() {
	if err := run(); err != nil {
		log.Fatalf("run: %v", err)
	}
	if err := run(); err != nil {
		panic(err)
	}
}`,
			expected: 0,
		},
		{
			name: "fmt.Println is the caller on a CLI — ok",
			code: `package m
import ("fmt"; "errors")
func run() error {
	if err := do(); err != nil {
		fmt.Println("do:", err)
		return errors.New("run failed")
	}
	return nil
}`,
			expected: 0,
		},
		{
			name: "no message at all (silent-error-handling territory) — not ours",
			code: `package s
func (s *Svc) Load() {
	if err := s.repo.Load(); err != nil {
		s.logger.Error("load failed", "error", err)
		return
	}
}`,
			expected: 0,
		},
		{
			name: "condition is not an error nil-check — ignored",
			code: `package s
import "errors"
func (s *Svc) Load() error {
	if s.cfg != nil {
		return errors.New("config already set")
	}
	return nil
}`,
			expected: 0,
		},
		{
			name: "4xx verdict on client input — ok",
			code: `package h
import "net/http"
func handle(w http.ResponseWriter, req *http.Request) {
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if err := verify(req); err != nil {
		http.Error(w, "bad signature", 401)
		return
	}
	if err := parse(req); err != nil {
		sendDenied(w, req, "Требуется авторизация")
		return
	}
}`,
			expected: 0,
		},
		{
			name: "format verbs with own arguments carry specifics — ok",
			code: `package p
import "fmt"
func parseAmount(name, v string) error {
	if _, err := strconv.Atoi(v); err != nil {
		return fmt.Errorf("%s: not a number: %q", name, v)
	}
	return nil
}`,
			expected: 0,
		},
		{
			name: "validation or not-found verdict explains itself — ok",
			code: `package p
import ("fmt"; "errors")
func parseID(raw string) error {
	if _, err := uuid.Parse(raw); err != nil {
		return fmt.Errorf("account_id должен быть UUID")
	}
	if _, err := url.Parse(raw); err != nil {
		return fmt.Errorf("parse RPC URL: invalid syntax")
	}
	if _, err := find(raw); err != nil {
		return errors.New("план не найден")
	}
	if _, err := rates(); err != nil {
		h.writeError(w, http.StatusBadGateway, "rate feed is not available")
	}
	return nil
}`,
			expected: 0,
		},
		{
			name: "plain if err != nil without init — flagged",
			code: `package s
import "errors"
func (s *Svc) Load() error {
	err := s.repo.Load()
	if err != nil {
		return errors.New("load failed")
	}
	return nil
}`,
			expected: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			violations := analyzeGoSnippet(t, rule, tt.code)
			assert.Len(t, violations, tt.expected, "code:\n%s", tt.code)
		})
	}
}

func TestErrorCauseDropped5xxLogged(t *testing.T) {
	code := `package h
import (
	"log/slog"
	"net/http"
	"os"
)
type Handler struct{ path string }
func (h *Handler) page(w http.ResponseWriter, r *http.Request) {
	data, err := os.ReadFile(h.path)
	if err != nil {
		slog.Error("read page", "err", err)
		http.Error(w, "could not render the page", http.StatusInternalServerError)
		return
	}
	w.Write(data)
}`

	rule := NewErrorCauseDroppedRule()
	assert.Empty(t, analyzeGoSnippet(t, rule, code))
	assert.Empty(t, analyzeSecurityRule(t, security.NewErrorDetailIn5xxResponseRule(), code))

	withoutLog := strings.Replace(code, "\t\tslog.Error(\"read page\", \"err\", err)\n", "", 1)
	assert.Len(t, analyzeGoSnippet(t, rule, withoutLog), 1)
}

func TestErrorCauseDropped5xxLogPaths(t *testing.T) {
	rule := NewErrorCauseDroppedRule()
	tests := []struct {
		name     string
		body     string
		expected int
	}{
		{
			name: "log on returning branch does not reach response",
			body: `if retry {
			slog.Error("retrying", "err", err)
			return
		}
		http.Error(w, "request failed", http.StatusInternalServerError)`,
			expected: 1,
		},
		{
			name: "log before response",
			body: `slog.Error("request failed", "err", err)
			http.Error(w, "request failed", http.StatusInternalServerError)`,
		},
		{
			name: "both branches log before common response",
			body: `if retry {
			slog.Error("retrying", "err", err)
		} else {
			slog.Error("not retrying", "err", err)
		}
		http.Error(w, "request failed", http.StatusInternalServerError)`,
		},
		{
			name: "one branch log does not cover common response",
			body: `if retry {
			slog.Error("retrying", "err", err)
		}
		http.Error(w, "request failed", http.StatusInternalServerError)`,
			expected: 1,
		},
		{
			name: "loop log does not cover zero iterations",
			body: `for range items {
			slog.Error("retrying", "err", err)
		}
		http.Error(w, "request failed", http.StatusInternalServerError)`,
			expected: 1,
		},
		{
			name: "with logger on response path",
			body: `logger := slog.With("err", err)
			logger.Error("request failed")
			http.Error(w, "request failed", http.StatusInternalServerError)`,
		},
		{
			name: "log after response covers it",
			body: `http.Error(w, "internal failure", http.StatusInternalServerError)
			slog.Error("request failed", "err", err)`,
		},
		{
			name: "response in immediately called function literal",
			body: `slog.Error("request failed", "err", err)
			func() { http.Error(w, "internal failure", 500) }()`,
		},
		{
			name: "response in deferred function literal",
			body: `slog.Error("request failed", "err", err)
			defer func() { http.Error(w, "internal failure", 500) }()`,
		},
		{
			name: "response in if condition",
			body: `slog.Error("request failed", "err", err)
			if writeError(w, 500, "internal failure") != nil { return }`,
		},
		{
			name: "second response without a log is reported",
			body: `if retry {
			slog.Error("retrying", "err", err)
			http.Error(w, "internal failure", 500)
			return
		}
		http.Error(w, "service failure", 500)`,
			expected: 1,
		},
		{
			name: "log in immediately called function literal",
			body: `func() { slog.Error("request failed", "err", err) }()
			http.Error(w, "internal failure", 500)`,
		},
		{
			name: "stored response closure after log",
			body: `respond := func() { http.Error(w, "internal failure", 500) }
			slog.Error("request failed", "err", err)
			respond()`,
		},
		{
			name: "stored logger closure uses unexpanded-literal fallback",
			body: `logIt := func() { slog.Error("request failed", "err", err) }
			logIt()
			http.Error(w, "internal failure", 500)`,
		},
		{
			name: "nested error construction inside logger is not a response",
			body: `log.Println(errors.New("internal failure"), err)
			http.Error(w, "internal failure", 500)`,
		},
		{
			name: "unreached once callback uses whole-branch logged fallback",
			body: `slog.Error("request failed", "err", err)
			once.Do(func() { http.Error(w, "internal failure", 500) })`,
		},
		{
			name: "recursive function literal with an unexpanded log uses fallback",
			body: `var again func(k int)
			again = func(k int) { slog.Error("request failed", "err", err); if k > 0 { again(k - 1) } }
			again(3)
			http.Error(w, "internal failure", http.StatusInternalServerError)`,
		},
		{
			name: "mutually recursive literals with an unexpanded log use fallback",
			body: `var ping, pong func()
			ping = func() { slog.Error("request failed", "err", err); pong() }
			pong = func() { ping() }
			ping()
			http.Error(w, "internal failure", http.StatusInternalServerError)`,
		},
		{
			name: "inner function literal binding does not shadow outer call after block",
			body: `respond := func() {
				slog.Error("request failed", "err", err)
				http.Error(w, "internal failure", 500)
			}
			{
				respond := func() { http.Error(w, "internal failure", 500) }
				_ = respond
			}
			respond()`,
		},
		{
			name: "reassignment to plain function uses unexpanded-literal fallback",
			body: `logIt := func() { slog.Error("request failed", "err", err) }
			logIt = plain
			logIt()
			http.Error(w, "internal failure", 500)`,
		},
		{
			name: "callback argument log uses unexpanded-literal fallback",
			body: `run(func() { slog.Error("request failed", "err", err) })
			http.Error(w, "internal failure", 500)`,
		},
		{
			name: "struct field log uses unexpanded-literal fallback",
			body: `h := hooks{logIt: func() { slog.Error("request failed", "err", err) }}
			h.logIt()
			http.Error(w, "internal failure", 500)`,
		},
		{
			name: "nested local literal log uses unexpanded-literal fallback",
			body: `c := func() { slog.Error("request failed", "err", err) }
			b := func() { c() }
			a := func() { b() }
			a()
			http.Error(w, "internal failure", 500)`,
		},
		{
			name: "select then log preserves response path",
			body: `http.Error(w, "internal failure", 500)
			select { case <-ch: default: }
			slog.Error("request failed", "err", err)`,
		},
		{
			name: "select with unexpanded local log uses fallback",
			body: `logIt := func() { slog.Error("request failed", "err", err) }
			select { case <-ch: default: }
			logIt()
			http.Error(w, "internal failure", 500)`,
		},
		{
			name: "switch case local literal does not leak binding",
			body: `respond := func() {
				slog.Error("request failed", "err", err)
				http.Error(w, "internal failure", 500)
			}
			switch n {
			case 1:
			case 2:
				respond := func() { http.Error(w, "internal failure", 500) }
				_ = respond
			}
			respond()`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code := `package h
import (
	"errors"
	"log"
	"log/slog"
	"net/http"
)
func handle(w http.ResponseWriter, retry bool, items []int) {
	err := load()
	if err != nil {
		` + tt.body + `
	}
}
func load() error { return nil }`
			code += `
func plain() {}
type hooks struct { logIt func() }
func run(func()) {}`
			assert.Len(t, analyzeGoSnippet(t, rule, code), tt.expected, "code:\n%s", code)
		})
	}
}

func TestErrorCauseDroppedFlowExitPaths(t *testing.T) {
	tests := []struct {
		name string
		code string
	}{
		{
			name: "break",
			code: `package h
import "net/http"
func handle(w http.ResponseWriter, err error) {
	for {
		if err != nil {
			http.Error(w, "internal failure", 500)
			break
		}
		break
	}
}`,
		},
		{
			name: "continue",
			code: `package h
import "net/http"
func handle(w http.ResponseWriter, err error) {
	for retry := true; retry; retry = false {
		if err != nil {
			http.Error(w, "internal failure", 500)
			continue
		}
	}
}`,
		},
		{
			name: "goto out of branch",
			code: `package h
import "net/http"
func handle(w http.ResponseWriter, err error) {
	if err != nil {
		http.Error(w, "internal failure", 500)
		goto end
	}
end:
}`,
		},
		{
			name: "labeled break out of branch",
			code: `package h
import "net/http"
func handle(w http.ResponseWriter, err error) {
outer:
	for {
		if err != nil {
			http.Error(w, "internal failure", 500)
			break outer
		}
		break outer
	}
}`,
		},
		{
			name: "pending response survives another branch return",
			code: `package h
import "log/slog"
import "net/http"
func handle(w http.ResponseWriter, err error, retry bool) {
	for {
		if err != nil {
			http.Error(w, "internal failure", 500)
			if retry {
				slog.Error("retrying", "err", err)
				return
			}
			break
		}
		break
	}
}
	`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Len(t, analyzeGoSnippet(t, NewErrorCauseDroppedRule(), tt.code), 1)
		})
	}
}

func analyzeSecurityRule(t *testing.T, rule interface {
	AnalyzeFile(*core.FileContext) []*core.Violation
}, code string) []*core.Violation {
	t.Helper()
	ctx := core.NewFileContext("/src/handler.go", "/src", []byte(code), core.DefaultConfig())
	parser := core.NewParser()
	fset, astFile, err := parser.ParseGoFile("/src/handler.go", []byte(code))
	require.NoError(t, err)
	ctx.SetGoAST(fset, astFile)
	return rule.AnalyzeFile(ctx)
}

func TestErrorCauseDropped_GoSkipsTests(t *testing.T) {
	rule := NewErrorCauseDroppedRule()
	code := `package s
import "errors"
func helper() error {
	if err := do(); err != nil {
		return errors.New("helper failed")
	}
	return nil
}`
	ctx := core.NewFileContext("/src/helper_test.go", "/src", []byte(code), core.DefaultConfig())
	parser := core.NewParser()
	fset, astFile, err := parser.ParseGoFile("/src/helper_test.go", []byte(code))
	require.NoError(t, err)
	ctx.SetGoAST(fset, astFile)
	assert.Empty(t, rule.AnalyzeFile(ctx))
}

func TestErrorCauseDropped_TS(t *testing.T) {
	rule := NewErrorCauseDroppedRule()

	tests := []struct {
		name     string
		code     string
		expected int
	}{
		{
			name: "catch logs and toasts a literal — flagged",
			code: `async function save() {
  try {
    await api.save(form)
  } catch (error) {
    console.error('save failed', error)
    toast.error('Не удалось сохранить')
  }
}`,
			expected: 1,
		},
		{
			name: "catch without binding and a state message — flagged",
			code: `const onSubmit = async () => {
  try {
    await submit()
  } catch {
    setErrorMessage('Something went wrong')
  }
}`,
			expected: 1,
		},
		{
			name: "rethrow as a fresh literal error — flagged",
			code: `export async function load() {
  try {
    return await fetchIt()
  } catch (e) {
    logger.error(e)
    throw new Error('load failed')
  }
}`,
			expected: 1,
		},
		{
			name: "message built from the error — ok",
			code: `const run = async () => {
  try {
    await act()
  } catch (error) {
    logger.error('act failed:', error)
    const errorMessage = getErrorMessage(error, 'act')
    setErrorAlert({ isOpen: true, message: ` + "`Не удалось выполнить действие: ${errorMessage}`" + ` })
  }
}`,
			expected: 0,
		},
		{
			name:     "message interpolates the error directly — ok",
			code:     `try { go() } catch (e) { toast.error(` + "`Failed: ${e}`" + `) }`,
			expected: 0,
		},
		{
			name: "branch on the error before the text — ok",
			code: `try {
  await go()
} catch (err) {
  if (err instanceof ApiError && err.status === 409) {
    toast.error('Уже выполнено, обновите список')
  } else {
    throw err
  }
}`,
			expected: 0,
		},
		{
			name: "ternary reads err.message — not a fixed text",
			code: `const restore = async () => {
  try {
    await restoreCookie()
  } catch (err) {
    logger.log('restore skipped:', err instanceof Error ? err.message : 'unknown')
  }
  return false
}`,
			expected: 0,
		},
		{
			name: "a brace inside a string or comment does not end the block — flagged",
			code: `async function load() {
  try {
    await api.load()
  } catch (error) {
    console.error('load failed: }', error) // closes with }
    setMessage('Could not load')
  }
}`,
			expected: 1,
		},
		{
			name: "a brace inside a string does not hide a later use — ok",
			code: `async function load() {
  try {
    await api.load()
  } catch (error) {
    setMessage('Could not load }')
    report(error)
  }
}`,
			expected: 0,
		},
		{
			name:     "rethrown as is — ok",
			code:     `try { go() } catch (e) { console.error(e); throw e }`,
			expected: 0,
		},
		{
			name:     "silent catch (no message) — frontend-silent-catch territory",
			code:     `try { go() } catch (e) { console.error(e) }`,
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := core.NewFileContext("/src/app/page.tsx", "/src", []byte(tt.code), core.DefaultConfig())
			violations := rule.AnalyzeFile(ctx)
			assert.Len(t, violations, tt.expected, "code:\n%s", tt.code)
		})
	}
}

func TestErrorCauseDropped_TSSkipsTestsAndE2E(t *testing.T) {
	rule := NewErrorCauseDroppedRule()
	code := `try { go() } catch { toast.error('nope') }`
	for _, path := range []string{"/src/e2e/flow.spec.ts", "/src/app/page.test.tsx", "/src/node_modules/x/index.js"} {
		ctx := core.NewFileContext(path, "/src", []byte(code), core.DefaultConfig())
		assert.Empty(t, rule.AnalyzeFile(ctx), path)
	}
}

func TestErrorCauseDropped_TSReportsCatchLine(t *testing.T) {
	rule := NewErrorCauseDroppedRule()
	code := `async function save() {
  try {
    await api.save()
  } catch (error) {
    console.error(error)
    toast.error('Не удалось сохранить')
  } finally {
    setBusy(false)
  }
}`
	ctx := core.NewFileContext("/src/app/page.tsx", "/src", []byte(code), core.DefaultConfig())
	violations := rule.AnalyzeFile(ctx)
	require.Len(t, violations, 1)
	assert.Equal(t, 4, violations[0].Line, "the finding points at the catch, not at the end of the block")
}
