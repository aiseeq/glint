package patterns

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
)

func decisionProject(t *testing.T, files map[string]string) *core.GoProjectContext {
	t.Helper()
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.com/decision\n\ngo 1.24\n"), 0o644))

	var contexts []*core.FileContext
	for name, source := range files {
		path := filepath.Join(root, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(source), 0o644))
		ctx, err := core.NewFileContextChecked(path, root, []byte(source), core.DefaultConfig())
		require.NoError(t, err)
		contexts = append(contexts, ctx)
	}

	project, err := core.LoadGoProject(root, contexts, core.GoProjectOptions{})
	require.NoError(t, err)
	return project
}

func analyzeDecision(t *testing.T, source string) []*core.Violation {
	t.Helper()
	violations, err := NewIgnoredDecisionResultRule().AnalyzeGoProject(decisionProject(t, map[string]string{"budget.go": source}))
	require.NoError(t, err)
	return violations
}

// Repro from a real project: Buy answers "was there enough" and the caller
// dropped the answer, so the order went out with no resources behind it.
func TestIgnoredDecisionResultReportsDroppedBuy(t *testing.T) {
	violations := analyzeDecision(t, `package budget

type Wallet struct {
	Money float64
}

// Buy reserves the amount for this frame. It returns false when the money is
// not there and the order must not be issued.
func (w *Wallet) Buy(amount float64) bool {
	if w.Money < amount {
		return false
	}
	w.Money -= amount
	return true
}

func Place(w *Wallet, amount float64) string {
	w.Buy(amount)
	return "ordered"
}
`)

	require.Len(t, violations, 1)
	assert.Equal(t, 18, violations[0].Line)
	assert.Contains(t, violations[0].Message, "Buy")
}

// The blank identifier states the intent no better: the decision is still gone.
func TestIgnoredDecisionResultReportsBlankAssignment(t *testing.T) {
	violations := analyzeDecision(t, `package budget

type Pool struct{}

// Reserve takes one slot and reports whether a slot was free.
func (p *Pool) Reserve() bool { return true }

func Take(p *Pool) {
	_ = p.Reserve()
}
`)

	require.Len(t, violations, 1)
	assert.Contains(t, violations[0].Message, "Reserve")
}

// A (value, ok) pair whose ok is dropped hides the same decision.
func TestIgnoredDecisionResultReportsDroppedOk(t *testing.T) {
	violations := analyzeDecision(t, `package budget

type Store struct{}

// TryGet returns the entry and false when nothing is stored under the key.
func (s *Store) TryGet(key string) (int, bool) { return 0, false }

func Read(s *Store) int {
	value, _ := s.TryGet("k")
	return value
}
`)

	require.Len(t, violations, 1)
	assert.Contains(t, violations[0].Message, "TryGet")
}

// Using the result — in a condition, in an assignment, as an argument — is the
// normal case and must stay quiet.
func TestIgnoredDecisionResultAcceptsUsedResult(t *testing.T) {
	violations := analyzeDecision(t, `package budget

type Wallet struct {
	Money float64
}

// Buy returns false when the money is not there.
func (w *Wallet) Buy(amount float64) bool { return w.Money >= amount }

func Place(w *Wallet, amount float64) string {
	if !w.Buy(amount) {
		return ""
	}
	ok := w.Buy(amount)
	if !ok {
		return ""
	}
	return "ordered"
}
`)

	assert.Empty(t, violations)
}

// A bool that is not a decision — a plain predicate name, no promise in the doc
// — is out of scope: dropping it is pointless but not a resource bug.
func TestIgnoredDecisionResultAcceptsNonDecisionBool(t *testing.T) {
	violations := analyzeDecision(t, `package budget

type Wallet struct{}

// Ready reports whether the wallet is initialized.
func (w *Wallet) Ready() bool { return true }

func Warm(w *Wallet) {
	w.Ready()
}
`)

	assert.Empty(t, violations)
}

// A function that returns something else besides the bool answer, or nothing at
// all, is not this rule's subject.
func TestIgnoredDecisionResultAcceptsNonBoolResult(t *testing.T) {
	violations := analyzeDecision(t, `package budget

type Wallet struct{}

// TryFetch loads the value.
func (w *Wallet) TryFetch() (int, error) { return 0, nil }

// CanRun starts the worker.
func (w *Wallet) CanRun() {}

func Use(w *Wallet) {
	w.TryFetch()
	w.CanRun()
}
`)

	assert.Empty(t, violations)
}

// False positive from a real project: an idempotent claim returns
// (claimed, error), the caller handles the error and drops the "it was already
// claimed" note on purpose. The bool is not the last result, so it is not the
// comma-ok answer this rule is about.
func TestIgnoredDecisionResultAcceptsBoolBeforeError(t *testing.T) {
	violations := analyzeDecision(t, `package budget

import "errors"

type Repo struct{}

// ClaimIntent records the intent once. Returns false if it was already recorded.
func (r *Repo) ClaimIntent(id int) (bool, error) { return false, errors.New("x") }

func Record(r *Repo, id int) error {
	if _, err := r.ClaimIntent(id); err != nil {
		return err
	}
	return nil
}
`)

	assert.Empty(t, violations)
}

// Test helpers are allowed to call a decision for its side effect while the
// assertion lives elsewhere.
func TestIgnoredDecisionResultSkipsTestFiles(t *testing.T) {
	violations, err := NewIgnoredDecisionResultRule().AnalyzeGoProject(decisionProject(t, map[string]string{
		"budget.go": `package budget

type Wallet struct{}

// Buy returns false when the money is not there.
func (w *Wallet) Buy(amount float64) bool { return true }
`,
		"budget_test.go": `package budget

import "testing"

func TestBuy(t *testing.T) {
	w := &Wallet{}
	w.Buy(1)
}
`,
	}))
	require.NoError(t, err)
	assert.Empty(t, violations)
}

// A resolver answers a malformed input with a widened fallback and an invalid
// flag; the caller reads the flag only to log it and then lists with the
// fallback, so a bad filter shows everything the user may see instead of a
// refusal. A branch that refuses keeps the flag's meaning.
func TestIgnoredDecisionResultReportsFlagReadOnlyByLog(t *testing.T) {
	violations := analyzeDecision(t, `package budget

import "log/slog"

func resolveScope(text string, allowed []int) (ids []int, selected int, invalid bool) {
	if text == "" {
		return allowed, 0, false
	}
	return allowed, 0, true
}

func list(logger *slog.Logger, text string, allowed []int) []int {
	ids, _, invalid := resolveScope(text, allowed)
	if invalid {
		logger.Warn("invalid scope", "scope", text)
	}
	return ids
}

func export(logger *slog.Logger, text string, allowed []int) ([]int, bool) {
	ids, _, invalid := resolveScope(text, allowed)
	if invalid {
		logger.Warn("invalid scope", "scope", text)
		return nil, false
	}
	return ids, true
}
`)
	require.Len(t, violations, 1)
	assert.Equal(t, 14, violations[0].Line)
}

// Repro from a real project: Download skips a file already on disk and says
// so with (false, nil); the caller dropped the bool and logged the old file
// as freshly downloaded.
func TestIgnoredDecisionResultReportsDoneFlagWithSuccessLog(t *testing.T) {
	violations := analyzeDecision(t, `package budget

import (
	"log/slog"
	"os"
)

type Client struct{}

// Download stores u in dst, skipping a dst that already exists.
func (c *Client) Download(u, dst string) (bool, error) {
	if _, err := os.Stat(dst); err == nil {
		return false, nil
	}
	return true, nil
}

func Pull(c *Client, u, dst string) {
	if _, err := c.Download(u, dst); err != nil {
		slog.Warn("bot data", "err", err)
	} else {
		slog.Info("bot data downloaded", "file", dst)
	}
}
`)

	require.Len(t, violations, 1)
	assert.Equal(t, 19, violations[0].Line)
	assert.Contains(t, violations[0].Message, "Download")
}
