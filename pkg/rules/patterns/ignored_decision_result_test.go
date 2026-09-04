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
