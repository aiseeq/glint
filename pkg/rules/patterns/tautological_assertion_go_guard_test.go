package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func tautologicalGoLines(t *testing.T, code string) []int {
	t.Helper()
	ctx := createPatternContext(t, "service_test.go", code)
	return violationLines(NewTautologicalAssertionRule().AnalyzeFile(ctx))
}

// An assertion that runs only when the value is there: when it is not, the
// test passes without checking anything.
func TestTautologicalAssertion_GoGuardedAssertion(t *testing.T) {
	code := `package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type Withdrawal struct{ TransactionID *string }

func TestProtocol(t *testing.T) {
	response := map[string]any{}
	if data, ok := response["data"].(map[string]any); ok {
		if inner, ok := data["success"].(bool); ok {
			assert.False(t, inner)
		}
	}
	id, ok := response["id"].(string)
	require.True(t, ok)
	assert.NotEmpty(t, id)
	if v, ok := response["v"].(string); ok {
		assert.Equal(t, "x", v)
	} else {
		t.Fatal("no v")
	}
}

func TestAbsence(t *testing.T) {
	seen := map[string]bool{}
	if _, ok := seen["raw"]; ok {
		t.Fatal("raw units must not surface")
	}
	for _, id := range []string{"a"} {
		if _, ok := seen[id]; ok {
			assert.True(t, seen[id])
		}
	}
}

func TestWithdrawal(t *testing.T) {
	w := Withdrawal{}
	if w.TransactionID == nil {
		t.Logf("transaction not created yet")
	} else {
		assert.NotEmpty(t, *w.TransactionID)
	}
}
`
	assert.Equal(t, []int{14, 15, 43}, tautologicalGoLines(t, code))
}

// A test that skips when the code under test fails reports the failure as a
// skip: the suite stays green.
func TestTautologicalAssertion_GoSkipOnFailure(t *testing.T) {
	code := `package service

import (
	"net/http"
	"os/exec"
	"testing"
)

type Client struct{}

func (c *Client) Get(path string) (*http.Response, error) { return nil, nil }

func setup(t *testing.T) (*Client, error) { return &Client{}, nil }

func TestSearch(t *testing.T) {
	client, err := setup(t)
	if err != nil || client == nil {
		t.Skipf("no admin client: %v", err)
	}
	resp, getErr := client.Get("/api/users")
	if getErr != nil {
		t.Skipf("server unavailable: %v", getErr)
	}
	if resp.StatusCode != http.StatusOK {
		t.Skipf("API returned %d", resp.StatusCode)
	}
}

func TestParserAccepts(t *testing.T) {
	_, err := setup(t)
	if err == nil {
		t.Skip("parser accepted the file on this version")
	}
}

func TestTool(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not installed")
	}
}
`
	assert.Equal(t, []int{18, 22, 25}, tautologicalGoLines(t, code))
}

// A test helper that skips a fixture it failed to read or decode: the broken
// fixture drops out of the check and the test stays green. A missing optional
// path probed with os.Stat is the environment; a branch with a comment says
// the failure is the expected outcome.
func TestTautologicalAssertion_GoFixtureDroppedOnError(t *testing.T) {
	code := `package service

import (
	"encoding/json"
	"os"
	"path/filepath"
)

type Article struct{ Title string }

func loadArticles(dir string) ([]Article, error) {
	files, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var articles []Article
	for _, file := range files {
		if filepath.Ext(file.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, file.Name()))
		if err != nil {
			continue
		}
		var article Article
		if err := json.Unmarshal(data, &article); err != nil {
			continue
		}
		articles = append(articles, article)
	}
	for _, extra := range []string{"a", "b"} {
		if _, err := os.Stat(extra); err != nil {
			continue
		}
		if _, err := os.ReadFile(extra); err != nil {
			continue // a refused read is the behaviour under test
		}
	}
	return articles, nil
}
`
	assert.Equal(t, []int{22, 26}, tautologicalGoLines(t, code))
}

// A guard anywhere inside a loop filters the items the test is about; the
// completeness is checked after the loop. A guard whose body returns falls
// through to a failure when the value is not there.
func TestTautologicalAssertion_GoGuardWithFailurePath(t *testing.T) {
	code := `package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStrategies(t *testing.T) {
	items := []map[string]any{}
	found := map[string]bool{"basic": false}
	for _, s := range items {
		if name, ok := s["name"].(string); ok {
			if _, want := found[name]; want {
				found[name] = true
				assert.Contains(t, s, "description")
			}
		} else {
			assert.IsType(t, "", s["name"])
		}
	}
	for name, f := range found {
		assert.True(t, f, name)
	}
}

func listOf(t *testing.T, resp map[string]any) []any {
	if m, ok := resp["data"].(map[string]any); ok {
		if items, has := m["items"]; has {
			list, ok := items.([]any)
			require.True(t, ok)
			return list
		}
	}
	t.Fatalf("unexpected shape: %T", resp["data"])
	return nil
}

func TestShape(t *testing.T) {
	resp := map[string]any{}
	if m, ok := resp["data"].(map[string]any); ok {
		assert.NotEmpty(t, m["items"])
	}
}
`
	assert.Equal(t, []int{42}, tautologicalGoLines(t, code))
}
