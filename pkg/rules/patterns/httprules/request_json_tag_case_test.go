package httprules

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patterntest"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/tools/go/packages"
)

// The project names every JSON key in lowerCamel; one handler decodes its
// request into fields tagged "StrategyID" and "Amount", the client posts
// strategyId and amount, and every request arrives empty.
func TestRequestJSONTagCase(t *testing.T) {
	violations, err := NewRequestJSONTagCaseRule().AnalyzeGoProject(rulestest.Project(t, map[string]string{
		"api/models.go": `package api

type Transfer struct {
	ID        string ` + "`json:\"id\"`" + `
	UserID    string ` + "`json:\"userId\"`" + `
	Balance   string ` + "`json:\"balance\"`" + `
	Currency  string ` + "`json:\"currency\"`" + `
	CreatedAt string ` + "`json:\"createdAt\"`" + `
	UpdatedAt string ` + "`json:\"updatedAt\"`" + `
	Status    string ` + "`json:\"status\"`" + `
	Network   string ` + "`json:\"network\"`" + `
	Address   string ` + "`json:\"address\"`" + `
	Label     string ` + "`json:\"label,omitempty\"`" + `
}

type Payout struct {
	ID        string ` + "`json:\"id\"`" + `
	UserID    string ` + "`json:\"userId\"`" + `
	Balance   string ` + "`json:\"balance\"`" + `
	Currency  string ` + "`json:\"currency\"`" + `
	CreatedAt string ` + "`json:\"createdAt\"`" + `
	UpdatedAt string ` + "`json:\"updatedAt\"`" + `
	Status    string ` + "`json:\"status\"`" + `
	Network   string ` + "`json:\"network\"`" + `
	Address   string ` + "`json:\"address\"`" + `
	Label     string ` + "`json:\"label,omitempty\"`" + `
}

type Account struct {
	ID        string ` + "`json:\"id\"`" + `
	UserID    string ` + "`json:\"userId\"`" + `
	Balance   string ` + "`json:\"balance\"`" + `
	Currency  string ` + "`json:\"currency\"`" + `
	CreatedAt string ` + "`json:\"createdAt\"`" + `
	UpdatedAt string ` + "`json:\"updatedAt\"`" + `
	Status    string ` + "`json:\"status\"`" + `
	Network   string ` + "`json:\"network\"`" + `
	Address   string ` + "`json:\"address\"`" + `
	Label     string ` + "`json:\"label,omitempty\"`" + `
}

type depositRequest struct {
	Amount  string ` + "`json:\"amount\"`" + `
	Network string ` + "`json:\"network\"`" + `
}

type ProviderQuote struct {
	Rate   string ` + "`json:\"Rate\"`" + `
}
`,
		"api/handlers.go": `package api

import (
	"encoding/json"
	"io"
	"net/http"
)

func createOrder(w http.ResponseWriter, r *http.Request) {
	var req struct {
		StrategyID string ` + "`json:\"StrategyID\"`" + `
		Amount     string ` + "`json:\"Amount\"`" + `
		Note       string ` + "`json:\"note\"`" + `
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
	}
}

func deposit(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return
	}
	var req depositRequest
	_ = json.Unmarshal(body, &req)
}

func fetchQuote(client *http.Client) (*ProviderQuote, error) {
	resp, err := client.Get("https://quotes.example/latest")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var quote ProviderQuote
	return &quote, json.NewDecoder(resp.Body).Decode(&quote)
}
`,
	}))
	require.NoError(t, err)
	assert.Equal(t, []string{"api/handlers.go:11", "api/handlers.go:12"}, patterntest.FoundLines(violations))
}

func TestRequestJSONTagCase_TrimpathNestedReplaceModule(t *testing.T) {
	root, contexts := rulestest.Module(t, map[string]string{
		"go.mod":        "module example.com/app\n\ngo 1.24\n\nrequire example.com/shared v0.0.0\nreplace example.com/shared => ./shared\n",
		"shared/go.mod": "module example.com/shared\n\ngo 1.24\n",
		"shared/request.go": "package shared\n\ntype ID string\n\ntype Input struct {\n" +
			"StrategyID ID `json:\"StrategyID\"`\n" +
			"A string `json:\"a\"`\nB string `json:\"b\"`\nC string `json:\"c\"`\nD string `json:\"d\"`\n" +
			"E string `json:\"e\"`\nF string `json:\"f\"`\nG string `json:\"g\"`\nH string `json:\"h\"`\nI string `json:\"i\"`\n}\n",
		"handler.go": "package app\n\nimport (\"encoding/json\"; \"net/http\"; \"example.com/shared\")\n\n" +
			"func Handle(w http.ResponseWriter, r *http.Request) { var input shared.Input; _ = json.NewDecoder(r.Body).Decode(&input) }\n",
	})
	project, err := core.LoadGoProject(root, contexts, core.GoProjectOptions{ListPackages: func(cfg *packages.Config, patterns ...string) ([]*packages.Package, error) {
		cfg.BuildFlags = []string{"-trimpath"}
		return packages.Load(cfg, patterns...)
	}})
	require.NoError(t, err)
	violations, err := NewRequestJSONTagCaseRule().AnalyzeGoProject(project)
	require.NoError(t, err)
	require.Len(t, violations, 1)
	assert.Equal(t, "shared/request.go", violations[0].File)
	assert.Equal(t, 6, violations[0].Line)
}

// The request type of a nested module that imports "C" is reported in its
// file: cgo type-checks generated files, the trimmed position still names the
// source file.
func TestRequestJSONTagCase_CgoNestedReplaceModule(t *testing.T) {
	rulestest.RequireCgo(t)
	root, contexts := rulestest.Module(t, map[string]string{
		"go.mod":        "module example.com/app\n\ngo 1.24\n\nrequire example.com/shared v0.0.0\nreplace example.com/shared => ./shared\n",
		"shared/go.mod": "module example.com/shared\n\ngo 1.24\n",
		"shared/request.go": "package shared\n\n/*\nstatic int seven(void) { return 7; }\n*/\nimport \"C\"\n\n" +
			"type Input struct {\n\tStrategyID string `json:\"StrategyID\"`\n}\n\nfunc Seven() int { return int(C.seven()) }\n",
		"shared/style.go": "package shared\n\ntype Style struct {\n" +
			"A string `json:\"a\"`\nB string `json:\"b\"`\nC string `json:\"c\"`\nD string `json:\"d\"`\nE string `json:\"e\"`\n" +
			"F string `json:\"f\"`\nG string `json:\"g\"`\nH string `json:\"h\"`\nI string `json:\"i\"`\nJ string `json:\"j\"`\n}\n",
		"handler.go": "package app\n\nimport (\"encoding/json\"; \"net/http\"; \"example.com/shared\")\n\n" +
			"func Handle(w http.ResponseWriter, r *http.Request) { var input shared.Input; _ = json.NewDecoder(r.Body).Decode(&input) }\n",
	})
	project, err := core.LoadGoProject(root, contexts, core.GoProjectOptions{})
	require.NoError(t, err)
	violations, err := NewRequestJSONTagCaseRule().AnalyzeGoProject(project)
	require.NoError(t, err)
	require.Len(t, violations, 1)
	assert.Equal(t, "shared/request.go", violations[0].File)
}

// Two fields of one name and type on one line - one of an anonymous struct -
// do not stop the run: the capitalized one is reported on its line.
func TestRequestJSONTagCase_NamesakeFieldsOnOneLine(t *testing.T) {
	root, contexts := rulestest.Module(t, map[string]string{
		"go.mod":        "module example.com/app\n\ngo 1.24\n\nrequire example.com/shared v0.0.0\nreplace example.com/shared => ./shared\n",
		"shared/go.mod": "module example.com/shared\n\ngo 1.24\n",
		"shared/request.go": "package shared\n\ntype Input struct {\n" +
			"\tMeta struct{ Name string `json:\"name\"` } `json:\"meta\"`; Name string `json:\"Name\"`\n}\n\ntype Style struct {\n" +
			"A string `json:\"a\"`\nB string `json:\"b\"`\nC string `json:\"c\"`\nD string `json:\"d\"`\nE string `json:\"e\"`\n" +
			"F string `json:\"f\"`\nG string `json:\"g\"`\nH string `json:\"h\"`\nI string `json:\"i\"`\nJ string `json:\"j\"`\n}\n",
		"handler.go": "package app\n\nimport (\"encoding/json\"; \"net/http\"; \"example.com/shared\")\n\n" +
			"func Handle(w http.ResponseWriter, r *http.Request) { var input shared.Input; _ = json.NewDecoder(r.Body).Decode(&input) }\n",
	})
	project, err := core.LoadGoProject(root, contexts, core.GoProjectOptions{})
	require.NoError(t, err)
	violations, err := NewRequestJSONTagCaseRule().AnalyzeGoProject(project)
	require.NoError(t, err)
	assert.Equal(t, []string{"shared/request.go:4"}, patterntest.FoundLines(violations))
}
