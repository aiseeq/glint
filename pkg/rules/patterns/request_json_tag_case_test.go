package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
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

func createInvestment(w http.ResponseWriter, r *http.Request) {
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
	assert.Equal(t, []string{"api/handlers.go:11", "api/handlers.go:12"}, foundLines(violations))
}
