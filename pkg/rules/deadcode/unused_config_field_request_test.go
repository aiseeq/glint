package deadcode

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// A handler decodes its own request body into a type whose field no code
// reads: the client sends the setting, the request is accepted, and the
// setting does nothing. A response of another service decoded by a client
// stays out — it declares what the other side sends — and so does a model
// shared with responses, whose server-set fields the client does not send.
func TestUnusedConfigFieldReportsIgnoredRequestField(t *testing.T) {
	violations := analyzeConfigFields(t, map[string]string{
		"handler.go": `package api

import (
	"encoding/json"
	"io"
	"net/http"
)

type CreateCardRequest struct {
	Amount     string ` + "`json:\"amount\"`" + `
	AutoInvest *bool  ` + "`json:\"autoRenew,omitempty\"`" + `
	Strategy   string ` + "`json:\"strategy,omitempty\"`" + `
	Ignored    string ` + "`json:\"-\"`" + `
}

type RenameRequest struct {
	Name  string ` + "`json:\"name\"`" + `
	Color string ` + "`json:\"color\"`" + `
}

type Deal struct {
	ID        string ` + "`json:\"id\"`" + `
	CreatedAt string ` + "`json:\"createdAt\"`" + `
}

type ProviderReply struct {
	ID     string ` + "`json:\"id\"`" + `
	Status string ` + "`json:\"status\"`" + `
}

func decodeBody(r *http.Request, dst any) error {
	return json.NewDecoder(r.Body).Decode(dst)
}

func createCard(w http.ResponseWriter, r *http.Request) {
	var req CreateCardRequest
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	_, _ = w.Write([]byte(req.Amount))
}

func rename(w http.ResponseWriter, r *http.Request) {
	var req RenameRequest
	if err := decodeBody(r, &req); err != nil {
		return
	}
	_, _ = w.Write([]byte(req.Name))
}

func createDeal(w http.ResponseWriter, r *http.Request) {
	var deal Deal
	if err := json.NewDecoder(r.Body).Decode(&deal); err != nil {
		return
	}
	_, _ = w.Write([]byte(deal.ID))
}

func fetch(body io.Reader) (string, error) {
	var reply ProviderReply
	if err := json.NewDecoder(body).Decode(&reply); err != nil {
		return "", err
	}
	return reply.ID, nil
}
`,
	})
	var fields []string
	for _, v := range violations {
		fields = append(fields, v.Context["field"].(string))
	}
	assert.Equal(t, []string{"CreateCardRequest.AutoInvest", "CreateCardRequest.Strategy", "RenameRequest.Color"}, fields)
}
