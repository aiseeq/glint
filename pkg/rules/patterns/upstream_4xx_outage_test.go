package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// The provider's client keeps the HTTP status of a refusal, yet the handler
// answers every failure of the call with 502: a corridor the provider
// declines (400) is reported as its outage, and the operator sees an empty
// form instead of the reason.
func TestUpstream4xxReportedAsOutage(t *testing.T) {
	files := map[string]string{
		"payprov/client.go": `package payprov

import (
	"context"
	"fmt"
)

type APIError struct {
	StatusCode int
	Message    string
}

func (e *APIError) Error() string { return fmt.Sprintf("payprov %d: %s", e.StatusCode, e.Message) }

type Client struct{}

func (c *Client) Banks(ctx context.Context, country string) ([]string, error) {
	return nil, &APIError{StatusCode: 400, Message: "corridor not served"}
}
`,
		"provider/provider.go": `package provider

import (
	"context"

	"example.com/rulestest/payprov"
)

type Metadata interface {
	Banks(ctx context.Context, country string) ([]string, error)
}

type Adapter struct{ client *payprov.Client }

func (a *Adapter) Banks(ctx context.Context, country string) ([]string, error) {
	return a.client.Banks(ctx, country)
}
`,
		"store/store.go": `package store

import "context"

type Repo struct{}

func (r *Repo) Banks(ctx context.Context, country string) ([]string, error) { return nil, nil }
`,
		"admin/handlers.go": `package admin

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"example.com/rulestest/payprov"
	"example.com/rulestest/provider"
	"example.com/rulestest/store"
)

type Admin struct {
	logger   *slog.Logger
	metadata provider.Metadata
	repo     *store.Repo
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func (a *Admin) handleBanks(w http.ResponseWriter, r *http.Request) {
	banks, err := a.metadata.Banks(r.Context(), r.URL.Query().Get("country"))
	if err != nil {
		a.logger.Error("failed to get banks", "error", err)
		writeJSONError(w, http.StatusBadGateway, "provider bank list is unavailable") // want upstream-4xx-reported-as-outage
		return
	}
	_ = json.NewEncoder(w).Encode(banks)
}

func (a *Admin) handleBanksClassified(w http.ResponseWriter, r *http.Request) {
	banks, err := a.metadata.Banks(r.Context(), r.URL.Query().Get("country"))
	if err != nil {
		var apiErr *payprov.APIError
		if errors.As(err, &apiErr) && apiErr.StatusCode < 500 {
			writeJSONError(w, http.StatusUnprocessableEntity, apiErr.Message)
			return
		}
		writeJSONError(w, http.StatusBadGateway, "provider bank list is unavailable")
		return
	}
	_ = json.NewEncoder(w).Encode(banks)
}

// handleStored reads our own database: a failure there is ours.
func (a *Admin) handleStored(w http.ResponseWriter, r *http.Request) {
	banks, err := a.repo.Banks(r.Context(), "x")
	if err != nil {
		writeJSONError(w, http.StatusServiceUnavailable, "store unavailable")
		return
	}
	_ = json.NewEncoder(w).Encode(banks)
}
`,
	}
	violations, err := NewUpstream4xxReportedAsOutageRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	assert.Equal(t, wantedLines(files, "upstream-4xx-reported-as-outage"), foundLines(violations))
}
