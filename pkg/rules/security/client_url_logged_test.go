package security

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// A URL a browser reports about itself (a CSP report's document-uri, the
// Referer) carries the page's query: tokens and codes there go into the log
// with it. A URL cut to its path first, or a field that is not a URL, is fine.
func TestClientURLLoggedWithQuery(t *testing.T) {
	code := `package routing

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
)

type violation struct {
	DocumentURI string ` + "`json:\"document-uri\"`" + `
	BlockedURI  string ` + "`json:\"blocked-uri\"`" + `
	Directive   string ` + "`json:\"violated-directive\"`" + `
}

type envelope struct {
	Report violation ` + "`json:\"csp-report\"`" + `
}

func truncate(s string) string { return s[:min(len(s), 512)] }

func urlWithoutQuery(s string) string {
	if i := strings.IndexAny(s, "?#"); i >= 0 {
		return s[:i]
	}
	return s
}

func handleReport(logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return
		}
		var env envelope
		if err := json.Unmarshal(body, &env); err != nil {
			return
		}
		report := env.Report
		logger.Warn("csp violation",
			"document_uri", truncate(report.DocumentURI),
			"blocked_uri", urlWithoutQuery(report.BlockedURI),
			"directive", truncate(report.Directive),
			"referer", r.Referer())
	}
}

func handleConfig(logger *slog.Logger, cfg violation) {
	logger.Info("config", "uri", cfg.DocumentURI)
}
`
	assert.Equal(t, []int{42, 45}, ruleLines(t, NewClientURLLoggedRule(), code))
}
