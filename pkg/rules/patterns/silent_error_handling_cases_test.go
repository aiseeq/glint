package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

const silentRatesSource = `package rates

import "strconv"

type Rate struct{ V int }

func LatestA(s string) *Rate {
	v, err := strconv.Atoi(s)
	if err != nil {
		return nil
	}
	return &Rate{V: v}
}
`

// Only test files are skipped: latest_rates.go contains "test_" and a
// testimonials directory starts with "/test", yet both are production code.
func TestSilentErrorHandling_ProductionFilesWithTestLikeNames(t *testing.T) {
	for _, path := range []string{"rates/latest_rates.go", "web/testimonials/rates.go", "rates/test.go"} {
		t.Run(path, func(t *testing.T) {
			ctx := rulestest.GoFile(t, path, silentRatesSource)
			assert.Equal(t, []int{9}, violationLines(NewSilentErrorHandlingRule().AnalyzeFile(ctx)))
		})
	}
}

// A declared function answering with one bool leaves its error branches that
// return true/false to error-masked-as-false-bool and error-masking; the same
// branch is not reported by two rules.
func TestSilentErrorHandling_BoolFunctionBranchBelongsToBoolRules(t *testing.T) {
	const source = `package p

import "strconv"

func Publish(s string) bool {
	_, err := strconv.Atoi(s)
	if err != nil {
		return false
	}
	return true
}

func Process(s string) bool {
	_, err := strconv.Atoi(s)
	if err != nil {
		return false
	}
	return true
}
`
	ctx := rulestest.GoFile(t, "p/p.go", source)
	assert.Empty(t, NewSilentErrorHandlingRule().AnalyzeFile(ctx))
}

// A branch that answers the client through the handler's http.ResponseWriter
// has reported the failure, whatever the responder helper is called; a CLI
// branch that writes to stderr and returns an exit code has reported it too.
// A logger obtained from a factory call is still a logger, and the cause
// travelling inside a concatenated message or a field of the error value is
// still the cause. A branch that does none of that stays reported.
func TestSilentErrorHandling_ReportedThroughResponseStderrOrMessage(t *testing.T) {
	const source = `package payprov

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
)

type paramError struct{ message, details string }

func (e *paramError) Error() string { return e.message }

func parseQuery(s string) (int, *paramError) { return 0, nil }

func HandleLimit(w http.ResponseWriter, req *http.Request) {
	_, err := strconv.Atoi(req.URL.Query().Get("limit"))
	if err != nil {
		apihttp.RejectInput(w, req, "limit must be a number", "")
		return
	}
	var body map[string]any
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		writeProblem(w, http.StatusBadRequest)
		return
	}
	if from, parseErr := strconv.Atoi(req.URL.Query().Get("from")); parseErr != nil {
		apihttp.Reply(nil, req, "invalid 'from': "+parseErr.Error())
		return
	} else {
		_ = from
	}
	_, queryErr := parseQuery(req.URL.RawQuery)
	if queryErr != nil {
		apihttp.Reply(nil, req, queryErr.message, queryErr.details)
		return
	}
}

func writeProblem(w http.ResponseWriter, status int) { w.WriteHeader(status) }

func validateCommand() int {
	_, err := strconv.Atoi(os.Getenv("PAYPROV_LIMIT"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "payprov limit is invalid")
		return 2
	}
	return 0
}

func decodeMetadata(payload string) map[string]any {
	raw := map[string]any{}
	if err := json.Unmarshal([]byte(payload), &raw); err != nil {
		obs.DefaultLogger().Debug("skipping unparseable metadata: " + err.Error())
		return nil
	}
	return raw
}

func quietLimit(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return n
}
`
	ctx := rulestest.GoFile(t, "payprov/handlers.go", source)
	assert.Equal(t, []int{63}, violationLines(NewSilentErrorHandlingRule().AnalyzeFile(ctx)))
}
