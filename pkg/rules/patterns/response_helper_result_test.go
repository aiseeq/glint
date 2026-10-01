package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// A helper that writes the error response itself answers false; the handler
// that drops the answer goes on and writes a second response.
func TestResponseHelperResultIgnored(t *testing.T) {
	files := map[string]string{
		"go.mod": "module example.com/rulestest\n\ngo 1.24\n",
		"web/helpers.go": `package web

import (
	"encoding/json"
	"net/http"
)

func ParseJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	if err := json.NewDecoder(r.Body).Decode(target); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return false
	}
	return true
}

func Authorized(r *http.Request) bool { return r.Header.Get("Authorization") != "" }

func WriteJSON(w http.ResponseWriter, value any) error {
	return json.NewEncoder(w).Encode(value)
}
`,
		"web/handlers.go": `package web

import "net/http"

type note struct{ Text string }

func Process(w http.ResponseWriter, r *http.Request) {
	var body note
	_ = ParseJSON(w, r, &body)
	ParseJSON(w, r, &body)
	if !ParseJSON(w, r, &body) {
		return
	}
	ok := ParseJSON(w, r, &body)
	if !ok {
		return
	}
	_ = Authorized(r)
	_ = WriteJSON(w, body)
}

// The helper is the last thing the handler does: nothing follows that could
// write again, the answer has nobody to stop.
func Dispatch(w http.ResponseWriter, r *http.Request) {
	var body note
	if r.Method == http.MethodPut {
		ParseJSON(w, r, &body)
	} else {
		_ = ParseJSON(w, r, &body)
	}
}
`,
	}
	violations, err := NewResponseHelperResultIgnoredRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	assert.Equal(t, []string{"web/handlers.go:10", "web/handlers.go:9"}, foundLines(violations))
}
