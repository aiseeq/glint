package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// A middleware wrapping the writer to capture the status hides Flush: a
// streaming handler asserting http.Flusher behind it fails.
func TestResponseWriterWrapperHidesFlush(t *testing.T) {
	files := map[string]string{
		"mw/status.go": `package mw

import "net/http"

type statusWriter struct { // want response-writer-wrapper-hides-flush
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

type flushingWriter struct {
	http.ResponseWriter
	status int
}

func (w *flushingWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

type unwrappingWriter struct {
	http.ResponseWriter
}

func (w *unwrappingWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

type holder struct {
	w      http.ResponseWriter
	status int
}
`,
	}
	violations, err := NewResponseWriterWrapperRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	assert.Equal(t, wantedLines(files, "response-writer-wrapper-hides-flush"), foundLines(violations))
}
