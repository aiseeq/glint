package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// A status-recording wrapper whose WriteHeader overwrites the stored status:
// a timeout middleware writing its 503 after the handler already answered 200
// leaves the log with a failure the client never saw. A guard on the stored
// status or a wroteHeader flag keeps the first code, as net/http does.
func TestResponseWrapperRecordsLastStatus(t *testing.T) {
	files := map[string]string{
		"mw/watch.go": `package mw

import "net/http"

type watchWriter struct {
	http.ResponseWriter
	status int
}

func (w *watchWriter) WriteHeader(code int) {
	w.status = code // want response-wrapper-records-last-status
	w.ResponseWriter.WriteHeader(code)
}

func (w *watchWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

type namedInner struct {
	inner  http.ResponseWriter
	status int
}

func (w *namedInner) Header() http.Header { return w.inner.Header() }

func (w *namedInner) Write(b []byte) (int, error) { return w.inner.Write(b) }

func (w *namedInner) WriteHeader(statusCode int) {
	w.inner.WriteHeader(statusCode)
	w.status = statusCode // want response-wrapper-records-last-status
}

type firstWriter struct {
	http.ResponseWriter
	status int
}

func (w *firstWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *firstWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

type flaggedWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (w *flaggedWriter) WriteHeader(code int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *flaggedWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

type recorder struct {
	status int
}

func (r *recorder) WriteHeader(code int) { r.status = code }
`,
	}
	violations, err := NewResponseWrapperRecordsLastStatusRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	assert.Equal(t, wantedLines(files, "response-wrapper-records-last-status"), foundLines(violations))
}
