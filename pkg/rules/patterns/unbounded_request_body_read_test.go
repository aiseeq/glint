package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

func TestUnboundedRequestBodyReadRule_Metadata(t *testing.T) {
	rule := NewUnboundedRequestBodyReadRule()
	assert.Equal(t, "unbounded-request-body-read", rule.Name())
	assert.Equal(t, "patterns", rule.Category())
	assert.Equal(t, core.SeverityMedium, rule.DefaultSeverity())
	assert.False(t, rule.RequiresSSA())
}

// limitedHandler is the handler that shows the project limits bodies by hand.
const limitedHandler = `package api

import (
	"encoding/json"
	"net/http"
)

type tokenRequest struct{ Token string }

func Token(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1024)
	var body tokenRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad", http.StatusBadRequest)
	}
}
`

func TestUnboundedRequestBodyReadRule_Detection(t *testing.T) {
	tests := []struct {
		name    string
		files   map[string]string
		expects []string
	}{
		{
			// Репро: публичная проверка кода без авторизации декодировала тело
			// без предела, хотя соседние обработчики ставили MaxBytesReader, —
			// строку любой длины держали в памяти целиком.
			name: "a public handler decodes the body without the limit its neighbours set",
			files: map[string]string{
				"api/token.go": limitedHandler,
				"api/codes.go": `package api

import (
	"encoding/json"
	"io"
	"net/http"
)

type codeRequest struct{ Code string }

type Codes struct{}

func (c *Codes) validate(w http.ResponseWriter, req *http.Request) {
	var request codeRequest
	if err := json.NewDecoder(req.Body).Decode(&request); err != nil {
		http.Error(w, "bad", http.StatusBadRequest)
	}
}

func Upload(w http.ResponseWriter, r *http.Request) {
	data, _ := io.ReadAll(r.Body)
	_, _ = w.Write(data)
}
`,
			},
			expects: []string{"api/codes.go:15", "api/codes.go:21"},
		},
		{
			name: "a global body-limit middleware covers every handler",
			files: map[string]string{
				"api/token.go": limitedHandler,
				"api/limit.go": `package api

import "net/http"

func BodyLimit(max int64, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, max)
		next.ServeHTTP(w, r)
	})
}
`,
				"api/codes.go": `package api

import (
	"encoding/json"
	"net/http"
)

func Validate(w http.ResponseWriter, r *http.Request) {
	var v map[string]string
	_ = json.NewDecoder(r.Body).Decode(&v)
}
`,
			},
		},
		{
			name: "a project that limits nowhere is left alone for decoders",
			files: map[string]string{
				"api/codes.go": `package api

import (
	"encoding/json"
	"net/http"
)

func Validate(w http.ResponseWriter, r *http.Request) {
	var v map[string]string
	_ = json.NewDecoder(r.Body).Decode(&v)
}
`,
			},
		},
		{
			// A project with no limit anywhere: the signature middleware and the
			// webhook handler copied the whole raw body into memory.
			name: "a project that limits nowhere still reports a raw read of the whole body",
			files: map[string]string{
				"api/auth.go": `package api

import (
	"bytes"
	"io"
	"net/http"
)

func Signed(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		next.ServeHTTP(w, r)
	})
}

func Hook(w http.ResponseWriter, r *http.Request) {
	payload, _ := io.ReadAll(r.Body)
	_, _ = w.Write(payload)
}
`,
			},
			expects: []string{"api/auth.go:11", "api/auth.go:22"},
		},
		{
			name: "client code reading its own outgoing request is not a handler",
			files: map[string]string{
				"api/token.go": limitedHandler,
				"api/retry.go": `package api

import (
	"bytes"
	"io"
	"net/http"
)

type retrying struct{ next http.RoundTripper }

func (t *retrying) RoundTrip(req *http.Request) (*http.Response, error) {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	req.Body = io.NopCloser(bytes.NewReader(body))
	return t.next.RoundTrip(req)
}
`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := map[string]string{"go.mod": "module example.com/rulestest\n\ngo 1.24\n"}
			for name, source := range tt.files {
				files[name] = source
			}
			violations, err := NewUnboundedRequestBodyReadRule().AnalyzeGoProject(rulestest.Project(t, files))
			require.NoError(t, err)
			assert.Equal(t, tt.expects, foundLines(violations))
		})
	}
}
