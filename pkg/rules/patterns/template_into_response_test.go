package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// A template executed straight into the ResponseWriter commits 200 with its
// first byte: a failing action halfway through leaves a cut page, and the
// http.Error of the error branch only appends its text to it.
func TestTemplateExecutedIntoResponse(t *testing.T) {
	files := map[string]string{
		"web/render.go": `package web

import (
	"bytes"
	"html/template"
	"log/slog"
	"net/http"
	ttemplate "text/template"
)

type Pages struct {
	pages  map[string]*template.Template
	plain  *ttemplate.Template
	logger *slog.Logger
}

func (p *Pages) render(w http.ResponseWriter, name string, data any) {
	t := p.pages[name]
	if err := t.ExecuteTemplate(w, name, data); err != nil { // want template-executed-into-response
		p.logger.Error("render", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func (p *Pages) renderPlain(w http.ResponseWriter, data any) {
	err := p.plain.Execute(w, data) // want template-executed-into-response
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func (p *Pages) renderBuffered(w http.ResponseWriter, name string, data any) {
	var buf bytes.Buffer
	if err := p.pages[name].ExecuteTemplate(&buf, name, data); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	_, _ = w.Write(buf.Bytes())
}

// renderLogged writes the page and only logs a failure: nothing claims a
// status the client cannot get any more.
func (p *Pages) renderLogged(w http.ResponseWriter, name string, data any) {
	if err := p.pages[name].ExecuteTemplate(w, name, data); err != nil {
		p.logger.Error("render", "error", err)
	}
}
`,
	}
	violations, err := NewTemplateExecutedIntoResponseRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	assert.Equal(t, wantedLines(files, "template-executed-into-response"), foundLines(violations))
}
