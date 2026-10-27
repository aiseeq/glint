package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

func TestEmbeddedTemplatesParsedPerConstructionOnceDoAllowed(t *testing.T) {
	assert.Empty(t, embeddedTemplateFindings(t, map[string]string{
		"view/view.go": `package view

import (
	"embed"
	"html/template"
	"sync"
)

//go:embed *.html
var templates embed.FS
var once sync.Once

func NewView() {
	once.Do(func() {
		_, _ = template.New("").ParseFS(templates, "*.html")
	})
}
`,
	}))
}

func embeddedTemplateFindings(t *testing.T, files map[string]string) []string {
	t.Helper()
	root, _ := rulestest.Module(t, files)
	contexts, errs := core.NewWalker(root, core.DefaultConfig()).WalkSync()
	require.Empty(t, errs)
	rule := NewEmbeddedTemplatesParsedPerConstructionRule()
	rule.UseProjectFiles(contexts)
	var violations []*core.Violation
	for _, ctx := range contexts {
		violations = append(violations, rule.AnalyzeFile(ctx)...)
	}
	return foundLines(violations)
}

func TestEmbeddedTemplatesParsedPerConstruction(t *testing.T) {
	assert.Equal(t, []string{"view/view.go:12"}, embeddedTemplateFindings(t, map[string]string{
		"view/view.go": `package view

import (
	"embed"
	"html/template"
)

//go:embed *.html
var templates embed.FS

func NewView() (*View, error) {
	t, err := parseTemplates()
	if err != nil { return nil, err }
	return &View{templates: t}, nil
}

func parseTemplates() (*template.Template, error) {
	return template.New("").ParseFS(templates, "*.html")
}

type View struct { templates *template.Template }
`,
	}))
}

func TestEmbeddedTemplatesParsedPerConstructionAllowed(t *testing.T) {
	assert.Empty(t, embeddedTemplateFindings(t, map[string]string{
		"view/view.go": `package view

import (
	"embed"
	"html/template"
	"sync"
)

//go:embed *.html
var templates embed.FS

func NewView() (*View, error) {
	t, err := loadTemplates()
	if err != nil { return nil, err }
	return &View{templates: t}, nil
}

func parseTemplates() (*template.Template, error) {
	return template.New("").ParseFS(templates, "*.html")
}

var loadTemplates = sync.OnceValues(parseTemplates)

func NewOther() (*View, error) {
	t, err := loadTemplates()
	if err != nil { return nil, err }
	return &View{templates: t}, nil
}

func loadRequestTemplate() (*template.Template, error) {
	return template.New("").ParseFS(templates, "*.html")
}

func render() { _, _ = loadRequestTemplate() }

type View struct { templates *template.Template }
`,
		"view/other.go": `package view

import "html/template"

func NewFromString() *template.Template {
	t, _ := template.New("").Parse("static template")
	return t
}
`,
	}))
}
