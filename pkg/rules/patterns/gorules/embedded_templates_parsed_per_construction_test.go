package gorules

import (
	"testing"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
)

func TestEmbeddedTemplatesParsedPerConstructionOnceDoAllowed(t *testing.T) {
	assert.Empty(t, rulestest.ProjectFilesRulePlaces(t, NewEmbeddedTemplatesParsedPerConstructionRule(), map[string]string{
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

func TestEmbeddedTemplatesParsedPerConstruction(t *testing.T) {
	assert.Equal(t, []string{"view/view.go:12"}, rulestest.ProjectFilesRulePlaces(t, NewEmbeddedTemplatesParsedPerConstructionRule(), map[string]string{
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
	assert.Empty(t, rulestest.ProjectFilesRulePlaces(t, NewEmbeddedTemplatesParsedPerConstructionRule(), map[string]string{
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
