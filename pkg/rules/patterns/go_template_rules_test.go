package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// webPageSource renders a list page whose rows are a type of their own.
const webPageSource = `package web

import (
	"html/template"
	"net/http"
)

type PageData struct {
	Lang  string
	Title string
}

type Row struct {
	ID   int
	Name string
}

type ListPage struct {
	PageData
	Rows   []Row
	Filter string
}

type Server struct{ tmpl *template.Template }

func (s *Server) render(w http.ResponseWriter, name string, data any) {
	_ = s.tmpl.ExecuteTemplate(w, name, data)
}

func (s *Server) list(w http.ResponseWriter, r *http.Request) {
	s.render(w, "list.html", ListPage{PageData: PageData{Lang: "en"}})
}
`

// Inside {{range .Rows}} the dot is a row: .Lang there is a field of the
// page, which a row lacks - the template fails on the first row, while an
// empty table renders the {{else}} branch fine.
func TestGoTemplateRootFieldInsideRange(t *testing.T) {
	assert.Equal(t, []string{"web/templates/list.html:4"}, typedFuncFindings(t, NewGoTemplateRootFieldInsideRangeRule(), map[string]string{
		"web/page.go": webPageSource,
		"web/templates/list.html": `{{define "content"}}
<h2>{{t .Lang "list.title"}}</h2>
{{range .Rows}}
<tr><td>{{.ID}}</td><td>{{.Name}}</td><td>{{t .Lang "list.delete"}}</td><td>{{t $.Lang "list.edit"}}</td></tr>
{{else}}
<p>{{t .Lang "list.empty"}}</p>
{{end}}
{{with .Filter}}<p>{{.}}</p>{{end}}
{{end}}
`,
		// No Go code renders this one: its data type is unknown.
		"web/templates/other.html": `{{range .Rows}}{{.Lang}}{{end}}
`,
	}))
}

// One template set parsed from every page: each page defines "content", the
// last parsed wins, and every page shows the same body.
func TestGoTemplateDefineCollisionInSharedSet(t *testing.T) {
	assert.Equal(t, []string{"web/templates.go:16"}, typedFuncFindings(t, NewGoTemplateDefineCollisionInSharedSetRule(), map[string]string{
		"web/templates.go": `package web

import (
	"embed"
	"html/template"
)

//go:embed templates
var templateFS embed.FS

//go:embed partials
var partialFS embed.FS

func parse() (*template.Template, *template.Template, error) {
	funcs := template.FuncMap{}
	pages, err := template.New("").Funcs(funcs).ParseFS(templateFS, "templates/*.html")
	if err != nil {
		return nil, nil, err
	}
	partials, err := template.New("").ParseFS(partialFS, "partials/*.html")
	return pages, partials, err
}
`,
		"web/templates/layout.html":    `<html>{{block "content" .}}{{end}}</html>`,
		"web/templates/dashboard.html": `{{define "content"}}dashboard{{end}}`,
		"web/templates/orders.html":    `{{define "content"}}orders{{end}}`,
		"web/partials/row.html":        `{{define "row"}}row{{end}}`,
		"web/partials/cell.html":       `{{define "cell"}}cell{{end}}`,
	}))
}

// A JSON string interpolated as a bare value inside <script>: html/template
// escapes a string there as a JS string literal, so the script gets a string
// where it expected an object.
func TestGoTemplateJSONStringInScriptContext(t *testing.T) {
	assert.Equal(t, []string{"web/page.go:6"}, typedFuncFindings(t, NewGoTemplateJSONStringInScriptContextRule(), map[string]string{
		"web/page.go": `package web

import "html/template"

type Page struct {
	PairsJSON  string
	RatesJSON  template.JS
	ConfigJSON string
	Title      string
}
`,
		"web/templates/page.html": `<h1>{{.Title}}</h1>
<script>
  const pairs = {{.PairsJSON}};
  const rates = {{.RatesJSON}};
  const config = JSON.parse("{{.ConfigJSON}}");
</script>
`,
	}))
}

// A relative URL in a page served under a nested route resolves against the
// page's own path: 'options' on /orders/new is /orders/options.
func TestRelativeFetchURLResolvesAgainstPagePath(t *testing.T) {
	ctx := rulestest.TextFile(t, "web/templates/new_order.html", `<div id="fields" hx-get="fields" hx-trigger="load"></div>
<div hx-get="/orders/new/fields"></div>
<div hx-get="{{.FieldsURL}}"></div>
<script>
  Form.fetchOptions(document.getElementById('fields'), 'options', country);
  Form.fetchOptions(document.getElementById('fields'), '/orders/new/options', country);
  fetch('api/rates').then(r => r.json());
  fetch('./rates');
  fetch(url, {method: 'POST', mode: 'cors'});
</script>
`)
	assert.Equal(t, []string{"web/templates/new_order.html:1", "web/templates/new_order.html:5", "web/templates/new_order.html:7"}, foundLines(NewRelativeFetchURLResolvesAgainstPagePathRule().AnalyzeFile(ctx)))
}

// A key the templates or the handlers translate that a language map lacks
// shows the raw key; a key one language has and another lacks shows the raw
// key in that language only.
func TestI18nKeyUsedButNotDefined(t *testing.T) {
	assert.Equal(t, []string{"i18n/en.go:7", "web/handler.go:6", "web/templates/page.html:2"}, typedFuncFindings(t, NewI18nKeyUsedButNotDefinedRule(), map[string]string{
		"i18n/en.go": `package i18n

var en = map[string]string{
	"page.title":   "Title",
	"page.save":    "Save",
	"page.cancel":  "Cancel",
	"page.status":  "Status",
	"nav.home":     "Home",
	"nav.orders":   "Orders",
	"nav.settings": "Settings",
	"nav.logout":   "Log out",
	"nav.help":     "Help",
	"nav.about":    "About",
}
`,
		"i18n/ru.go": `package i18n

var ru = map[string]string{
	"page.title":   "Заголовок",
	"page.save":    "Сохранить",
	"page.cancel":  "Отмена",
	"nav.home":     "Главная",
	"nav.orders":   "Заказы",
	"nav.settings": "Настройки",
	"nav.logout":   "Выйти",
	"nav.help":     "Помощь",
	"nav.about":    "О сервисе",
}

func T(lang, key string) string {
	if lang == "ru" {
		return ru[key]
	}
	return en[key]
}
`,
		"web/handler.go": `package web

import "example.com/rulestest/i18n"

func labels(lang string) []string {
	return []string{i18n.T(lang, "page.title"), i18n.T(lang, "page.delete"), i18n.T(lang, "report.ready")}
}
`,
		"web/templates/page.html": `<h1>{{t .Lang "page.title"}}</h1>
<th>{{t .Lang "page.created"}}</th>
<p>{{.Version}} {{printf "%s" "v1.2"}}</p>
`,
	}))
}

// A filter form that swaps only the table body: the count above the table
// and the pagination below stay those of the first load.
func TestHtmxSwapTargetExcludesDependentFragment(t *testing.T) {
	ctx := rulestest.TextFile(t, "web/templates/orders.html", `<h2>Orders ({{.Total}})</h2>
<form hx-get="/orders" hx-target="#orders-body" hx-swap="innerHTML">
  <input name="search" value="{{.Filter.Search}}">
</form>
<table>
  <tbody id="orders-body">
    {{range .Rows}}<tr><td>{{.ID}}</td></tr>{{end}}
  </tbody>
</table>
{{if gt .TotalPages 1}}<nav>{{.Page}}</nav>{{end}}
<div id="result"></div>
<button hx-post="/orders/export" hx-target="#result">Export</button>
<div id="stats" hx-get="/orders/stats" hx-trigger="every 30s" hx-target="#stats-body"><span id="stats-body">{{.Count}}</span></div>
<section id="list" hx-get="/orders" hx-select="#list" hx-target="this">{{.Total}}</section>
<select name="status" hx-get="/orders" hx-target="#orders-rows"></select>
<table><tbody id="orders-rows">{{template "order_rows" .}}</tbody></table>
`)
	assert.Equal(t, []string{"web/templates/orders.html:15", "web/templates/orders.html:2"}, foundLines(NewHtmxSwapTargetExcludesDependentFragmentRule().AnalyzeFile(ctx)))
}
