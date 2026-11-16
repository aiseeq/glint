package httprules

import (
	"testing"

	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patterntest"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
)

func TestBlockElementInsideP(t *testing.T) {
	assert.Equal(t, "block-element-inside-p", NewBlockElementInsidePRule().Name())
	ctx := rulestest.TextFile(t, "web/templates/page.html", `<p>form <form></form></p>
<p>div <DIV></DIV></p>
<p>list <ul></ul></p>
<p>heading <h1></h1></p>
<p>nested <p></p>
<p>{{.Name}} <table></table></p>
<p>break
<hr>
<p>inline <span></span><button></button><input></p>
<p>closed</p><div></div>
<div><p>closed by parent</div><form></form>
<p><button><div>in button</div></button></p>
<!-- <p><div>comment</div> -->
{{/* <p><div>template comment</div> */}}
<script>"<p><div>script</div>"</script>
<style><p><div>style</div></style>
<textarea><p><div>textarea</div></textarea>
<pre>not p</pre><div></div>
<picture></picture><div></div><progress></progress><param><div></div>
`)
	assert.Equal(t, []string{
		"web/templates/page.html:1", "web/templates/page.html:2", "web/templates/page.html:3",
		"web/templates/page.html:4", "web/templates/page.html:5", "web/templates/page.html:6",
		"web/templates/page.html:8",
	}, patterntest.FoundLines(NewBlockElementInsidePRule().AnalyzeFile(ctx)))

	branches := rulestest.TextFile(t, "web/templates/branches.tmpl", `{{if .X}}<p>{{else}}<div>{{end}}
<p>{{.X}}{{if .Y}}<div>{{end}}
<p>{{range .Items}}<div>{{end}}
<p>{{with .X}}<div>{{end}}
<p>{{template "inner" .}}<div>
<p>{{block "inner" .}}<div>{{end}}
<p>{{define "inner"}}<div>{{end}}
`)
	assert.Empty(t, NewBlockElementInsidePRule().AnalyzeFile(branches))

	nontemplate := rulestest.TextFile(t, "web/templates/page.txt", `<p><div></div></p>`)
	assert.Empty(t, NewBlockElementInsidePRule().AnalyzeFile(nontemplate))
}
