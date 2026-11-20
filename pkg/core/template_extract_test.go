package core

import (
	"strings"
	"testing"
)

func TestExtractTemplateJavaScriptPreservesSourceAndMasksActions(t *testing.T) {
	source := `<!doctype html>
<script>
const providers = {{.Providers}};
const title = "{{.Title}}";
const count = {{len .Providers}} + 1;
{{template "extra" .}}
{{if .Enabled}}
function show(list) { return list.length; }
{{else}}
function show(list) { return 0; }
{{end}}
{{range .Providers}}
show([{{.}}]);
{{end}}
</script>
`
	ctx := NewFileContext("/project/templates/page.html", "/project", []byte(source), DefaultConfig())
	got := ExtractTemplateJavaScript(ctx)
	if len(got) != 1 {
		t.Fatalf("got %d scripts, want 1", len(got))
	}
	virtual := got[0]
	if virtual.Path != ctx.Path || virtual.RelPath != ctx.RelPath || !virtual.IsJavaScriptFile() || virtual.IsTemplate() {
		t.Fatalf("virtual context lost source identity or JS mode: %#v", virtual)
	}
	if len(virtual.Content) != len(source) || len(virtual.Lines) != len(ctx.Lines) {
		t.Fatalf("source dimensions changed: bytes %d/%d, lines %d/%d", len(virtual.Content), len(source), len(virtual.Lines), len(ctx.Lines))
	}
	code := string(virtual.Content)
	for _, want := range []string{"const providers =", "const title =", "const count =", "function show(list) { return list.length; }", "show([", "0"} {
		if !strings.Contains(code, want) {
			t.Errorf("virtual source does not contain %q:\n%s", want, code)
		}
	}
	if !strings.Contains(code, "null") || !strings.Contains(code, `"  x`) || !strings.Contains(code, "null") || !strings.Contains(code, "+ 1") {
		t.Fatalf("template insertions did not retain neutral JS values:\n%s", code)
	}
	if strings.Contains(code, "return 0") || strings.Contains(code, "{{") || strings.Contains(code, "</script>") {
		t.Fatalf("template alternative/action or markup remains in virtual JS:\n%s", code)
	}
	for i, line := range strings.Split(code, "\n") {
		if strings.Count(line, "\n") != 0 {
			t.Fatalf("unexpected newline at split line %d", i)
		}
	}
}

func TestExtractTemplateJavaScriptNoScriptAndMultipleScripts(t *testing.T) {
	ctx := NewFileContext("/project/templates/page.html", "/project", []byte(`<script>let a = 1;</script><div>markup</div><script>let b = 2;</script>`), DefaultConfig())
	got := ExtractTemplateJavaScript(ctx)
	if len(got) != 2 {
		t.Fatalf("got %d scripts, want 2", len(got))
	}
	if strings.Contains(string(got[0].Content), "markup") || strings.Contains(string(got[1].Content), "markup") {
		t.Fatal("markup leaked into a virtual script")
	}
	json := NewFileContext("/project/templates/data.html", "/project", []byte(`<script type="application/json">{"x":1}</script><script type="module">let x = 1;</script>`), DefaultConfig())
	if scripts := ExtractTemplateJavaScript(json); len(scripts) != 1 || !strings.Contains(string(scripts[0].Content), "let x = 1") {
		t.Fatalf("non-JavaScript script was extracted: %#v", scripts)
	}
	closingTagInAction := NewFileContext("/project/templates/action.html", "/project", []byte(`<script>
const value = {{printf "</script>"}};
let visible = true;
</script>`), DefaultConfig())
	if scripts := ExtractTemplateJavaScript(closingTagInAction); len(scripts) != 1 || !strings.Contains(string(scripts[0].Content), "let visible = true") {
		t.Fatalf("script ended inside a Go action: %#v", scripts)
	}
	plain := NewFileContext("/project/templates/plain.html", "/project", []byte("<p>plain</p>"), DefaultConfig())
	if got := ExtractTemplateJavaScript(plain); len(got) != 0 {
		t.Fatalf("got scripts in plain template: %d", len(got))
	}
}

// A define body is another template and stays out of the script; its end
// closes the define, not the if around it.
func TestExtractTemplateJavaScriptDefineBodyIsBlank(t *testing.T) {
	source := "<script>\n{{if .On}}\nconst a = 1;\n{{define \"x\"}}\nconst hidden = 2;\n{{end}}\nconst b = 3;\n{{else}}\nconst c = 4;\n{{end}}\n</script>\n"
	ctx := NewFileContext("/project/templates/page.html", "/project", []byte(source), DefaultConfig())
	got := ExtractTemplateJavaScript(ctx)
	if len(got) != 1 {
		t.Fatalf("got %d scripts, want 1", len(got))
	}
	code := string(got[0].Content)
	for _, want := range []string{"const a = 1;", "const b = 3;"} {
		if !strings.Contains(code, want) {
			t.Errorf("virtual source lost %q:\n%s", want, code)
		}
	}
	for _, unwanted := range []string{"hidden", "const c"} {
		if strings.Contains(code, unwanted) {
			t.Errorf("virtual source keeps %q:\n%s", unwanted, code)
		}
	}
}

// A character whose lower case is longer in bytes before the script must not
// shift the script's position in the virtual source.
func TestExtractTemplateJavaScriptAfterNonASCIIKeepsOffsets(t *testing.T) {
	source := "<p>İİİİ</p>\n<SCRIPT>\nconst kept = 1;\n</SCRIPT>\n"
	ctx := NewFileContext("/project/templates/page.html", "/project", []byte(source), DefaultConfig())
	got := ExtractTemplateJavaScript(ctx)
	if len(got) != 1 {
		t.Fatalf("got %d scripts, want 1", len(got))
	}
	if line := got[0].Lines[2]; line != "const kept = 1;" {
		t.Errorf("line 3 of the virtual source = %q, want the script line", line)
	}
	if strings.Contains(string(got[0].Content), "SCRIPT") {
		t.Errorf("script tags are kept:\n%s", got[0].Content)
	}
}
