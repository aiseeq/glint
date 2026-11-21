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
	for _, want := range []string{"const providers =", "const title =", "const count =", "function show(list) { return list.length; }", "show([null"} {
		if !strings.Contains(code, want) {
			t.Errorf("virtual source does not contain %q:\n%s", want, code)
		}
	}
	if !strings.Contains(code, "null") || !strings.Contains(code, `"x`) || !strings.Contains(code, "+ 1") {
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
	// Every script of a template goes into one virtual file of the template's
	// size, not one full-size copy per script.
	ctx := NewFileContext("/project/templates/page.html", "/project", []byte(`<title>{{.T}}</title><script>let a = 1;</script><div>markup</div><script>let b = 2;</script>`), DefaultConfig())
	got := ExtractTemplateJavaScript(ctx)
	if len(got) != 1 {
		t.Fatalf("got %d virtual files, want 1", len(got))
	}
	code := string(got[0].Content)
	if !strings.Contains(code, "let a = 1;") || !strings.Contains(code, "let b = 2;") {
		t.Fatalf("a script is missing from the virtual file:\n%s", code)
	}
	if strings.Contains(code, "markup") || strings.Contains(code, "title") {
		t.Fatal("markup leaked into a virtual script")
	}
	// A file without a template action is plain HTML, not a Go template.
	staticPage := NewFileContext("/project/docs/prototype.html", "/project", []byte(`<script>let a = 1;</script>`), DefaultConfig())
	if got := ExtractTemplateJavaScript(staticPage); len(got) != 0 {
		t.Fatalf("got %d virtual files for plain HTML, want 0", len(got))
	}
	json := NewFileContext("/project/templates/data.html", "/project", []byte(`{{/* data */}}<script type="application/json">{"x":1}</script><script type="module">let x = 1;</script>`), DefaultConfig())
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
	source := "<p>İİİİ {{.X}}</p>\n<SCRIPT>\nconst kept = 1;\n</SCRIPT>\n"
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

// An else if chain keeps its first branch only: the later branches are other
// versions of the same code, and two of them side by side declare the same
// name twice or read as a copied block.
func TestExtractTemplateJavaScriptElseIfChainKeepsFirstBranch(t *testing.T) {
	source := "<script>\n{{if eq .Mode \"a\"}}\nconst mode = \"a\";\n{{else if eq .Mode \"b\"}}\nconst mode = \"b\";\n{{else}}\nconst mode = \"c\";\n{{end}}\n{{range .Items}}\nshow(1);\n{{else}}\nconst none = 1;\n{{end}}\n</script>\n"
	ctx := NewFileContext("/project/templates/page.html", "/project", []byte(source), DefaultConfig())
	got := ExtractTemplateJavaScript(ctx)
	if len(got) != 1 {
		t.Fatalf("got %d scripts, want 1", len(got))
	}
	code := string(got[0].Content)
	if !strings.Contains(code, `const mode = "a";`) || !strings.Contains(code, "show(1);") {
		t.Errorf("the first branch is lost:\n%s", code)
	}
	for _, unwanted := range []string{`"b"`, `"c"`, "none"} {
		if strings.Contains(code, unwanted) {
			t.Errorf("virtual source keeps %s from a later branch:\n%s", unwanted, code)
		}
	}
}

// A template call or a field name in an expression is a value, not a
// statement: a semicolon there breaks the parse of the whole script.
func TestExtractTemplateJavaScriptExpressionActionsStayValues(t *testing.T) {
	source := "<script>\nconst a = {{template \"val\" .}};\nconst b = obj.{{.Field}};\n{{template \"extra\" .}}\n</script>\n"
	ctx := NewFileContext("/project/templates/page.html", "/project", []byte(source), DefaultConfig())
	got := ExtractTemplateJavaScript(ctx)
	if len(got) != 1 {
		t.Fatalf("got %d scripts, want 1", len(got))
	}
	lines := got[0].Lines
	for i, want := range map[int]string{1: "const a = null", 2: "const b = obj._", 3: ";"} {
		if line := strings.Join(strings.Fields(lines[i]), " "); !strings.HasPrefix(line, want) {
			t.Errorf("line %d = %q, want it to start with %q", i+1, lines[i], want)
		}
	}
}

func TestExtractTemplateJavaScriptQuotesInCommentsDoNotChangeActionContext(t *testing.T) {
	source := "<script>\n// it's a comment\nconst single = {{.A}};\n/* it's also a comment */ const double = {{.B}};\n</script>\n"
	ctx := NewFileContext("/project/templates/comments.html", "/project", []byte(source), DefaultConfig())
	got := ExtractTemplateJavaScript(ctx)
	if len(got) != 1 {
		t.Fatalf("got %d scripts, want 1", len(got))
	}
	lines := got[0].Lines
	for i, want := range map[int]string{
		2: "const single = null  ;",
		3: "/* it's also a comment */ const double = null  ;",
	} {
		if lines[i] != want {
			t.Errorf("line %d = %q, want exact virtual line %q", i+1, lines[i], want)
		}
	}
}

func TestExtractTemplateJavaScriptActionBetweenOperandsIsOperator(t *testing.T) {
	source := "<script>\nconst sum = 1 {{.Operator}} 2;\n</script>\n"
	ctx := NewFileContext("/project/templates/operator.html", "/project", []byte(source), DefaultConfig())
	got := ExtractTemplateJavaScript(ctx)
	if len(got) != 1 {
		t.Fatalf("got %d scripts, want 1", len(got))
	}
	want := "const sum = 1 +" + strings.Repeat(" ", len("{{.Operator}}")-1) + " 2;"
	if got[0].Lines[1] != want {
		t.Errorf("line 2 = %q, want exact virtual line %q", got[0].Lines[1], want)
	}
}

func TestExtractTemplateJavaScriptOwnLineActionIsNotBinaryOperator(t *testing.T) {
	action := `{{template "init" .}}`
	source := "<script>\nconst a = 1\n" + action + "\nconst b = 2\n</script>\n"
	ctx := NewFileContext("/project/templates/asi.html", "/project", []byte(source), DefaultConfig())
	got := ExtractTemplateJavaScript(ctx)
	if len(got) != 1 {
		t.Fatalf("got %d scripts, want 1", len(got))
	}
	want := ";" + strings.Repeat(" ", len(action)-1)
	if got[0].Lines[2] != want {
		t.Errorf("line 3 = %q, want exact virtual line %q", got[0].Lines[2], want)
	}
}

func TestExtractTemplateJavaScriptImportSourceIsStringLiteral(t *testing.T) {
	source := "<script>\nimport value from {{.DefaultModule}};\nimport { item } from {{.NamedModule}};\n</script>\n"
	ctx := NewFileContext("/project/templates/import.html", "/project", []byte(source), DefaultConfig())
	got := ExtractTemplateJavaScript(ctx)
	if len(got) != 1 {
		t.Fatalf("got %d scripts, want 1", len(got))
	}
	for i, want := range map[int]string{
		1: `import value from "x"` + strings.Repeat(" ", len("{{.DefaultModule}}")-3) + ";",
		2: `import { item } from "x"` + strings.Repeat(" ", len("{{.NamedModule}}")-3) + ";",
	} {
		if got[0].Lines[i] != want {
			t.Errorf("line %d = %q, want exact virtual line %q", i+1, got[0].Lines[i], want)
		}
	}
}

func TestExtractTemplateJavaScriptActionAfterDotIsIdentifier(t *testing.T) {
	source := "<script>\nconst a = obj.{{.ID}};\nconst b = obj.{{.FieldName}}.trim();\n</script>\n"
	ctx := NewFileContext("/project/templates/property.html", "/project", []byte(source), DefaultConfig())
	got := ExtractTemplateJavaScript(ctx)
	if len(got) != 1 {
		t.Fatalf("got %d scripts, want 1", len(got))
	}
	for i, want := range map[int]string{
		1: "const a = obj._" + strings.Repeat(" ", len("{{.ID}}")-1) + ";",
		2: "const b = obj._" + strings.Repeat(" ", len("{{.FieldName}}")-1) + ".trim();",
	} {
		if got[0].Lines[i] != want {
			t.Errorf("line %d = %q, want exact virtual line %q", i+1, got[0].Lines[i], want)
		}
	}
}

func TestExtractTemplateJavaScriptActionNextToKeywordIsNotBinaryOperator(t *testing.T) {
	action := `{{template "stmt" .}}`
	statement := ";" + strings.Repeat(" ", len(action)-1)
	for _, tc := range []struct{ line, want string }{
		{"if (a) " + action + " else b();", "if (a) " + statement + " else b();"},
		{"do " + action + " while (x);", "do " + statement + " while (x);"},
		{"if (a) x(); else " + action + " b();", "if (a) x(); else " + statement + " b();"},
		{"try " + action + " finally {}", "try " + "{}" + strings.Repeat(" ", len(action)-2) + " finally {}"},
		{"try {} catch (e) " + action, "try {} catch (e) " + "{}" + strings.Repeat(" ", len(action)-2)},
		{"try {} finally " + action, "try {} finally " + "{}" + strings.Repeat(" ", len(action)-2)},
		{"const v = a {{.Op}} b;", "const v = a +" + strings.Repeat(" ", len("{{.Op}}")-1) + " b;"},
		{"const t = done {{.Op}} other;", "const t = done +" + strings.Repeat(" ", len("{{.Op}}")-1) + " other;"},
		{"f(opts.default {{.Op}} 1);", "f(opts.default +" + strings.Repeat(" ", len("{{.Op}}")-1) + " 1);"},
		{"const v = [el.class {{.Op}} b];", "const v = [el.class +" + strings.Repeat(" ", len("{{.Op}}")-1) + " b];"},
		{"f(a {{.Op}} new Date());", "f(a +" + strings.Repeat(" ", len("{{.Op}}")-1) + " new Date());"},
		{"f(a {{.Op}} typeof b);", "f(a +" + strings.Repeat(" ", len("{{.Op}}")-1) + " typeof b);"},
		{"p.then(ok).catch(fail) {{.Op}} next();", "p.then(ok).catch(fail) +" + strings.Repeat(" ", len("{{.Op}}")-1) + " next();"},
		{"f(p.catch {{.Op}} 1);", "f(p.catch +" + strings.Repeat(" ", len("{{.Op}}")-1) + " 1);"},
		{"f(of {{.Op}} 2);", "f(of +" + strings.Repeat(" ", len("{{.Op}}")-1) + " 2);"},
		{"f(let {{.Op}} other);", "f(let +" + strings.Repeat(" ", len("{{.Op}}")-1) + " other);"},
		{"p.catch(report) " + action, "p.catch(report) " + statement},
		{"if (a) " + action + " x = 1;", "if (a) " + statement + " x = 1;"},
		{"if (f(a)) " + action + " b();", "if (f(a)) " + statement + " b();"},
		{"while (c) " + action + " i++;", "while (c) " + statement + " i++;"},
		{"with (o) " + action + " x = 1;", "with (o) " + statement + " x = 1;"},
		{"for (const k of arr) " + action + " x = 1;", "for (const k of arr) " + statement + " x = 1;"},
		{"for (;;) " + action + " (b || c)();", "for (;;) " + statement + " (b || c)();"},
		{"f(a) {{.Op}} b;", "f(a) +" + strings.Repeat(" ", len("{{.Op}}")-1) + " b;"},
		{"const v = (a) {{.Op}} b;", "const v = (a) +" + strings.Repeat(" ", len("{{.Op}}")-1) + " b;"},
		{"const v = o.if(a) {{.Op}} b;", "const v = o.if(a) +" + strings.Repeat(" ", len("{{.Op}}")-1) + " b;"},
	} {
		source := "<script>\n" + tc.line + "\n</script>\n"
		ctx := NewFileContext("/project/templates/keyword.html", "/project", []byte(source), DefaultConfig())
		got := ExtractTemplateJavaScript(ctx)
		if len(got) != 1 {
			t.Fatalf("got %d scripts, want 1", len(got))
		}
		if got[0].Lines[1] != tc.want {
			t.Errorf("%q: virtual line = %q, want %q", tc.line, got[0].Lines[1], tc.want)
		}
	}
}

func TestExtractTemplateJavaScriptMaskingResidueClasses(t *testing.T) {
	action := `{{.X}}`
	call := `{{template "stmt" .}}`
	for _, tc := range []struct {
		name, line, action, replacement string
	}{
		{"regex single quote", `const re = /'/; x = 1 {{.Op}} 2;`, `{{.Op}}`, "+"},
		{"regex double quote", `const re = /"/g; f({{.X}});`, action, "null"},
		{"regex escaped slash", `const re = /\/\//g; x = 1 {{.Op}} 2;`, `{{.Op}}`, "+"},
		{"case value", `switch (k) { case {{.X}}: break; }`, action, "null"},
		{"for of value", `for (const v of {{.X}}) { f(v); }`, action, "null"},
		{"for in value", `for (const k in {{.X}}) { f(k); }`, action, "null"},
		{"instanceof value", `x = e instanceof {{.X}};`, action, "null"},
		{"extends value", `class A extends {{.X}} {}`, action, "null"},
		{"import binding", `import {{.X}};`, action, `"x"`},
		{"export default value", `export default {{.X}};`, action, "null"},
		{"const binding", `const {{.X}} = 1;`, action, "_"},
		{"function binding", `function {{.X}}() {}`, action, "_"},
		{"class binding", `class {{.X}} {}`, action, "_"},
		{"comment between equals", "x = // note\n  {{.X}};", action, "null"},
		{"operator after word suffix", `x = renew {{.Op}} b;`, `{{.Op}}`, "+"},
		{"operator after property", `x = opts.new {{.Op}} 1;`, `{{.Op}}`, "+"},
		{"case template statement", `switch (k) { case 1: ` + call + ` break; }`, call, ";"},
		{"label template statement", `lbl: ` + call + ` x();`, call, ";"},
		{"object body template", `const o = { a: 1, ` + call + ` };`, call, ""},
		{"switch body template", `switch (k) { ` + call + ` }`, call, "default:;"},
		{"switch body template on next line", "switch (k) {\n  " + call + "\n}", call, "default:;"},
		{"object body template on next line", "const o = {\n  " + call + "\n};", call, ""},
		{"for test value", `for (let i = 0; {{.X}} > i; i++) {}`, action, "null"},
		{"statement member value", `{{.X}}.init();`, action, "null"},
		{"statement call value", `{{.X}}(1);`, action, "null"},
		{"statement assignment binding", `{{.X}} = 1;`, action, "_"},
		{"else call value", `if (a) {} else {{.X}}(1);`, action, "null"},
		{"unary minus rhs", `f(a {{.Op}} -1);`, `{{.Op}}`, "+"},
		{"unary not rhs", `f(a {{.Op}} !b);`, `{{.Op}}`, "+"},
		{"unary decimal rhs", `f(a {{.Op}} .5);`, `{{.Op}}`, "+"},
		{"action comment emits nothing", `x = 1 {{/* c */}} + 2;`, `{{/* c */}}`, ""},
		{"action declaration emits nothing", `x = 1 {{$v := 2}} + 2;`, `{{$v := 2}}`, ""},
		{"Allman try block", "try\n" + call + "\ncatch (e) {}", call, "{}"},
		{"Allman catch block", "try {} catch (e)\n" + call, call, "{}"},
		{"nested catch binding", `try {} catch ({ a = f() }) ` + call, call, "{}"},
		{"empty switch body", `switch (k) { ` + call + ` }`, call, "default:;"},
		{"ternary value", `x = c ? null : {{.X}};`, action, "null"},
		{"object default key value", `x = { default: {{.X}} };`, action, "null"},
		{"object property value after return", `function f() { return {a: {{.X}}, b: {{.Y}}}; }`, action, "null"},
		{"statement start assignment", "x();\n{{.X}} = 1;", action, "_"},
		{"statement start call", "x();\n{{.X}}(1);", action, "null"},
		{"in operator without whitespace", `x = 'k' in{{.X}};`, action, " null"},
		{"class expression name", `x = class {{.X}} {};`, action, "_"},
		{"bare import string", `import {{.X}};`, action, `"x"`},
		{"decimal fraction after dot", `x = 0.{{.X}};`, action, "0"},
		{"yield operator to value", `function* g() { x = yield {{.Op}} x; }`, `{{.Op}}`, "+"},
		{"await operator to value", `async function f() { x = await {{.Op}} 2; }`, `{{.Op}}`, "+"},
		{"operator before empty action", `x = a {{.Op}}{{.X}};`, `{{.Op}}`, "+"},
		{"operator before spaced action", `x = a {{.Op}} {{.X}};`, `{{.Op}}`, "+"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := "<script>\n" + tc.line + "\n</script>\n"
			ctx := NewFileContext("/project/templates/residue.html", "/project", []byte(source), DefaultConfig())
			got := ExtractTemplateJavaScript(ctx)
			if len(got) != 1 {
				t.Fatalf("got %d scripts, want 1", len(got))
			}
			if tc.action == "" {
				t.Fatal("empty action in test case")
			}
			lineStart := strings.Index(source, tc.line)
			actionStart := strings.Index(tc.line, tc.action)
			if lineStart < 0 || actionStart < 0 {
				t.Fatalf("action %q not found in input %q", tc.action, tc.line)
			}
			at := lineStart + actionStart
			line := string(got[0].Content)
			if tc.replacement == "" {
				for _, c := range line[at : at+len(tc.action)] {
					if c != ' ' {
						t.Errorf("action should emit only whitespace, line = %q", line)
						break
					}
				}
				return
			}
			if !strings.HasPrefix(line[at:], tc.replacement) {
				t.Errorf("replacement at byte %d = %q, want prefix %q (line %q)", at, line[at:], tc.replacement, line)
			}
		})
	}
}
