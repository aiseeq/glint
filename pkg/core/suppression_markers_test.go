package core

import (
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// markerFixture is a file and the lines of the markers it carries.
type markerFixture struct {
	name, path, source string
	lines              []int
}

var markerFixtures = []markerFixture{
	{"go line comment", "a.go", "package p\n\n//nolint:my-rule\nconst ()\n", []int{3}},
	{"go block continuation", "a.go", "package p\n\n/* grouped constants\n * nolint:my-rule */\nconst ()\n", []int{4}},
	{"go block one line", "a.go", "package p\n\n/* nolint:my-rule real reason */\nconst ()\n", []int{3}},
	{"go raw string", "a.go", "package p\n\nvar s = `\n//nolint:my-rule\n`; const ()\n", nil},
	{"go interpreted string", "a.go", "package p\n\nvar s = \"//nolint:my-rule\"\n", nil},
	{"go doc code block", "a.go", "package p\n\n//\tnolint:my-rule\nconst ()\n", nil},
	{"go two comments on a line", "a.go", "package p\n\nconst () /* note */ //nolint:my-rule\n", []int{3}},
	{"ts template literal", "a.ts", "const t = `\n//nolint:my-rule\n`; const password = 1;\n", nil},
	{"ts block continuation", "a.ts", "/* grouped\n * nolint:my-rule */\nconst x = 1;\n", []int{2}},
	{"ts line comment", "a.ts", "const x = 1; //nolint:my-rule\n", []int{1}},
	{"md comment on the line", "doc.md", "# Doc\n\nSee [x](missing.md). <!-- //nolint:my-rule -->\n", []int{3}},
	{"md comment above", "doc.md", "# Doc\n\n<!-- nolint:my-rule -->\nSee [x](missing.md).\n", []int{3}},
	{"md slashes are text", "doc.md", "//nolint:my-rule\nSee [x](missing.md).\n", nil},
	{"md comment in a fence", "doc.md", "```html\n<!-- nolint:my-rule -->\n```\nSee [x](missing.md).\n", nil},
	{"md comment in inline code", "doc.md", "Write `<!-- nolint:my-rule -->` above.\n", nil},
	{"html comment", "p.html", "<script src=\"x.js\"></script> <!-- //nolint:my-rule -->\n", []int{1}},
	{"html slashes are text", "p.html", "<p>//nolint:my-rule</p>\n", nil},
	{"go template comment", "p.tmpl", "{{/* nolint:my-rule */}}\n<p>x</p>\n", []int{1}},
	{"python hash comment", "s.py", "# nolint:my-rule\nprint(\"x\")\n", []int{1}},
	{"python slashes after the hash", "s.py", "# //nolint:my-rule\nprint(\"x\")\n", nil},
	{"python triple-quoted string", "s.py", "s = \"\"\"\n# nolint:my-rule\n\"\"\"\n", nil},
	{"python slashes are text", "s.py", "x = 1 //nolint:my-rule\n", nil},
	{"sql dash comment", "m.sql", "-- nolint:my-rule\nDROP TABLE t;\n", []int{1}},
	{"sql dashes in a string", "m.sql", "SELECT '-- nolint:my-rule';\n", nil},
	{"nginx hash comment", "site.conf", "# nolint:my-rule\nserver {}\n", []int{1}},
	{"tsconfig line comment", "tsconfig.json", "{\n  // nolint:my-rule\n  \"strict\": false\n}\n", []int{2}},
	{"shell hash comment", "a.sh", "#nolint:my-rule\necho x\n", []int{1}},
	{"yaml hash comment", "settings.yaml", "#nolint:my-rule\nkey: v\n", []int{1}},
	{"plain text has no comments", "notes.txt", "//nolint:my-rule\n# nolint:my-rule\n", nil},
	{"md code span of two backticks", "doc.md", "`` <!-- nolint:my-rule --> ``\ntext\n", nil},
	{"md single backtick inside a double span", "doc.md", "``a ` <!-- nolint:my-rule --> ``\ntext\n", nil},
	{"md comment after a closed double span", "doc.md", "`` a `` <!-- nolint:my-rule -->\ntext\n", []int{1}},
	{"md unmatched backtick is text", "doc.md", "a ` b <!-- nolint:my-rule -->\ntext\n", []int{1}},
	{"md long fence holds a short one", "doc.md", "````markdown\n```\n<!-- nolint:my-rule -->\n```\n````\n<!-- nolint:my-rule -->\ntext\n", []int{6}},
	{"md tilde fence", "doc.md", "~~~\n<!-- nolint:my-rule -->\n~~~\n<!-- nolint:my-rule -->\ntext\n", []int{4}},
	{"md tildes do not close backticks", "doc.md", "```\n~~~\n<!-- nolint:my-rule -->\n```\ntext\n", nil},
	{"md indented code block", "doc.md", "# E\n\n    <!-- nolint:my-rule -->\ntext\n", nil},
	{"md tab-indented code block", "doc.md", "# E\n\n\t<!-- nolint:my-rule -->\ntext\n", nil},
	{"md indented paragraph continuation", "doc.md", "text\n    <!-- nolint:my-rule -->\ntext\n", []int{2}},
	{"sql multi-line string", "m.sql", "SELECT 'multi\n-- nolint:my-rule\n';\nSET x = 1;\n", nil},
	{"sql dollar quote", "m.sql", "SELECT $$ it's $$; -- nolint:my-rule\nSET x = 1;\n", []int{1}},
	{"sql tagged dollar quote", "m.sql", "SELECT $body$\n-- nolint:my-rule\n$body$; -- nolint:my-rule\nSET x = 1;\n", []int{3}},
	{"sql DO body is code", "m.sql", "DO $$\nBEGIN\n  -- nolint:my-rule\n  SET x = 1;\nEND $$;\n", []int{3}},
	{"sql block comment in a DO body", "m.sql", "DO $$\nBEGIN\n  /* nolint:my-rule */\n  SET x = 1;\nEND $$;\n", []int{3}},
	{"sql tagged DO body over lines", "m.sql", "do\n$body$\n-- nolint:my-rule\n$body$; -- nolint:my-rule\nSET x = 1;\n", []int{3, 4}},
	{"sql function body is code", "m.sql", "CREATE FUNCTION f() RETURNS void AS $fn$\nBEGIN\n  -- nolint:my-rule\n  RETURN;\nEND $fn$ LANGUAGE plpgsql;\n", []int{3}},
	{"sql dollar string in a body", "m.sql", "DO $$\nBEGIN\n  RAISE NOTICE $q$ -- nolint:my-rule $q$;\nEND $$; -- nolint:my-rule\nSET x = 1;\n", []int{4}},
	{"sql function body in a DO body", "m.sql", "DO $$\nBEGIN\n  EXECUTE $f$ SELECT 1 $f$;\n  -- nolint:my-rule\nEND $$;\nSET x = 1;\n", []int{4}},
	{"sql dollar string after a word ending in as", "m.sql", "SELECT alias $$\n-- nolint:my-rule\n$$;\nSET x = 1;\n", nil},
	{"sql dollar string after a closed body", "m.sql", "DO $$ BEGIN NULL; END $$;\nSELECT $$\n-- nolint:my-rule\n$$;\nSET x = 1;\n", nil},
	{"sql dollar string after AS and a bracket", "m.sql", "SELECT 1 AS (\n$$\n-- nolint:my-rule\n$$);\nSET x = 1;\n", nil},
	{"sql dollar string after AS and a quoted name", "m.sql", "SELECT 1 AS \"a\" $$\n-- nolint:my-rule\n$$;\nSET x = 1;\n", nil},
	{"sql dollar string first in a body", "m.sql", "DO $a$\n$q$\n-- nolint:my-rule\n$q$\n$a$;\nSET x = 1;\n", nil},
	{"sql body closed right after a word", "m.sql", "DO $$\nBEGIN\n  SET x = 1;\nEND$$;\nSELECT $$ -- nolint:my-rule $$;\nSET x = 1;\n", nil},
	{"sql dollar in a name ending in do", "m.sql", "SELECT do$$ FROM t;\nSELECT $$\n-- nolint:my-rule\n$$;\nSET x = 1;\n", nil},
	{"sql dollar string after AS and a comma", "m.sql", "SELECT 1 AS a, $$\n-- nolint:my-rule\n$$;\nSET x = 1;\n", nil},
	{"sql escape string", "m.sql", "SELECT E'\\'' AS q; -- nolint:my-rule\nSET x = 1;\n", []int{1}},
	{"sql positional parameter", "m.sql", "SELECT $1, 'a'; -- nolint:my-rule\nSET x = 1;\n", []int{1}},
	{"html comment in an attribute", "p.html", "<div title=\"<!-- nolint:my-rule -->\"></div>\n<p>x</p>\n", nil},
	{"html attribute with a greater-than", "p.html", "<div title=\"a > b <!-- nolint:my-rule -->\"></div>\n<p>x</p>\n", nil},
	{"template action string with braces", "p.tmpl", "{{ printf \"}} <!-- nolint:my-rule -->\" }}\n<p>x</p>\n", nil},
	{"html comment in a script string", "p.html", "<script>var s = \"<!-- nolint:my-rule -->\";</script>\n<p>x</p>\n", nil},
	{"html comment after a script", "p.html", "<script>var s = 1;</script> <!-- nolint:my-rule -->\n<p>x</p>\n", []int{1}},
	{"html attribute over lines", "p.html", "<div\n  title='a\n<!-- nolint:my-rule -->'>\n</div>\n", nil},
	{"html multi-line comment", "p.html", "<!--\n nolint:my-rule\n-->\n<p>x</p>\n", []int{2}},
	{"html text with a less-than", "p.html", "<p>a < b</p> <!-- nolint:my-rule -->\n<p>x</p>\n", []int{1}},
	{"template action string", "p.tmpl", "{{ \"<!-- nolint:my-rule -->\" }}\n<p>x</p>\n", nil},
	{"template trimmed comment", "p.tmpl", "{{- /* nolint:my-rule */ -}}\n<p>x</p>\n", []int{1}},
	{"template comment after an action", "p.gohtml", "{{ .Name }} {{/* nolint:my-rule */}}\n<p>x</p>\n", []int{1}},
	{"template comment in a script", "p.html", "<script>\n{{/* nolint:my-rule */}}\n</script>\n<p>x</p>\n", []int{2}},
	{"template comment in a script after code", "p.html", "<script>var a = 1; {{- /* nolint:my-rule */ -}}</script>\n<p>x</p>\n", []int{1}},
	{"script text after a template action", "p.html", "<script>{{ .X }} var s = \"<!-- nolint:my-rule -->\";</script>\n<p>x</p>\n", nil},
	{"script end in a template action string", "p.html", "<script>{{ \"</script>\" }} <!-- nolint:my-rule --></script>\n<p>x</p>\n", nil},
	{"template action after a script", "p.html", "<script></script> {{ .X }} <!-- nolint:my-rule -->\n<p>x</p>\n", []int{1}},
	{"comment after a script with an action", "p.html", "<script>{{ .X }}</script> <!-- nolint:my-rule -->\n<p>x</p>\n", []int{1}},
	{"html comment in a textarea", "p.html", "<textarea><!-- nolint:my-rule --></textarea>\n<p>x</p>\n", nil},
	{"html comment in a title", "p.html", "<TITLE>a <!-- nolint:my-rule --></TITLE>\n<p>x</p>\n", nil},
	{"html comment after a textarea", "p.html", "<textarea>x</textarea> <!-- nolint:my-rule -->\n<p>x</p>\n", []int{1}},
}

func fixtureContext(f markerFixture) *FileContext {
	return &FileContext{Path: f.path, RelPath: f.path, Lines: strings.Split(f.source, "\n")}
}

// The markers a file carries are the comments of its own language, and they
// are what both suppression and the marker rules read: a line is suppressed
// exactly when a marker the rules see stands on it or directly above it.
func TestSuppressionMarkersAreWhatSuppresses(t *testing.T) {
	for _, f := range markerFixtures {
		t.Run(f.name, func(t *testing.T) {
			var lines []int
			for _, marker := range fixtureContext(f).SuppressionMarkers() {
				assert.Equal(t, []string{"my-rule"}, marker.Rules)
				lines = append(lines, marker.Line)
			}
			assert.Equal(t, f.lines, lines, "marker lines")
			for line := 1; line <= len(fixtureContext(f).Lines); line++ {
				want := false
				for _, marked := range f.lines {
					want = want || marked == line || marked == line-1
				}
				assert.Equal(t, want, fixtureContext(f).IsSuppressed(line, "my-rule"), "IsSuppressed(%d)", line)
				assert.Equal(t, slices.Contains(f.lines, line), fixtureContext(f).LineSuppresses(line, "my-rule"), "LineSuppresses(%d)", line)
			}
		})
	}
}

// A CRLF file has the markers of the same file with LF line ends.
func TestSuppressionMarkersReadCRLF(t *testing.T) {
	for _, f := range markerFixtures {
		t.Run(f.name, func(t *testing.T) {
			f.source = strings.ReplaceAll(f.source, "\n", "\r\n")
			var lines []int
			for _, marker := range fixtureContext(f).SuppressionMarkers() {
				assert.Equal(t, []string{"my-rule"}, marker.Rules)
				lines = append(lines, marker.Line)
			}
			assert.Equal(t, f.lines, lines, "marker lines")
		})
	}
}

// A reason is text with a letter or a digit: punctuation alone explains
// nothing.
func TestSuppressionReasonNeedsALetterOrDigit(t *testing.T) {
	for comment, want := range map[string]bool{
		"//nolint:my-rule .":                                      false,
		"//nolint:my-rule //":                                     false,
		"//nolint:my-rule –":                                      false,
		"//nolint:my-rule --":                                     false,
		"// my-rule: safe.":                                       false,
		"// my-rule: safe –":                                      false,
		"// my-rule: safe —":                                      false,
		"/* nolint:my-rule */":                                    false,
		"//nolint:my-rule — real reason":                          true,
		"/* nolint:my-rule real reason */":                        true,
		"//nolint:my-rule -- 42":                                  true,
		"// my-rule: safe — причина":                              true,
		"// my-rule:\tsafe — real reason":                         true,
		"//nolint:other, my-rule — reason for both":               true,
		"//nolint:my-rule //nolint:other":                         false,
		"//nolint:my-rule # nolint":                               false,
		"//nolint:my-rule //nolint:other — generated table":       true,
		"//nolint:my-rule my-rule":                                false,
		"//nolint:other, my-rule other my-rule":                   false,
		"// my-rule: safe my-rule: safe":                          false,
		"// my-rule: safe — other-rule: safe":                     false,
		"//nolint:my-rule ${reason}":                              false,
		"//nolint:my-rule <reason>":                               false,
		"// my-rule: safe — <reason>":                             false,
		"// my-rule: safe — {{reason}}":                           false,
		"//nolint:my-rule 1":                                      true,
		"//nolint:my-rule x < y holds here":                       true,
		"// my-rule: safe — returns <nil> by design":              true,
		"//nolint:my-rule <https://example.com/issues/12>":        true,
		"//nolint:my-rule <issue-12>":                             true,
		"//nolint:my-rule <#12>":                                  true,
		"//nolint:my-rule <https://example.com/docs/cache>":       true,
		"//nolint:my-rule <#cold-cache>":                          true,
		"//nolint:my-rule <nil>":                                  false,
		"// my-rule: safe — <limit, measured RSS>":                false,
		"// my-rule: safe — followed by why it is needed":         false,
		"# my-rule: safe — followed by why the project needs it":  false,
		"// my-rule: safe — ` followed by the reason written out": false,
	} {
		assert.Equal(t, want, SuppressionHasReason(comment, "my-rule"), comment)
	}
}
