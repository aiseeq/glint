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
	{"sql comment after a closing multi-line string", "m.sql", "SELECT 'a\n' -- nolint:my-rule\nSET x = 1;\n", []int{2}},
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
	{"shell heredoc", "a.sh", "cat > out <<EOF\n# nolint:my-rule\nEOF\n# nolint:my-rule\necho x\n", []int{4}},
	{"shell quoted heredoc", "a.sh", "cat <<'EOF'\n# nolint:my-rule\nEOF\ncat <<\"END\"\n# nolint:my-rule\nEND\necho x\n", nil},
	{"shell heredoc with tabs stripped", "a.sh", "cat <<-EOF\n\t# nolint:my-rule\n\tEOF\n# nolint:my-rule\necho x\n", []int{4}},
	{"shell heredoc terminator must stand alone", "a.sh", "cat <<EOF\n EOF\nEOF x\n# nolint:my-rule\nEOF\necho x\n", nil},
	{"shell comment on the heredoc line", "a.sh", "cat <<EOF # nolint:my-rule\n# nolint:my-rule\nEOF\necho x\n", []int{1}},
	{"shell two heredocs on a line", "a.sh", "paste <<A <<B\n# nolint:my-rule\nA\n# nolint:my-rule\nB\n# nolint:my-rule\necho x\n", []int{6}},
	{"shell here-string", "a.sh", "cat <<<x\n# nolint:my-rule\necho x\n", []int{2}},
	{"shell arithmetic shift", "a.sh", "echo $((1 << n))\n# nolint:my-rule\necho x\n", []int{2}},
	{"shell heredoc in quotes", "a.sh", "echo \"<<EOF\"\n# nolint:my-rule\necho x\n", []int{2}},
	{"shell multi-line double quotes", "a.sh", "echo \"multi\n# nolint:my-rule\n\"\necho x\n", nil},
	{"shell multi-line single quotes", "a.sh", "echo 'multi\n# nolint:my-rule\n'\necho x\n", nil},
	{"shell backslash in single quotes", "a.sh", "echo 'a\\' # nolint:my-rule\necho x\n", []int{1}},
	{"shell ansi-c quotes", "a.sh", "echo $'it\\'s' # nolint:my-rule\necho x\n", []int{1}},
	{"shell escaped quote", "a.sh", "echo \\\" # nolint:my-rule\necho x\n", []int{1}},
	{"shell hash in a word", "a.sh", "echo a#nolint:my-rule ${#x}#nolint:my-rule\necho x\n", nil},
	{"shell heredoc of a script", "a.sh", "cat >\"$d/hold\" <<'EOF'\n#!/bin/bash\nflock 8 || exit 1 # nolint:my-rule the lock is held on purpose\nEOF\necho x\n", []int{3}},
	{"shell heredoc of an env shebang script", "a.sh", "cat > s <<EOF\n#!/usr/bin/env bash\n# nolint:my-rule\nrun\nEOF\necho x\n", []int{3}},
	{"shell quotes in a heredoc script", "a.sh", "cat <<EOF\n#!/bin/sh\necho '# nolint:my-rule'\n# nolint:my-rule\nEOF\necho x\n", []int{4}},
	{"shell heredoc in a heredoc script", "a.sh", "cat <<'OUT'\n#!/bin/bash\ncat <<IN\n# nolint:my-rule\nIN\n# nolint:my-rule\nOUT\n# nolint:my-rule\necho x\n", []int{6, 8}},
	{"shell heredoc script ends at its delimiter", "a.sh", "cat <<'OUT'\n#!/bin/bash\necho \"open\nOUT\n# nolint:my-rule\necho x\n", []int{5}},
	{"shell heredoc script with tabs stripped", "a.sh", "cat <<-EOF\n\t#!/bin/bash\n\t# nolint:my-rule\n\tEOF\necho x\n", []int{3}},
	{"shell heredoc to bash", "a.sh", "bash <<EOF\n# nolint:my-rule\nrun\nEOF\n", []int{2}},
	{"shell heredoc to sh -s", "a.sh", "sh -s <<'EOF'\n# nolint:my-rule\nrun\nEOF\n", []int{2}},
	{"shell heredoc to bash -s with arguments", "a.sh", "bash -s -- a b <<EOF\n# nolint:my-rule\nrun\nEOF\n", []int{2}},
	{"shell heredoc to ssh", "a.sh", "ssh host.example <<'EOF'\n# nolint:my-rule\nrun\nEOF\n", []int{2}},
	{"shell heredoc to sudo bash", "a.sh", "sudo bash <<EOF\n# nolint:my-rule\nrun\nEOF\n", []int{2}},
	{"shell heredoc to sudo -u bash", "a.sh", "sudo -u app /bin/bash <<EOF\n# nolint:my-rule\nrun\nEOF\n", []int{2}},
	{"shell heredoc to bash after then", "a.sh", "if true; then bash <<EOF\n# nolint:my-rule\nrun\nEOF\nfi\n", []int{2}},
	{"shell heredoc to bash with a variable", "a.sh", "X=1 env bash <<EOF\n# nolint:my-rule\nrun\nEOF\n", []int{2}},
	{"shell heredoc to bash with a redirection", "a.sh", "bash 2>/dev/null <<EOF\n# nolint:my-rule\nrun\nEOF\n", []int{2}},
	{"shell heredoc to dash", "a.sh", "dash -e <<EOF\n# nolint:my-rule\nrun\nEOF\n", []int{2}},
	{"shell heredoc to ksh", "a.sh", "ksh <<EOF\n# nolint:my-rule\nrun\nEOF\n", []int{2}},
	{"shell heredoc to zsh", "a.sh", "zsh <<EOF\n# nolint:my-rule\nrun\nEOF\n", []int{2}},
	{"shell heredoc with no command", "a.sh", "<<EOF\n# nolint:my-rule\nEOF\n# nolint:my-rule\necho x\n", []int{4}},
	{"shell script heredocs one after another", "a.sh", "cat <<'A'\n#!/bin/bash\necho \"open\nA\ncat <<'B'\n#!/bin/bash\n# nolint:my-rule\nrun\nB\n", []int{7}},
	{"shell heredoc to a script file", "a.sh", "bash run.sh <<EOF\n# nolint:my-rule\nEOF\necho x\n", nil},
	{"shell heredoc to bash -c", "a.sh", "bash -c 'read x' <<EOF\n# nolint:my-rule\nEOF\necho x\n", nil},
	{"shell heredoc to psql", "a.sh", "psql <<SQL\n-- x\n# nolint:my-rule\nSQL\necho x\n", nil},
	{"shell heredoc to cat after a bash command", "a.sh", "bash run.sh; cat <<EOF\n# nolint:my-rule\nEOF\necho x\n", nil},
	{"shell shebang later in a heredoc", "a.sh", "cat <<EOF\nfoo\n#!/bin/bash\n# nolint:my-rule\nEOF\necho x\n", nil},
	{"shell heredoc of a python script", "a.sh", "cat <<EOF\n#!/usr/bin/env python3\n# nolint:my-rule\nEOF\necho x\n", nil},
	{"yaml block scalar", "ci.yml", "run: |\n  # nolint:my-rule\n# nolint:my-rule\nkey: v\n", []int{3}},
	{"yaml folded scalar", "ci.yml", "a: >-\n  # nolint:my-rule\n\n  # nolint:my-rule\nb: c\n", nil},
	{"yaml block scalar in a sequence", "ci.yml", "steps:\n  - run: |\n      # nolint:my-rule\n    container: x # nolint:my-rule\n", []int{4}},
	{"yaml block scalar header comment", "ci.yml", "a: |2 # nolint:my-rule\n  x\n", []int{1}},
	{"yaml empty block scalar", "ci.yml", "a: |\nb: 1 # nolint:my-rule\n", []int{2}},
	{"yaml anchored block scalar", "ci.yml", "a: &x |\n  # nolint:my-rule\nb: 1\n", nil},
	{"yaml bar in a plain scalar", "ci.yml", "a: x |\n# nolint:my-rule\nb: 1\n", []int{2}},
	{"yaml double-quoted", "ci.yml", "a: \"# nolint:my-rule\"\nb: { n: '# nolint:my-rule' }\n", nil},
	{"yaml multi-line quotes", "ci.yml", "a: \"x\n  # nolint:my-rule\"\nb: 1\n", nil},
	{"yaml apostrophe in a plain scalar", "ci.yml", "a: don't # nolint:my-rule\nb: 1\n", []int{1}},
	{"yaml doubled single quote", "ci.yml", "a: 'it''s # x' # nolint:my-rule\nb: 1\n", []int{1}},
	{"yaml hash in a word", "ci.yml", "a: x#nolint:my-rule\n", nil},
	{"dockerfile comment line", "Dockerfile", "FROM alpine\n  # nolint:my-rule\nRUN x\n", []int{2}},
	{"dockerfile hash after an instruction", "Dockerfile", "FROM alpine\nCOPY a b # nolint:my-rule\nRUN x\n", nil},
	{"dockerfile comment in a continuation", "Containerfile", "RUN a \\\n# nolint:my-rule\n  b\n", []int{2}},
	{"dockerfile heredoc", "app.dockerfile", "RUN <<EOF\n# nolint:my-rule\nEOF\n# nolint:my-rule\nRUN x\n", []int{4}},
	{"make comment after a recipe", "Makefile", "build:\n\t@echo x # nolint:my-rule\n\t@echo y\n", []int{2}},
	{"shell comment after a closing quote", "a.sh", "echo \"a\n\" # nolint:my-rule\necho x\n", []int{2}},
	{"yaml empty block scalar in a mapping", "ci.yml", "x:\n  a: |\n  b: 1 # nolint:my-rule\n  c: 2\n", []int{3}},
	{"yaml comment after a closing quote", "ci.yml", "a: \"x\n  y\" # nolint:my-rule\nb: 1\n", []int{2}},
	{"yaml bar after a plain scalar", "ci.yml", "a: b |\n  # nolint:my-rule\nc: 1\n", []int{2}},
	{"yaml bracket in a plain scalar", "ci.yml", "a: x[, 'y # nolint:my-rule\nb: 1\n", []int{1}},
	{"yaml comma in a plain scalar", "ci.yml", "a: x, 'y # nolint:my-rule\nb: 1\n", []int{1}},
	{"yaml colon in a plain scalar", "ci.yml", "a: b:'c # nolint:my-rule\nd: 1\n", []int{1}},
	{"yaml second block scalar indented less", "ci.yml", "a: |\n    x\nb: |\n  # nolint:my-rule\nc: 1\n", nil},
	{"yaml comma after a closed flow sequence", "ci.yml", "a: [x], 'y # nolint:my-rule\nb: 1\n", []int{1}},
	{"yaml quoted sequence entry", "ci.yml", "- 'a # nolint:my-rule\n  b'\n- x\n", nil},
	{"template action after a template comment", "p.tmpl", "{{/* a */}}\n{{ .X }} <!-- nolint:my-rule -->\n<p>x</p>\n", []int{2}},
	{"yaml escaped double quote", "ci.yml", "a: \"x\\\" # nolint:my-rule\n  y\"\nb: 1\n", nil},
	{"go comment after a closing raw string", "a.go", "package p\n\nvar s = `\n` //nolint:my-rule\nconst ()\n", []int{4}},
	{"html comment after spaces", "p.html", "  <!-- nolint:my-rule -->\n<p>x</p>\n", []int{1}},
	{"html comment after text", "p.html", "text <!-- nolint:my-rule -->\nmore\n", []int{1}},
	{"template comment after script code", "p.html", "<script>\nvar a = 1; {{/* nolint:my-rule */}}\n</script>\n", []int{2}},
	{"template comment before script code", "p.html", "<script>\n{{/* nolint:my-rule */}} var a = 1;\n</script>\n", []int{2}},
	{"html comment after a tag over lines", "p.html", "<div\n  title=\"a\"> <!-- nolint:my-rule -->\n<p>x</p>\n", []int{2}},
}

// markerWithCode are, by fixture, the marker lines that hold code besides
// the marker: such a marker covers its line only, not the next one.
var markerWithCode = map[string][]int{
	"ts line comment":                               {1},
	"md comment on the line":                        {3},
	"html comment":                                  {1},
	"md comment after a closed double span":         {1},
	"md unmatched backtick is text":                 {1},
	"sql dollar quote":                              {1},
	"sql tagged dollar quote":                       {3},
	"sql tagged DO body over lines":                 {4},
	"sql dollar string in a body":                   {4},
	"sql escape string":                             {1},
	"sql positional parameter":                      {1},
	"html comment after a script":                   {1},
	"html text with a less-than":                    {1},
	"template comment after an action":              {1},
	"template comment in a script after code":       {1},
	"template action after a script":                {1},
	"comment after a script with an action":         {1},
	"html comment after a textarea":                 {1},
	"shell comment on the heredoc line":             {1},
	"shell backslash in single quotes":              {1},
	"shell ansi-c quotes":                           {1},
	"shell escaped quote":                           {1},
	"yaml block scalar in a sequence":               {4},
	"yaml block scalar header comment":              {1},
	"yaml empty block scalar":                       {2},
	"yaml apostrophe in a plain scalar":             {1},
	"yaml doubled single quote":                     {1},
	"sql comment after a closing multi-line string": {2},
	"shell heredoc of a script":                     {3},
	"make comment after a recipe":                   {2},
	"shell comment after a closing quote":           {2},
	"yaml empty block scalar in a mapping":          {3},
	"yaml comment after a closing quote":            {2},
	"yaml bracket in a plain scalar":                {1},
	"yaml comma in a plain scalar":                  {1},
	"yaml colon in a plain scalar":                  {1},
	"html comment after text":                       {1},
	"template comment after script code":            {2},
	"template comment before script code":           {2},
	"html comment after a tag over lines":           {2},
	"yaml comma after a closed flow sequence":       {1},
	"template action after a template comment":      {2},
}

func fixtureContext(f markerFixture) *FileContext {
	return &FileContext{Path: f.path, RelPath: f.path, Lines: strings.Split(f.source, "\n")}
}

// The markers a file carries are the comments of its own language, and they
// are what both suppression and the marker rules read: a line is suppressed
// exactly when a marker the rules see stands on it, or directly above it on a
// line of its own; a marker after code covers that line only.
func TestSuppressionMarkersAreWhatSuppresses(t *testing.T) {
	for _, f := range markerFixtures {
		t.Run(f.name, func(t *testing.T) {
			withCode := markerWithCode[f.name]
			var lines []int
			for _, marker := range fixtureContext(f).SuppressionMarkers() {
				assert.Equal(t, []string{"my-rule"}, marker.Rules)
				assert.Equal(t, slices.Contains(withCode, marker.Line), marker.WithCode, "WithCode of the marker on line %d", marker.Line)
				lines = append(lines, marker.Line)
			}
			assert.Equal(t, f.lines, lines, "marker lines")
			for line := 1; line <= len(fixtureContext(f).Lines); line++ {
				want := false
				for _, marked := range f.lines {
					want = want || marked == line || marked == line-1 && !slices.Contains(withCode, marked)
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

// A marker after code on line N is that line's: the finding on N+1 is not
// hidden by it, and a marker on N+1 is the one that silences there, so it
// is not left stale. A marker on a line of its own still covers the line
// under it, the declaration below a Go marker among them.
func TestMarkerAfterCodeCoversItsLineOnly(t *testing.T) {
	tests := []struct {
		name, path, source string
		// hits are the lines of the markers that silence findings on
		// lines 1 to 3, by finding line; 0 when none does.
		hits [3]int
	}{
		{"ts", "a.ts", "const a = \"x\"; // nolint:my-rule\nconst b = \"y\"; // nolint:my-rule fixture key\nconst c = 1;\n", [3]int{1, 2, 0}},
		{"js after code only", "b.js", "const a = \"x\"; // nolint:my-rule\nconst b = \"y\";\n\n", [3]int{1, 0, 0}},
		{"ts block before code", "a.ts", "/* nolint:my-rule */ const a = 1;\nconst b = 2; // nolint:my-rule\n\n", [3]int{1, 2, 0}},
		{"sql", "m.sql", "CREATE TABLE g (c CHAR(3)); -- nolint:my-rule\nCREATE TABLE h (c CHAR(3)); -- nolint:my-rule fixed-width code\n\n", [3]int{1, 2, 0}},
		{"shell", "a.sh", "echo x # nolint:my-rule\npsql -f d.sql\n\n", [3]int{1, 0, 0}},
		{"yaml", "compose.yml", "image: nginx # nolint:my-rule\nports: [80]\n\n", [3]int{1, 0, 0}},
		{"go declaration below a marker", "a.go", "//nolint:my-rule generated table\nfunc f() {}\n\n", [3]int{1, 1, 0}},
		{"go marker after code covers the next line, as golangci-lint reads it", "a.go", "if err != nil { //nolint:my-rule\n\treturn nil\n}\n", [3]int{1, 1, 0}},
		{"python marker after code", "s.py", "x = 1  # nolint:my-rule\ny = 2\n\n", [3]int{1, 0, 0}},
		{"html comment after text", "p.html", "<p>x</p> <!-- nolint:my-rule -->\n<p>y</p>\n\n", [3]int{1, 0, 0}},
		{"template comment of its own", "p.tmpl", "{{- /* nolint:my-rule */ -}}\n<p>y</p>\n\n", [3]int{1, 1, 0}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for line, want := range tt.hits {
				ctx := &FileContext{Path: tt.path, RelPath: tt.path, Lines: strings.Split(tt.source, "\n")}
				assert.Equal(t, want != 0, ctx.IsSuppressed(line+1, "my-rule"), "IsSuppressed(%d)", line+1)
				var hits []int
				if want != 0 {
					hits = []int{want}
				}
				assert.Equal(t, hits, ctx.TakeSuppressionHits("my-rule"), "marker that silences line %d", line+1)
			}
		})
	}
}
