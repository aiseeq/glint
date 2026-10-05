package patterns

import (
	"go/ast"
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewHandRolledDotenvParserRule())
}

// HandRolledDotenvParserRule detects a hand-written .env parser in a project
// that already parses .env files with a library:
//
//	func parseEnvFile(data []byte) map[string]string {
//	    for _, line := range strings.Split(string(data), "\n") {
//	        if strings.HasPrefix(line, "#") { continue }
//	        if eq := strings.Index(line, "="); eq > 0 { vars[line[:eq]] = line[eq+1:] }
//	    }
//	}
//
// The copy reads the same files as the library and reads them differently:
// quotes stay in the value, "export KEY=..." becomes a key with a space, an
// inline comment joins the value. A secret that loads fine through the
// library arrives quoted through the copy. Use the library's parser
// (godotenv.Parse / godotenv.Read, gotenv.StrictParse).
// The shape: a loop over lines that skips "#" comments and splits at "=".
// In a script or a make recipe, a sed or awk program that turns .env into
// another env file is the same parser, whatever library the code uses.
type HandRolledDotenvParserRule struct {
	*rules.BaseRule
	// library is the dotenv package some production file of the root imports,
	// "" when none does.
	library string
}

// NewHandRolledDotenvParserRule creates the rule
func NewHandRolledDotenvParserRule() *HandRolledDotenvParserRule {
	return &HandRolledDotenvParserRule{BaseRule: rules.NewBaseRule(
		"hand-rolled-dotenv-parser",
		"patterns",
		"Detects a hand-written .env parser in a project that already uses a dotenv library — the copy reads quotes, export and comments differently",
		core.SeverityMedium,
	)}
}

// dotenvLibraries are the import paths of .env parsers.
var dotenvLibraries = []string{`"github.com/joho/godotenv"`, `"github.com/subosito/gotenv"`, `"github.com/hashicorp/go-envparse"`}

// UseProjectFiles finds the dotenv library the root uses.
func (r *HandRolledDotenvParserRule) UseProjectFiles(files []*core.FileContext) {
	r.library = ""
	for _, ctx := range files {
		if !productionGoFile(ctx) {
			continue
		}
		for _, spec := range ctx.GoAST.Imports {
			for _, library := range dotenvLibraries {
				if spec.Path != nil && spec.Path.Value == library {
					r.library = strings.Trim(library, `"`)
					return
				}
			}
		}
	}
}

// ResetState drops the library of the previous root.
func (r *HandRolledDotenvParserRule) ResetState() { r.library = "" }

// AnalyzeFile reports the functions of a file that parse .env by hand.
func (r *HandRolledDotenvParserRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if src, ok := readShell(ctx); ok {
		return append(r.shellRewrites(src), r.shellKeyReads(src)...)
	}
	if r.library == "" || !productionGoFile(ctx) {
		return nil
	}
	var violations []*core.Violation
	for _, decl := range ctx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || !parsesDotenv(fn.Body) {
			continue
		}
		line := ctx.LineFor(fn)
		if ctx.IsSuppressed(line, r.Name()) {
			continue
		}
		v := r.CreateViolation(ctx.RelPath, line, fn.Name.Name+" parses KEY=VALUE lines by hand while the project reads .env with "+r.library+" — the two disagree on quotes, export and comments")
		v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
		v.WithSuggestion("Parse with the library the project already uses (godotenv.Parse / godotenv.Read)")
		violations = append(violations, v)
	}
	return violations
}

// parsesDotenv reports a loop that skips lines starting with "#" and splits
// a line at "=".
func parsesDotenv(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		var loopBody *ast.BlockStmt
		switch loop := n.(type) {
		case *ast.RangeStmt:
			loopBody = loop.Body
		case *ast.ForStmt:
			loopBody = loop.Body
		default:
			return !found
		}
		comment, split := false, false
		ast.Inspect(loopBody, func(m ast.Node) bool {
			call, ok := m.(*ast.CallExpr)
			if !ok || len(call.Args) < 2 {
				return true
			}
			arg, ok := literalText(call.Args[1])
			if !ok {
				return true
			}
			switch calledName(call) {
			case "HasPrefix":
				comment = comment || arg == "#"
			case "Index", "Cut", "SplitN", "IndexByte":
				split = split || arg == "="
			}
			return true
		})
		found = found || (comment && split)
		return !found
	})
	return found
}

var (
	dotenvPath   = regexp.MustCompile(`(?:^|[\s/"'])\.env(?:["'\s;)]|$)`)
	textFilter   = regexp.MustCompile(`(?:^|[\s|;(])(?:sed|awk|gawk)\s`)
	inPlaceEdit  = regexp.MustCompile(`\bsed\s+(?:-[a-zA-Z]*i|--in-place)`)
	dotenvSyntax = regexp.MustCompile(`\^#|="|\\"|'\\''|"'"'"'`)
)

// shellRewrites reports sed or awk turning .env into another env file: the
// program strips comments and quotes its own way, and a value with quotes,
// $ or an inline comment arrives changed. An in-place edit of a key is not
// a parser.
func (r *HandRolledDotenvParserRule) shellRewrites(src *shellSource) []*core.Violation {
	var out []*core.Violation
	for _, l := range src.lines {
		for _, seg := range segments(l.text) {
			if !textFilter.MatchString(seg.text) || inPlaceEdit.MatchString(seg.text) || !dotenvPath.MatchString(seg.text) || !dotenvSyntax.MatchString(seg.text) {
				continue
			}
			out = appendReport(out, src.report(r, l.lineAt(seg.offset),
				"sed/awk rewrites .env by hand — quotes, export, $ and inline comments come out differently than the shell or a dotenv parser reads them",
				"Source the file (set -a; . ./.env; set +a) and print the evaluated values, or use a dotenv parser"))
		}
	}
	return out
}

var (
	// dotenvKeyGrep is a grep for the line of one key: grep '^KEY='.
	dotenvKeyGrep  = regexp.MustCompile(`\bgrep\b[^|]*\^([A-Za-z_][A-Za-z0-9_]*)=`)
	cutAfterEquals = regexp.MustCompile(`\bcut\s+-d\s*['"]?=['"]?\s+-f\s*2`)
	captureVar     = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]*)=\$\(`)
)

// shellKeyReads reports a key read out of .env with grep and its name cut
// off - by cut -d= -f2-, sed 's/^KEY=//' or ${line#KEY=}: the value keeps
// its quotes, an export prefix and an inline comment, which the shell or a
// dotenv parser would strip.
func (r *HandRolledDotenvParserRule) shellKeyReads(src *shellSource) []*core.Violation {
	var out []*core.Violation
	for i, l := range src.lines {
		m := dotenvKeyGrep.FindStringSubmatch(l.text)
		if m == nil || !dotenvPath.MatchString(l.text) || strings.Contains(l.text, "grep -q") {
			continue
		}
		key := m[1]
		stripped := cutAfterEquals.MatchString(l.text) || strings.Contains(l.text, "s/^"+key+"=//")
		if !stripped {
			if c := captureVar.FindStringSubmatch(l.text); c != nil {
				for _, later := range src.lines[i+1:] {
					if strings.Contains(later.text, "${"+c[1]+"#"+key+"=}") {
						stripped = true
						break
					}
				}
			}
		}
		if !stripped {
			continue
		}
		out = appendReport(out, src.report(r, l.lineAt(0),
			"A .env value is read with grep and its name cut off — quotes, export and an inline comment stay in the value the shell would strip",
			"Source the file in a subshell (set -a; . ./.env; printf '%s' \"$KEY\") or use a dotenv parser"))
	}
	return out
}
