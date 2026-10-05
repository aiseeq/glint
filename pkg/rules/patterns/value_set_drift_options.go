package patterns

import (
	"fmt"
	"go/ast"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

// optionSet is the literal options of a <select> in a template: code to
// label, with the words of the select's name.
type optionSet struct {
	path   string
	line   int
	words  map[string]bool
	labels map[string]string
}

var (
	selectBlock = regexp.MustCompile(`(?s)<select\b([^>]*)>(.*?)</select>`)
	selectName  = regexp.MustCompile(`\bname="([^"{}]+)"`)
	optionTag   = regexp.MustCompile(`<option\b[^>]*\bvalue="([^"{}]+)"[^>]*>([^<{}]*)</option>`)
	// labelCode is the code a label repeats before its text: "3 — Cash".
	labelCode = regexp.MustCompile(`^\s*[\w.]+\s*(?:—|–|-|:|\.)\s+`)
)

// templateOptionSets reads the <select> elements of the project's templates
// whose options carry three or more literal codes.
func templateOptionSets(root string) ([]optionSet, error) {
	paths, err := templateFiles(root)
	if err != nil {
		return nil, err
	}
	var sets []optionSet
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return nil, err
		}
		text := string(data)
		for _, m := range selectBlock.FindAllStringSubmatchIndex(text, -1) {
			name := selectName.FindStringSubmatch(text[m[2]:m[3]])
			if name == nil {
				continue
			}
			labels := make(map[string]string)
			for _, opt := range optionTag.FindAllStringSubmatch(text[m[4]:m[5]], -1) {
				labels[opt[1]] = opt[2]
			}
			if len(labels) < 3 {
				continue
			}
			sets = append(sets, optionSet{
				path: filepath.ToSlash(rel), line: strings.Count(text[:m[0]], "\n") + 1,
				words: lowerWords(name[1]), labels: labels,
			})
		}
	}
	return sets, nil
}

// lowerWords returns the lower-case words of a name: payout_method,
// payoutMethodDesc.
func lowerWords(name string) map[string]bool {
	words := make(map[string]bool)
	for _, part := range strings.FieldsFunc(name, func(r rune) bool { return r == '_' || r == '-' || r == '.' }) {
		for _, word := range helpers.IdentifierWords(part) {
			words[strings.ToLower(word)] = true
		}
	}
	return words
}

// labelSwitch is a function translating codes to labels with a switch whose
// every case returns a literal.
type labelSwitch struct {
	name   string
	line   int
	labels map[string]string
}

// fileLabelSwitches returns the label switches of a Go file.
func fileLabelSwitches(ctx *core.FileContext) []labelSwitch {
	var out []labelSwitch
	for _, decl := range ctx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			sw, ok := n.(*ast.SwitchStmt)
			if !ok {
				return true
			}
			labels := make(map[string]string)
			for _, stmt := range sw.Body.List {
				clause, ok := stmt.(*ast.CaseClause)
				if !ok {
					return true
				}
				if clause.List == nil {
					continue
				}
				label, ok := stringLiteral(singleReturnExpr(clause.Body))
				if !ok || len(clause.List) != 1 {
					return true
				}
				code, ok := clause.List[0].(*ast.BasicLit)
				if !ok || (code.Kind != token.INT && code.Kind != token.STRING) {
					return true
				}
				value := code.Value
				if text, isString := stringLiteral(code); isString {
					value = text
				}
				labels[value] = label
			}
			if len(labels) >= 3 {
				out = append(out, labelSwitch{name: fn.Name.Name, line: ctx.LineFor(sw), labels: labels})
			}
			return true
		})
	}
	return out
}

// singleReturnExpr returns the value of a body that is one return of one value.
func singleReturnExpr(body []ast.Stmt) ast.Expr {
	if len(body) != 1 {
		return nil
	}
	ret, ok := body[0].(*ast.ReturnStmt)
	if !ok || len(ret.Results) != 1 {
		return nil
	}
	return ret.Results[0]
}

// labelText normalizes a label for comparison: no repeated code, lower case,
// single spaces.
func labelText(label string) string {
	return strings.Join(strings.Fields(strings.ToLower(labelCode.ReplaceAllString(label, ""))), " ")
}

// optionLabelDrift reports a label switch whose codes a template <select>
// of the same name lists with other labels:
//
//	func payoutMethodDesc(pm int) string { switch pm { case 3: return "Cash Pickup" ... } }
//	<select name="payout_method"><option value="3">3 — Mobile Wallet</option>
//
// The screen offers a code under another meaning than the code gives it.
func (r *ValueSetDriftRule) optionLabelDrift(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || !ctx.HasGoAST() {
		return nil
	}
	var violations []*core.Violation
	for _, sw := range fileLabelSwitches(ctx) {
		words := lowerWords(sw.name)
		for _, set := range r.options {
			shared, differ := 0, ""
			for code, label := range set.labels {
				goLabel, ok := sw.labels[code]
				if !ok {
					continue
				}
				shared++
				a, b := labelText(label), labelText(goLabel)
				if a != b && !strings.Contains(a, b) && !strings.Contains(b, a) && (differ == "" || code < differ) {
					differ = code
				}
			}
			if shared < 3 || shared*4 < len(set.labels)*3 || differ == "" || !sharesWord(words, set.words) {
				continue
			}
			v := r.CreateViolation(ctx.RelPath, sw.line, fmt.Sprintf(
				"%s names code %s %q, and the <select> at %s:%d offers it as %q — the screen and the code give the code different meanings",
				sw.name, differ, sw.labels[differ], set.path, set.line, set.labels[differ]))
			v.WithCode(strings.TrimSpace(ctx.GetLine(sw.line)))
			v.WithSuggestion("Render the options from the same code-to-label table the code uses")
			violations = append(violations, v)
		}
	}
	return violations
}

// sharesWord reports a word other than a generic one both names have.
func sharesWord(a, b map[string]bool) bool {
	for word := range a {
		switch word {
		case "desc", "label", "name", "type", "code", "id", "text", "title":
			continue
		}
		if b[word] {
			return true
		}
	}
	return false
}
