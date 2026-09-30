package patterns

import (
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewReactRemountKeyRule())
}

// ReactRemountKeyRule detects a JSX key built from a value that a controlled
// input inside the same element edits. React treats a changed key as a new
// element: every keystroke unmounts the subtree, the fresh input mounts empty
// of focus, and the user can type exactly one character at a time.
//
// Typical case: a wallet row used
// key={`${wallet.walletAddress}-${index}`} while its <input
// value={wallet.walletAddress} onChange=.../> edited that very address.
//
// Precision over recall: the rule fires only when the key expression and the
// input's value= provably reference the same dotted path (x.field) and the
// input has an onChange/onInput handler in the same tag.
type ReactRemountKeyRule struct {
	*rules.BaseRule
	keyAttr    *regexp.Regexp
	valueAttr  *regexp.Regexp
	dottedPath *regexp.Regexp
}

// NewReactRemountKeyRule creates the rule.
func NewReactRemountKeyRule() *ReactRemountKeyRule {
	return &ReactRemountKeyRule{
		BaseRule: rules.NewBaseRule(
			"react-remount-key",
			"patterns",
			"Detects a JSX key derived from a value edited by a controlled input inside the same element — each keystroke remounts the subtree and the input loses focus",
			core.SeverityHigh,
		),
		keyAttr:    regexp.MustCompile(`\bkey=\{`),
		valueAttr:  regexp.MustCompile(`\bvalue=\{\s*([^{}]*?)\s*\}`),
		dottedPath: regexp.MustCompile(`[A-Za-z_$][\w$]*\.[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*`),
	}
}

// AnalyzeFile checks TSX/JSX sources.
func (r *ReactRemountKeyRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsTypeScriptFile() && !ctx.IsJavaScriptFile() {
		return nil
	}
	if skipFrontendPath(ctx) {
		return nil
	}

	// Structure only: tags, braces and attributes inside comments or string
	// literals are not markup.
	code := helpers.FileJSCode(ctx)

	var violations []*core.Violation
	for i, line := range code {
		loc := r.keyAttr.FindStringIndex(line)
		if loc == nil {
			continue
		}
		keyExpr, ok := balancedBraceExpr(line[loc[1]:])
		if !ok {
			continue
		}
		paths := r.editablePathsInKey(keyExpr)
		if len(paths) == 0 {
			continue
		}
		lineNum := i + 1
		if ctx.IsSuppressed(lineNum, r.Name()) {
			continue
		}
		if path, found := r.findControlledInput(code, i, loc[0], paths); found {
			v := r.CreateViolation(ctx.RelPath, lineNum,
				"JSX key is built from '"+path+"', which a controlled input inside this element edits — every keystroke remounts the subtree and the input loses focus")
			v.WithCode(strings.TrimSpace(ctx.Lines[i]))
			v.WithSuggestion("Key the element by a stable identity (persistent id, or the array index for editable drafts) instead of the edited field")
			v.WithContext("pattern", "react-remount-key")
			v.WithContext("key_path", path)
			violations = append(violations, v)
		}
	}
	return violations
}

// editablePathsInKey extracts dotted member paths (wallet.walletAddress) from
// the key expression. Bare identifiers (index, id) carry no provable link to
// an input's value and are ignored.
func (r *ReactRemountKeyRule) editablePathsInKey(keyExpr string) []string {
	seen := make(map[string]bool)
	var paths []string
	for _, path := range r.dottedPath.FindAllString(keyExpr, -1) {
		if seen[path] {
			continue
		}
		seen[path] = true
		paths = append(paths, path)
	}
	return paths
}

// findControlledInput looks inside the keyed element — from its opening tag to
// its closing tag — for value={<path>} whose tag also carries an
// onChange/onInput handler. An input after the element closes is not remounted
// by its key.
func (r *ReactRemountKeyRule) findControlledInput(code []string, keyLine, keyCol int, paths []string) (string, bool) {
	tagLine, tagCol, ok := findTagOpen(code, keyLine, keyCol, jsxTagBackLines)
	if !ok {
		return "", false
	}
	endLine, endCol, ok := jsxElementEnd(code, tagLine, tagCol)
	if !ok {
		return "", false
	}
	wanted := make(map[string]bool, len(paths))
	for _, path := range paths {
		wanted[path] = true
	}
	for j := tagLine; j <= endLine; j++ {
		for _, m := range r.valueAttr.FindAllStringSubmatchIndex(code[j], -1) {
			if (j == tagLine && m[0] < tagCol) || (j == endLine && m[0] > endCol) {
				continue
			}
			path := code[j][m[2]:m[3]]
			if !wanted[path] {
				continue
			}
			if tag, ok := enclosingJSXTag(code, j, m[0]); ok && jsxTagHasChangeHandler(tag) {
				return path, true
			}
		}
	}
	return "", false
}

// jsxTagBackLines bounds how far above an attribute its tag's '<' is looked for.
const jsxTagBackLines = 6

// jsxTagForwardLines bounds how far below its '<' a tag's '>' is looked for.
const jsxTagForwardLines = 12

// jsxTagEnd returns the position of the '>' that ends the tag opened at
// (line, col), skipping '>' inside attribute braces, and whether the tag is
// self-closing.
func jsxTagEnd(code []string, line, col int) (endLine, endCol int, selfClosing, ok bool) {
	depth := 0
	last := byte(0)
	for j := line; j < len(code) && j <= line+jsxTagForwardLines; j++ {
		from := 0
		if j == line {
			from = col + 1
		}
		for i := from; i < len(code[j]); i++ {
			c := code[j][i]
			switch {
			case c == '{':
				depth++
			case c == '}' && depth > 0:
				depth--
			case c == '>' && depth == 0:
				return j, i, last == '/', true
			}
			if c != ' ' && c != '\t' {
				last = c
			}
		}
	}
	return 0, 0, false, false
}

// jsxTagName returns the element name right after the '<' at (line, col).
func jsxTagName(code []string, line, col int) string {
	rest := code[line][col+1:]
	end := 0
	for end < len(rest) && isJSXNameChar(rest[end]) {
		end++
	}
	return rest[:end]
}

func isJSXNameChar(c byte) bool {
	return c == '.' || c == '-' || c == '_' || c == '$' || isASCIILetter(c) || (c >= '0' && c <= '9')
}

// jsxElementEnd returns the position of the '>' that ends the element opened
// at (line, col): the opening tag itself when it is self-closing, otherwise the
// closing tag that balances it — nested elements of the same name included.
func jsxElementEnd(code []string, line, col int) (int, int, bool) {
	name := jsxTagName(code, line, col)
	if name == "" {
		return 0, 0, false
	}
	endLine, endCol, selfClosing, ok := jsxTagEnd(code, line, col)
	if !ok || selfClosing {
		return endLine, endCol, ok
	}
	depth := 1
	j, i := endLine, endCol+1
	for j < len(code) {
		if i >= len(code[j]) {
			j, i = j+1, 0
			continue
		}
		if code[j][i] != '<' {
			i++
			continue
		}
		rest := code[j][i+1:]
		switch {
		case strings.HasPrefix(rest, "/"+name) && jsxNameEnds(rest, len(name)+1):
			depth--
			tagEndLine, tagEndCol, _, found := jsxTagEnd(code, j, i)
			if !found {
				return 0, 0, false
			}
			if depth == 0 {
				return tagEndLine, tagEndCol, true
			}
			j, i = tagEndLine, tagEndCol+1
		case strings.HasPrefix(rest, name) && jsxNameEnds(rest, len(name)):
			tagEndLine, tagEndCol, nestedSelfClosing, found := jsxTagEnd(code, j, i)
			if !found {
				return 0, 0, false
			}
			if !nestedSelfClosing {
				depth++
			}
			j, i = tagEndLine, tagEndCol+1
		default:
			i++
		}
	}
	return 0, 0, false
}

// jsxNameEnds reports whether the element name in rest stops at index n.
func jsxNameEnds(rest string, n int) bool {
	return n >= len(rest) || !isJSXNameChar(rest[n])
}

// balancedBraceExpr returns the text up to the brace that closes an already
// opened '{'. Only single-line expressions are considered; template-literal
// interpolations balance themselves.
func balancedBraceExpr(rest string) (string, bool) {
	depth := 1
	for i := 0; i < len(rest); i++ {
		switch rest[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return rest[:i], true
			}
		}
	}
	return "", false
}

// enclosingJSXTag reconstructs the JSX opening tag that contains the given
// position: back to the nearest '<' (a few lines up at most), forward to the
// first '>' outside of attribute braces.
func enclosingJSXTag(lines []string, lineIdx, col int) (string, bool) {
	startLine, startCol, ok := findTagOpen(lines, lineIdx, col, jsxTagBackLines)
	if !ok {
		return "", false
	}

	var tag strings.Builder
	depth := 0
	for j := startLine; j < len(lines) && j <= startLine+jsxTagForwardLines; j++ {
		segment := lines[j]
		from := 0
		if j == startLine {
			from = startCol
		}
		for i := from; i < len(segment); i++ {
			tag.WriteByte(segment[i])
			switch segment[i] {
			case '{':
				depth++
			case '}':
				if depth > 0 {
					depth--
				}
			case '>':
				if depth == 0 {
					return tag.String(), true
				}
			}
		}
		tag.WriteByte('\n')
	}
	return "", false
}

// findTagOpen locates the '<' that opens the tag containing (lineIdx, col).
func findTagOpen(lines []string, lineIdx, col, backLines int) (int, int, bool) {
	for j := lineIdx; j >= 0 && j >= lineIdx-backLines; j-- {
		segment := lines[j]
		limit := len(segment) - 1
		if j == lineIdx {
			limit = col
		}
		for i := limit; i >= 0; i-- {
			if segment[i] != '<' {
				continue
			}
			// '=>' arrows and comparisons never start with "<letter"; a JSX
			// opening tag does.
			if i+1 < len(segment) && (isASCIILetter(segment[i+1]) || segment[i+1] == '_') {
				return j, i, true
			}
		}
	}
	return 0, 0, false
}

func jsxTagHasChangeHandler(tag string) bool {
	return strings.Contains(tag, "onChange") || strings.Contains(tag, "onInput")
}

func isASCIILetter(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}
