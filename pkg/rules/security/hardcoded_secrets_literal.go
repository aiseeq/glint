package security

import (
	"go/ast"
	"go/token"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
)

// stringContentAt reports whether a one-based line and byte column fall
// between the quotes of a string literal. It is nil for files whose string
// syntax the rule does not model; nothing is exempt there.
type stringContentAt func(line, column int) bool

// stringContents builds the literal map of a file: exact from the syntax tree
// of a Go file, from a per-line scan of TypeScript and JavaScript.
func stringContents(ctx *core.FileContext) stringContentAt {
	switch {
	case ctx.IsGoFile() && ctx.GoAST != nil && ctx.GoFileSet != nil:
		return goStringContents(ctx)
	case ctx.IsTypeScriptFile(), ctx.IsJavaScriptFile():
		return scriptStringContents(ctx.Lines)
	}
	return nil
}

type literalSpan struct{ start, end token.Position }

func goStringContents(ctx *core.FileContext) stringContentAt {
	var spans []literalSpan
	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if ok && lit.Kind == token.STRING {
			spans = append(spans, literalSpan{
				start: ctx.GoFileSet.Position(lit.Pos()),
				end:   ctx.GoFileSet.Position(lit.End()),
			})
		}
		return true
	})
	return func(line, column int) bool {
		for _, span := range spans {
			// Content lies after the opening quote and before the closing
			// one, which sits right before span.end.
			afterOpen := line > span.start.Line || (line == span.start.Line && column > span.start.Column)
			beforeClose := line < span.end.Line || (line == span.end.Line && column < span.end.Column-1)
			if afterOpen && beforeClose {
				return true
			}
		}
		return false
	}
}

// scriptStringContents scans each line for '...', "..." and `...` literals,
// honoring backslash escapes. A template literal spanning lines is not
// followed: its continuation lines read as code.
func scriptStringContents(lines []string) stringContentAt {
	inside := make([][]bool, len(lines))
	for i, line := range lines {
		marks := make([]bool, len(line))
		var quote byte
		for j := 0; j < len(line); j++ {
			c := line[j]
			switch {
			case quote == 0:
				if c == '"' || c == '\'' || c == '`' {
					quote = c
				}
			case c == '\\':
				marks[j] = true
				if j+1 < len(line) {
					j++
					marks[j] = true
				}
			case c == quote:
				quote = 0
			default:
				marks[j] = true
			}
		}
		inside[i] = marks
	}
	return func(line, column int) bool {
		if line < 1 || line > len(inside) || column < 1 || column > len(inside[line-1]) {
			return false
		}
		return inside[line-1][column-1]
	}
}

// quotedValueIsCode reports whether the quoted value of a key=value match is
// not a string at all: the quote after the separator closes the literal
// holding the key, and what follows it is code - `"PASSWORD=" + cfg.Password`
// up to the next literal's opening quote.
func quotedValueIsCode(match string, matchStart, lineNum int, contentAt stringContentAt) bool {
	if contentAt == nil {
		return false
	}
	separator := strings.IndexAny(match, ":=")
	if separator < 0 {
		return false
	}
	rest := strings.TrimLeft(match[separator+1:], "=")
	rest = strings.TrimLeft(rest, " \t")
	if rest == "" || !strings.ContainsRune("\"'`", rune(rest[0])) {
		return false
	}
	quote := matchStart + len(match) - len(rest)
	// Columns are one-based: the character after the quote is at quote+2.
	return !contentAt(lineNum, quote+2)
}
