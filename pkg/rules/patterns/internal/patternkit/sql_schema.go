package patternkit

import (
	"go/ast"
	"go/token"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

// MigrationDirs reads the migrations setting.
func MigrationDirs(rule *rules.BaseRule) []string {
	var dirs []string
	for dir := range strings.SplitSeq(rule.GetStringSetting("migrations", ""), ",") {
		if dir = strings.TrimSpace(dir); dir != "" {
			dirs = append(dirs, dir)
		}
	}
	return dirs
}

// ProjectRelPath returns the path of a file as the file contexts under
// root name it.
func ProjectRelPath(root, path string) string {
	if rel, err := filepath.Rel(root, path); err == nil {
		return filepath.ToSlash(rel)
	}
	return filepath.ToSlash(path) // not relative to root: no file context names it
}

// SqlLiteral is SQL text assembled from string literals, with where each
// piece of it is written.
type SqlLiteral struct {
	Expr   ast.Expr // the literal or the concatenation in the code
	Text   string
	pieces []sqlPiece
	// Bare is the text with the operands that are not literals left out
	// instead of made parameters — a WHERE clause built elsewhere — at the
	// same offsets; empty when every operand is a literal.
	Bare string
}

type sqlPiece struct {
	start int // offset of the piece in text
	end   int
	pos   token.Pos
	raw   bool // a raw string: lines of the text are lines of the source
}

// LineAt returns the source line of an offset in the text.
func (l SqlLiteral) LineAt(ctx *core.FileContext, offset int) int {
	for _, piece := range l.pieces {
		if offset < piece.start || offset >= piece.end {
			continue
		}
		line := ctx.LineForPos(piece.pos)
		if piece.raw {
			line += strings.Count(l.Text[piece.start:offset], "\n")
		}
		return line
	}
	return ctx.LineForPos(l.pieces[0].pos)
}

// sqlStart is how a statement begins.
var sqlStart = regexp.MustCompile(`(?i)^\s*\(?\s*(?:select|insert|update|delete|with|create)\s`)

// fmtVerb is a fmt verb in a format string; it becomes a two-character
// parameter so that offsets stay put.
var fmtVerb = regexp.MustCompile(`%[sdvq]`)

// SqlLiterals returns the string literals and concatenations of literals
// under a node that begin like a SQL statement. An operand that is not a
// literal becomes a parameter; where it stood for a name the text does not
// parse.
func SqlLiterals(root ast.Node) []SqlLiteral {
	return SqlTexts(root, sqlStart.MatchString)
}

// SqlTexts returns the string literals and concatenations of literals under
// a node whose text accept takes.
func SqlTexts(root ast.Node, accept func(string) bool) []SqlLiteral {
	var literals []SqlLiteral
	ast.Inspect(root, func(n ast.Node) bool {
		expr, ok := n.(ast.Expr)
		if !ok {
			return true
		}
		if !IsStringOrConcat(expr) {
			return true
		}
		literal := SqlLiteral{Expr: expr}
		var builder strings.Builder
		var gaps []int
		hasLiteral := false
		for _, operand := range helpers.ConcatOperands(expr) {
			piece, isLit := operand.(*ast.BasicLit)
			text, ok := "", false
			pos := operand.Pos()
			raw := false
			if isLit {
				text, ok = GoStringLiteral(piece)
				raw = piece.Value[0] == '`'
			} else if ident, isIdent := operand.(*ast.Ident); isIdent {
				if declared := declaredStringLiteral(ident); declared != nil {
					text, ok = GoStringLiteral(declared)
				}
			}
			if !ok {
				gaps = append(gaps, builder.Len())
				builder.WriteString(" $9 ")
				continue
			}
			hasLiteral = true
			start := builder.Len()
			builder.WriteString(fmtVerb.ReplaceAllString(text, "$$9"))
			literal.pieces = append(literal.pieces, sqlPiece{start: start, end: builder.Len(), pos: pos, raw: raw})
		}
		literal.Text = builder.String()
		if len(gaps) > 0 {
			bare := []byte(literal.Text)
			for _, gap := range gaps {
				copy(bare[gap:], "    ")
			}
			literal.Bare = string(bare)
		}
		if hasLiteral && accept(literal.Text) {
			literals = append(literals, literal)
		}
		return false
	})
	return literals
}

func declaredStringLiteral(ident *ast.Ident) *ast.BasicLit {
	if ident == nil || ident.Obj == nil {
		return nil
	}
	if _, ok := ident.Obj.Decl.(*ast.ValueSpec); !ok {
		return nil
	}
	literal, ok := DeclaredValue(ident).(*ast.BasicLit)
	if !ok || literal.Kind != token.STRING {
		return nil
	}
	return literal
}

// IsStringOrConcat reports a string literal or a + expression, which may
// join string literals.
func IsStringOrConcat(expr ast.Expr) bool {
	switch x := expr.(type) {
	case *ast.BinaryExpr:
		return x.Op == token.ADD
	case *ast.BasicLit:
		return x.Kind == token.STRING
	}
	return false
}
