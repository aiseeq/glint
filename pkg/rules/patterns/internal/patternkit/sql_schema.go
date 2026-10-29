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

type sqlStringPiece struct {
	text string
	pos  token.Pos
	raw  bool
}

// PiecePosAt returns the source position of the string literal containing offset.
func (l SqlLiteral) PiecePosAt(offset int) token.Pos {
	for _, piece := range l.pieces {
		if offset >= piece.start && offset < piece.end {
			return piece.pos
		}
	}
	if len(l.pieces) == 0 {
		return token.NoPos
	}
	return l.pieces[0].pos
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

// SqlLiterals returns SQL strings and concatenations under a node that begin
// like a SQL statement. String constants are expanded; other operands become
// parameters so names do not break SQL parsing.
func SqlLiterals(root ast.Node) []SqlLiteral {
	return SqlTexts(root, sqlStart.MatchString)
}

func sqlStringConsts(root ast.Node) map[string]ast.Expr {
	consts := make(map[string]ast.Expr)
	addDecl := func(decl *ast.GenDecl) {
		if decl.Tok != token.CONST {
			return
		}
		for _, spec := range decl.Specs {
			values, ok := spec.(*ast.ValueSpec)
			if !ok || len(values.Values) != len(values.Names) {
				continue
			}
			for i, name := range values.Names {
				consts[name.Name] = values.Values[i]
			}
		}
	}
	if file, ok := root.(*ast.File); ok {
		for _, decl := range file.Decls {
			if gen, ok := decl.(*ast.GenDecl); ok {
				addDecl(gen)
			}
		}
		return consts
	}
	ast.Inspect(root, func(n ast.Node) bool {
		if decl, ok := n.(*ast.GenDecl); ok {
			addDecl(decl)
			return false
		}
		return true
	})
	return consts
}

func constSQLStringPieces(expr ast.Expr, consts map[string]ast.Expr, depth int) ([]sqlStringPiece, bool) {
	if depth > 20 {
		return nil, false
	}
	switch value := ast.Unparen(expr).(type) {
	case *ast.BasicLit:
		text, ok := GoStringLiteral(value)
		if !ok {
			return nil, false
		}
		return []sqlStringPiece{{text: text, pos: value.Pos(), raw: value.Value[0] == '`'}}, true
	case *ast.BinaryExpr:
		if value.Op != token.ADD {
			return nil, false
		}
		left, ok := constSQLStringPieces(value.X, consts, depth+1)
		if !ok {
			return nil, false
		}
		right, ok := constSQLStringPieces(value.Y, consts, depth+1)
		if !ok {
			return nil, false
		}
		return append(left, right...), true
	case *ast.Ident:
		if value, ok := consts[value.Name]; ok {
			return constSQLStringPieces(value, consts, depth+1)
		}
	}
	return nil, false
}

// SqlTexts returns the string literals and concatenations of literals under
// a node whose text accept takes.
func SqlTexts(root ast.Node, accept func(string) bool) []SqlLiteral {
	var literals []SqlLiteral
	consts := sqlStringConsts(root)
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
			pieces, isConst := constSQLStringPieces(operand, consts, 0)
			if !isConst {
				gaps = append(gaps, builder.Len())
				builder.WriteString(" $9 ")
				continue
			}
			for _, piece := range pieces {
				hasLiteral = true
				start := builder.Len()
				builder.WriteString(fmtVerb.ReplaceAllString(piece.text, "$$9"))
				literal.pieces = append(literal.pieces, sqlPiece{start: start, end: builder.Len(), pos: piece.pos, raw: piece.raw})
			}
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
