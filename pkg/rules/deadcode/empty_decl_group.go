package deadcode

import (
	"go/ast"
	"go/token"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewEmptyDeclGroupRule())
	rules.Register(NewDeclGroupTrailingCommentRule())
}

// EmptyDeclGroupRule detects a parenthesized import, const, var or type group
// that declares nothing:
//
//	const ()
//
//	const (
//	// TypeWorker — id of the worker.
//	)
//
// The last declaration of the group was deleted or moved, and the group
// stayed, bare or with the comments of the names it held. gofmt and vet
// accept it, and a reader looks for the code those comments describe.
type EmptyDeclGroupRule struct {
	*rules.BaseRule
}

// NewEmptyDeclGroupRule creates the rule
func NewEmptyDeclGroupRule() *EmptyDeclGroupRule {
	return &EmptyDeclGroupRule{
		BaseRule: rules.NewBaseRule(
			"empty-decl-group",
			"deadcode",
			"Detects an import, const, var or type group with no declarations, bare or with comments only — the code it held is gone and the group stayed",
			core.SeverityLow,
		),
	}
}

// AnalyzeFile reports each group without declarations.
func (r *EmptyDeclGroupRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.HasGoAST() || ctx.IsGenerated() {
		return nil
	}
	var violations []*core.Violation
	for _, gd := range declGroups(ctx.GoAST) {
		if len(gd.Specs) > 0 {
			continue
		}
		line := ctx.LineForPos(gd.Pos())
		if ctx.IsSuppressed(line, r.Name()) {
			continue
		}
		msg := "Group " + gd.Tok.String() + " ( ) declares nothing"
		if hasCommentWithin(ctx.GoAST, gd.Lparen, gd.Rparen) {
			msg += " — only comments of the names it held are left"
		}
		v := r.CreateViolation(ctx.RelPath, line, msg)
		v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
		v.WithSuggestion("Delete the group, and move any comment still worth keeping next to the code it describes")
		violations = append(violations, v)
	}
	return violations
}

// DeclGroupTrailingCommentRule detects a comment after the last entry of a
// parenthesized import, const, var or type group, on lines of its own:
//
//	import (
//		"example.com/game/data"
//		// Ids of the game API. The source is the enums of the protocol.
//	)
//
// A comment there documents no entry: the entry it described below was
// deleted, or the declaration it documented went away and the comment slid
// into the group above.
type DeclGroupTrailingCommentRule struct {
	*rules.BaseRule
}

// NewDeclGroupTrailingCommentRule creates the rule
func NewDeclGroupTrailingCommentRule() *DeclGroupTrailingCommentRule {
	return &DeclGroupTrailingCommentRule{
		BaseRule: rules.NewBaseRule(
			"decl-group-trailing-comment",
			"deadcode",
			"Detects a comment below the last entry of an import, const, var or type group — it documents no entry: what it described was deleted or moved",
			core.SeverityLow,
		),
	}
}

// AnalyzeFile reports the first trailing comment of each group with entries.
func (r *DeclGroupTrailingCommentRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.HasGoAST() || ctx.IsGenerated() {
		return nil
	}
	var violations []*core.Violation
	for _, gd := range declGroups(ctx.GoAST) {
		if len(gd.Specs) == 0 {
			continue // empty-decl-group
		}
		last := gd.Specs[len(gd.Specs)-1]
		lastLine := ctx.LineForPos(last.End())
		// continued is the last line of the last entry's line comment and of
		// the lines that go on with it right below.
		continued := 0
		if c := specLineComment(last); c != nil {
			continued = ctx.LineForPos(c.End())
		}
		for _, group := range ctx.GoAST.Comments {
			if group.Pos() <= gd.Lparen || group.End() > gd.Rparen || ctx.LineForPos(group.Pos()) <= lastLine {
				continue
			}
			line := ctx.LineForPos(group.Pos())
			if continued > 0 && line == continued+1 {
				continued = ctx.LineForPos(group.End())
				continue
			}
			if ctx.IsSuppressed(line, r.Name()) {
				break
			}
			v := r.CreateViolation(ctx.RelPath, line,
				"Comment below the last entry of the "+gd.Tok.String()+" group documents no entry — what it described was deleted or moved")
			v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
			v.WithSuggestion("Move the comment to the code it describes, or delete it")
			violations = append(violations, v)
			break
		}
	}
	return violations
}

// declGroups returns the parenthesized declarations of the file.
func declGroups(file *ast.File) []*ast.GenDecl {
	var groups []*ast.GenDecl
	for _, decl := range file.Decls {
		if gd, ok := decl.(*ast.GenDecl); ok && gd.Lparen.IsValid() {
			groups = append(groups, gd)
		}
	}
	return groups
}

// specLineComment returns the comment on the line of the entry, after it.
func specLineComment(spec ast.Spec) *ast.CommentGroup {
	switch s := spec.(type) {
	case *ast.ImportSpec:
		return s.Comment
	case *ast.ValueSpec:
		return s.Comment
	case *ast.TypeSpec:
		return s.Comment
	}
	return nil
}

// hasCommentWithin reports a comment between the positions lo and hi.
func hasCommentWithin(file *ast.File, lo, hi token.Pos) bool {
	for _, group := range file.Comments {
		if group.Pos() > lo && group.End() <= hi {
			return true
		}
	}
	return false
}
