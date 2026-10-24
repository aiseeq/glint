package deadcode

import (
	"go/ast"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewEmptyGoFileRule())
}

// EmptyGoFileRule detects a Go file that declares nothing:
//
//	package defense
//
//	// Foes hitting ours at the bases: a foe with damage that has one of ours
//	// in reach, counted only next to our own halls.
//
// The last declaration of the file was deleted or moved, and the file stayed
// with the package clause and the comments about the code it held. The
// compiler accepts it, and a reader opens a file named after code that is not
// there. A package doc (doc.go), a file under a build constraint that keeps
// the package buildable elsewhere, and a file of blank imports kept for their
// side effects declare nothing on purpose.
type EmptyGoFileRule struct {
	*rules.BaseRule
}

// NewEmptyGoFileRule creates the rule
func NewEmptyGoFileRule() *EmptyGoFileRule {
	return &EmptyGoFileRule{
		BaseRule: rules.NewBaseRule(
			"empty-go-file",
			"deadcode",
			"Detects a Go file with no declarations, only the package clause and comments — the code it held is gone and the file stayed",
			core.SeverityLow,
		),
	}
}

// AnalyzeFile reports a file without declarations.
func (r *EmptyGoFileRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.HasGoAST() || ctx.IsGenerated() {
		return nil
	}
	file := ctx.GoAST
	if len(file.Decls) > 0 || file.Doc != nil || hasBuildConstraint(file) {
		return nil
	}
	line := ctx.LineForPos(file.Package)
	if ctx.IsSuppressed(line, r.Name()) {
		return nil
	}
	v := r.CreateViolation(ctx.RelPath, line,
		"File "+ctx.BaseName()+" declares nothing — only the package clause and comments are left of the code it held")
	v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
	v.WithSuggestion("Delete the file, and move any comment still worth keeping next to the code it describes")
	return []*core.Violation{v}
}

// hasBuildConstraint reports a //go:build or // +build line above the package
// clause.
func hasBuildConstraint(file *ast.File) bool {
	for _, group := range file.Comments {
		if group.Pos() >= file.Package {
			break
		}
		for _, c := range group.List {
			if strings.HasPrefix(c.Text, "//go:build") || strings.HasPrefix(c.Text, "// +build") {
				return true
			}
		}
	}
	return false
}
