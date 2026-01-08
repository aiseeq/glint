package doccheck

import (
	"go/ast"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewDocCompletenessRule())
}

// DocCompletenessRule detects exported symbols without documentation
type DocCompletenessRule struct {
	*rules.BaseRule
}

// NewDocCompletenessRule creates the rule
func NewDocCompletenessRule() *DocCompletenessRule {
	return &DocCompletenessRule{
		BaseRule: rules.NewBaseRule(
			"doc-missing",
			"documentation",
			"Detects exported types, functions, and methods without documentation comments",
			core.SeverityLow,
		),
	}
}

// AnalyzeFile checks for missing documentation
func (r *DocCompletenessRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || ctx.GoAST == nil {
		return nil
	}

	// Skip test files
	if ctx.IsTestFile() {
		return nil
	}

	var violations []*core.Violation

	for _, decl := range ctx.GoAST.Decls {
		switch d := decl.(type) {
		case *ast.GenDecl:
			violations = append(violations, r.checkGenDecl(ctx, d)...)

		case *ast.FuncDecl:
			violations = append(violations, r.checkFuncDecl(ctx, d)...)
		}
	}

	return violations
}

// checkGenDecl checks type and const/var declarations
func (r *DocCompletenessRule) checkGenDecl(ctx *core.FileContext, decl *ast.GenDecl) []*core.Violation {
	var violations []*core.Violation

	for _, spec := range decl.Specs {
		switch s := spec.(type) {
		case *ast.TypeSpec:
			if ast.IsExported(s.Name.Name) && !r.hasDoc(decl.Doc, s.Doc) {
				pos := ctx.PositionFor(s.Name)
				v := r.CreateViolation(ctx.RelPath, pos.Line,
					"Exported type '"+s.Name.Name+"' is missing documentation")
				v.WithCode(ctx.GetLine(pos.Line))
				v.WithSuggestion("Add a comment starting with the type name: // " + s.Name.Name + " ...")
				v.WithContext("symbol", s.Name.Name)
				v.WithContext("kind", "type")
				violations = append(violations, v)
			}

		case *ast.ValueSpec:
			// Only check if it's a single const/var declaration at top level
			// Skip if there's a group doc comment
			if decl.Doc != nil && len(decl.Specs) > 1 {
				continue // Group has doc, individual items don't need it
			}

			for _, name := range s.Names {
				if ast.IsExported(name.Name) && !r.hasDoc(decl.Doc, s.Doc) {
					pos := ctx.PositionFor(name)
					v := r.CreateViolation(ctx.RelPath, pos.Line,
						"Exported constant/variable '"+name.Name+"' is missing documentation")
					v.WithCode(ctx.GetLine(pos.Line))
					v.WithSuggestion("Add a comment: // " + name.Name + " ...")
					v.WithContext("symbol", name.Name)
					v.WithContext("kind", "value")
					violations = append(violations, v)
				}
			}
		}
	}

	return violations
}

// checkFuncDecl checks function declarations
func (r *DocCompletenessRule) checkFuncDecl(ctx *core.FileContext, fn *ast.FuncDecl) []*core.Violation {
	var violations []*core.Violation

	// Skip unexported functions
	if !ast.IsExported(fn.Name.Name) {
		return nil
	}

	// Skip main and init
	if fn.Name.Name == "main" || fn.Name.Name == "init" {
		return nil
	}

	if fn.Doc == nil || len(fn.Doc.List) == 0 {
		pos := ctx.PositionFor(fn.Name)
		kind := "function"
		if fn.Recv != nil {
			kind = "method"
		}

		v := r.CreateViolation(ctx.RelPath, pos.Line,
			"Exported "+kind+" '"+fn.Name.Name+"' is missing documentation")
		v.WithCode(ctx.GetLine(pos.Line))
		v.WithSuggestion("Add a comment starting with the function name: // " + fn.Name.Name + " ...")
		v.WithContext("symbol", fn.Name.Name)
		v.WithContext("kind", kind)
		violations = append(violations, v)
	} else {
		// Check that doc starts with function name (Go convention)
		firstLine := fn.Doc.List[0].Text
		if !strings.HasPrefix(strings.TrimPrefix(firstLine, "// "), fn.Name.Name) &&
			!strings.HasPrefix(strings.TrimPrefix(firstLine, "/* "), fn.Name.Name) {
			pos := ctx.PositionFor(fn.Name)
			v := r.CreateViolation(ctx.RelPath, pos.Line,
				"Documentation for '"+fn.Name.Name+"' should start with the function name")
			v.WithCode(ctx.GetLine(pos.Line))
			v.WithSuggestion("Start comment with: // " + fn.Name.Name + " ...")
			v.WithContext("symbol", fn.Name.Name)
			v.WithContext("kind", "doc-format")
			violations = append(violations, v)
		}
	}

	return violations
}

// hasDoc checks if there's documentation in either group or individual doc
func (r *DocCompletenessRule) hasDoc(groupDoc, itemDoc *ast.CommentGroup) bool {
	if groupDoc != nil && len(groupDoc.List) > 0 {
		return true
	}
	if itemDoc != nil && len(itemDoc.List) > 0 {
		return true
	}
	return false
}
