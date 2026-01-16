package deadcode

import (
	"go/ast"
	"go/token"
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewDeprecatedCommentRule())
}

// DeprecatedCommentRule detects functions/methods with Deprecated comments that should be removed.
// Functions marked as deprecated often linger in codebases long after they should be removed.
//
// Detects patterns like:
//
//	// Deprecated: use NewFunction instead
//	func OldFunction() {}
//
//	// DEPRECATED - this will be removed
//	func LegacyMethod() {}
type DeprecatedCommentRule struct {
	*rules.BaseRule
	deprecatedPatterns []*regexp.Regexp
}

// NewDeprecatedCommentRule creates the rule
func NewDeprecatedCommentRule() *DeprecatedCommentRule {
	r := &DeprecatedCommentRule{
		BaseRule: rules.NewBaseRule(
			"deprecated-comment",
			"deadcode",
			"Detects functions with Deprecated/Legacy comments that should be reviewed for removal",
			core.SeverityLow,
		),
	}
	r.deprecatedPatterns = r.initDeprecatedPatterns()
	return r
}

// initDeprecatedPatterns initializes patterns for detecting deprecated comments
func (r *DeprecatedCommentRule) initDeprecatedPatterns() []*regexp.Regexp {
	return []*regexp.Regexp{
		// Standard "Deprecated:" godoc format
		regexp.MustCompile(`(?i)^\s*//\s*deprecated\s*:`),
		// "DEPRECATED" standalone
		regexp.MustCompile(`(?i)^\s*//\s*deprecated\b`),
		// "Legacy" prefix
		regexp.MustCompile(`(?i)^\s*//\s*legacy\s*:`),
		regexp.MustCompile(`(?i)^\s*//\s*legacy\s+\w`),
		// "Obsolete" prefix
		regexp.MustCompile(`(?i)^\s*//\s*obsolete\s*:`),
		regexp.MustCompile(`(?i)^\s*//\s*obsolete\b`),
		// "will be removed" pattern
		regexp.MustCompile(`(?i)will\s+be\s+removed`),
		// "scheduled for removal"
		regexp.MustCompile(`(?i)scheduled\s+for\s+removal`),
		// "do not use" pattern
		regexp.MustCompile(`(?i)do\s+not\s+use`),
		// "REMOVED:" prefix (function exists but shouldn't)
		regexp.MustCompile(`(?i)^\s*//\s*removed\s*:`),
	}
}

// AnalyzeFile checks for deprecated comments in Go files
func (r *DeprecatedCommentRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.HasGoAST() || ctx.IsTestFile() {
		return nil
	}

	// Skip test utility files
	pathLower := strings.ToLower(ctx.RelPath)
	if strings.Contains(pathLower, "/test") || strings.Contains(pathLower, "test_") {
		return nil
	}

	var violations []*core.Violation

	// Check each function/method declaration
	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		switch decl := n.(type) {
		case *ast.FuncDecl:
			if v := r.checkFuncDecl(ctx, decl); v != nil {
				violations = append(violations, v)
			}
		case *ast.GenDecl:
			// Check type declarations with deprecated comments
			if v := r.checkGenDecl(ctx, decl); v != nil {
				violations = append(violations, v)
			}
		}
		return true
	})

	return violations
}

// checkFuncDecl checks if a function has deprecated comments
func (r *DeprecatedCommentRule) checkFuncDecl(ctx *core.FileContext, fn *ast.FuncDecl) *core.Violation {
	if fn.Doc == nil {
		return nil
	}

	for _, comment := range fn.Doc.List {
		if r.isDeprecatedComment(comment.Text) {
			pos := ctx.PositionFor(fn.Name)
			funcName := fn.Name.Name
			if fn.Recv != nil && len(fn.Recv.List) > 0 {
				funcName = r.getReceiverType(fn.Recv.List[0]) + "." + funcName
			}

			v := r.CreateViolation(ctx.RelPath, pos.Line,
				"Function '"+funcName+"' is marked as deprecated - consider removal")
			v.WithCode(strings.TrimSpace(comment.Text))
			v.WithSuggestion("Remove deprecated function and update all callers")
			return v
		}
	}

	return nil
}

// checkGenDecl checks if a type/const/var declaration has deprecated comments
func (r *DeprecatedCommentRule) checkGenDecl(ctx *core.FileContext, decl *ast.GenDecl) *core.Violation {
	if decl.Doc == nil {
		return nil
	}

	for _, comment := range decl.Doc.List {
		if r.isDeprecatedComment(comment.Text) {
			// Get the name of the first spec
			if len(decl.Specs) == 0 {
				continue
			}

			var name string
			var pos token.Pos
			switch spec := decl.Specs[0].(type) {
			case *ast.TypeSpec:
				name = spec.Name.Name
				pos = spec.Name.Pos()
			case *ast.ValueSpec:
				if len(spec.Names) > 0 {
					name = spec.Names[0].Name
					pos = spec.Names[0].Pos()
				}
			}

			if name == "" {
				continue
			}

			position := ctx.GoFileSet.Position(pos)
			v := r.CreateViolation(ctx.RelPath, position.Line,
				"Type/const '"+name+"' is marked as deprecated - consider removal")
			v.WithCode(strings.TrimSpace(comment.Text))
			v.WithSuggestion("Remove deprecated declaration and update all usages")
			return v
		}
	}

	return nil
}

// isDeprecatedComment checks if comment matches deprecated patterns
func (r *DeprecatedCommentRule) isDeprecatedComment(text string) bool {
	for _, pattern := range r.deprecatedPatterns {
		if pattern.MatchString(text) {
			return true
		}
	}
	return false
}

// getReceiverType extracts the receiver type name
func (r *DeprecatedCommentRule) getReceiverType(field *ast.Field) string {
	switch t := field.Type.(type) {
	case *ast.StarExpr:
		if ident, ok := t.X.(*ast.Ident); ok {
			return ident.Name
		}
	case *ast.Ident:
		return t.Name
	}
	return ""
}
