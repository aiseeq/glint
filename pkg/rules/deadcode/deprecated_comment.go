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

	comment := r.deprecationMarker(fn.Doc)
	if comment == nil {
		return nil
	}

	pos := ctx.PositionFor(fn.Name)
	funcName := fn.Name.Name
	if fn.Recv != nil && len(fn.Recv.List) > 0 {
		funcName = receiverTypeName(fn.Recv.List[0]) + "." + funcName
	}

	v := r.CreateViolation(ctx.RelPath, pos.Line,
		"Function '"+funcName+"' is marked as deprecated - consider removal")
	v.WithCode(strings.TrimSpace(comment.Text))
	v.WithSuggestion("Remove deprecated function and update all callers")
	return v
}

// checkGenDecl checks if a type/const/var declaration has deprecated comments
func (r *DeprecatedCommentRule) checkGenDecl(ctx *core.FileContext, decl *ast.GenDecl) *core.Violation {
	if decl.Doc == nil {
		return nil
	}

	comment := r.deprecationMarker(decl.Doc)
	if comment == nil || len(decl.Specs) == 0 {
		return nil
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
		return nil
	}

	v := r.CreateViolation(ctx.RelPath, ctx.LineForPos(pos),
		"Type/const '"+name+"' is marked as deprecated - consider removal")
	v.WithCode(strings.TrimSpace(comment.Text))
	v.WithSuggestion("Remove deprecated declaration and update all usages")
	return v
}

// deprecationMarker returns the doc line that marks this declaration as
// deprecated, or nil. Two godoc conventions separate a marker from a mere
// mention:
//
//   - an indented line is example code, not a statement about this
//     declaration (a rule documenting the pattern it detects showed up as
//     deprecated itself);
//   - a loose phrase such as "legacy X" or "will be removed" only counts when
//     it opens its own paragraph; continuing a sentence from the line above
//     makes it prose. The canonical "Deprecated:" marker counts anywhere,
//     since it is routinely written right after the summary line.
func (r *DeprecatedCommentRule) deprecationMarker(doc *ast.CommentGroup) *ast.Comment {
	if doc == nil {
		return nil
	}
	for i, comment := range doc.List {
		if isGodocExample(comment.Text) {
			continue
		}
		if !r.isDeprecatedComment(comment.Text) {
			continue
		}
		if isCanonicalDeprecationMarker(comment.Text) {
			return comment
		}
		if i > 0 && !isBlankDocLine(doc.List[i-1].Text) {
			continue
		}
		return comment
	}
	return nil
}

// canonicalDeprecation matches the godoc "Deprecated:" marker.
var canonicalDeprecation = regexp.MustCompile(`(?i)^\s*//\s*deprecated\s*:`)

func isCanonicalDeprecationMarker(text string) bool {
	return canonicalDeprecation.MatchString(text)
}

// isGodocExample reports whether a doc line belongs to an indented code block.
func isGodocExample(text string) bool {
	body := strings.TrimPrefix(text, "//")
	if body == text {
		return false
	}
	return strings.HasPrefix(body, "\t") || strings.HasPrefix(body, "    ")
}

// isBlankDocLine reports whether a doc line is the empty "//" that separates
// godoc paragraphs.
func isBlankDocLine(text string) bool {
	return strings.TrimSpace(strings.TrimPrefix(text, "//")) == ""
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
