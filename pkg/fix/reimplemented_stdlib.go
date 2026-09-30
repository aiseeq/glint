package fix

import (
	"go/ast"

	"github.com/aiseeq/glint/pkg/core"
)

// ReimplementedStdlibFixer replaces a hand-written membership test with the
// standard library call it duplicates. The rule decides with type information
// whether slices.Contains performs exactly the helper's comparison and names
// the collection and target it passes; everything else keeps its body and only
// the message applies.
type ReimplementedStdlibFixer struct{}

// NewReimplementedStdlibFixer creates the fixer
func NewReimplementedStdlibFixer() *ReimplementedStdlibFixer {
	return &ReimplementedStdlibFixer{}
}

// RuleName returns the rule this fixer is for
func (f *ReimplementedStdlibFixer) RuleName() string {
	return "reimplemented-stdlib"
}

// CanFix reports whether the rule marked the helper as an exact
// slices.Contains.
func (f *ReimplementedStdlibFixer) CanFix(v *core.Violation) bool {
	if v == nil || v.Rule != "reimplemented-stdlib" || v.Column < 1 {
		return false
	}
	_, _, ok := containsOperands(v)
	return ok
}

func containsOperands(v *core.Violation) (collection, target string, ok bool) {
	replacement, _ := v.Context["replacement"].(string)
	collection, hasCollection := v.Context["fix_collection"].(string)
	target, hasTarget := v.Context["fix_target"].(string)
	return collection, target, replacement == "slices.Contains" && hasCollection && hasTarget
}

// GenerateFix replaces the body of the helper with a single slices.Contains
// call. The signature stays as written; a body holding a comment is left
// alone, the rewrite would drop it.
func (f *ReimplementedStdlibFixer) GenerateFix(ctx *core.FileContext, v *core.Violation) []*Fix {
	if ctx == nil || ctx.GoAST == nil || !f.CanFix(v) || !canReferToPackage(ctx.GoAST, "slices") {
		return nil
	}
	collection, target, _ := containsOperands(v)

	var helper *ast.FuncDecl
	for _, decl := range ctx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && fn.Body != nil && violationPosition(ctx, v, fn) {
			helper = fn
			break
		}
	}
	if helper == nil || len(helper.Body.List) != 2 {
		return nil
	}
	first, last := helper.Body.List[0], helper.Body.List[len(helper.Body.List)-1]
	for _, group := range ctx.GoAST.Comments {
		if group.Pos() >= first.Pos() && group.End() <= last.End() {
			return nil
		}
	}

	fix, ok := nodeFix(ctx, first.Pos(), last.End(), "return slices.Contains("+collection+", "+target+")")
	if !ok {
		return nil
	}
	fix.Message = "Use slices.Contains"
	fix.RuleName = "reimplemented-stdlib"
	fix.Violation = v
	fix.Imports = []string{"slices"}
	return []*Fix{fix}
}

func init() {
	DefaultRegistry.Register(NewReimplementedStdlibFixer())
}
