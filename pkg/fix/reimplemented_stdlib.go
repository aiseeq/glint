package fix

import (
	"go/ast"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
)

// ReimplementedStdlibFixer replaces a hand-written membership test with the
// standard library call it duplicates, and the three statements that collect
// and sort the keys of a map with slices.Sorted(maps.Keys(m)). The rule decides
// with type information whether slices.Contains performs exactly the helper's
// comparison and whether nil reads as an empty key list where the keys are
// used; everything else keeps its body and only the message applies.
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
	_, sorted := sortedKeysMark(v)
	return ok || sorted
}

// sortedKeysMark returns the keys variable and its replacement when the rule
// marked a sorted-keys block for the fixer.
func sortedKeysMark(v *core.Violation) (keys string, ok bool) {
	replacement, _ := v.Context["replacement"].(string)
	keys, hasKeys := v.Context["fix_sorted_keys"].(string)
	return keys, hasKeys && strings.HasPrefix(replacement, "slices.Sorted(maps.Keys(")
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
	if keys, ok := sortedKeysMark(v); ok {
		return sortedKeysFix(ctx, v, keys)
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

// sortedKeysFix replaces the declaration the finding is on and the two
// statements after it - the range collecting the keys and their sort - with
// keys := slices.Sorted(maps.Keys(m)). Statements holding a comment are left
// alone, the rewrite would drop it.
func sortedKeysFix(ctx *core.FileContext, v *core.Violation, keys string) []*Fix {
	if !canReferToPackage(ctx.GoAST, "maps") {
		return nil
	}
	var block []ast.Stmt
	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		var list []ast.Stmt
		switch node := n.(type) {
		case *ast.BlockStmt:
			list = node.List
		case *ast.CaseClause:
			list = node.Body
		case *ast.CommClause:
			list = node.Body
		}
		for i := 0; i+2 < len(list) && block == nil; i++ {
			if violationPosition(ctx, v, list[i]) {
				block = list[i : i+3]
			}
		}
		return block == nil
	})
	if block == nil {
		return nil
	}
	first, last := block[0], block[2]
	for _, group := range ctx.GoAST.Comments {
		if group.Pos() >= first.Pos() && group.End() <= last.End() {
			return nil
		}
	}
	replacement, _ := v.Context["replacement"].(string)
	fix, ok := nodeFix(ctx, first.Pos(), last.End(), keys+" := "+replacement)
	if !ok {
		return nil
	}
	fix.Message = "Use slices.Sorted(maps.Keys(...))"
	fix.RuleName = "reimplemented-stdlib"
	fix.Violation = v
	fix.Imports = []string{"maps", "slices"}
	fix.DropImports = []string{"sort"}
	return []*Fix{fix}
}

func init() {
	DefaultRegistry.Register(NewReimplementedStdlibFixer())
}
