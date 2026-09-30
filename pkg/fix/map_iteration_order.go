package fix

import (
	"go/ast"

	"github.com/aiseeq/glint/pkg/core"
)

// MapIterationOrderFixer rewrites a map range into a walk over sorted keys, so
// that the value the loop builds comes out the same on every run.
type MapIterationOrderFixer struct{}

// NewMapIterationOrderFixer creates the fixer
func NewMapIterationOrderFixer() *MapIterationOrderFixer {
	return &MapIterationOrderFixer{}
}

// RuleName returns the rule this fixer is for
func (f *MapIterationOrderFixer) RuleName() string {
	return "map-iteration-order"
}

// CanFix reports whether the rule marked the loop as one whose keys can be
// sorted: the rule knows the key type (slices.Sorted needs cmp.Ordered), the
// Go version and whether the body edits the map; the fixer does not.
func (f *MapIterationOrderFixer) CanFix(v *core.Violation) bool {
	if v == nil || v.Rule != "map-iteration-order" || v.Column < 1 {
		return false
	}
	sortable, ok := v.Context["sortable_keys"].(bool)
	return ok && sortable
}

// GenerateFix rewrites `for k, v := range m {` into
// `for _, k := range slices.Sorted(maps.Keys(m)) {` followed by `v := m[k]`.
func (f *MapIterationOrderFixer) GenerateFix(ctx *core.FileContext, v *core.Violation) []*Fix {
	if ctx == nil || ctx.GoAST == nil || !f.CanFix(v) {
		return nil
	}
	if !canReferToPackage(ctx.GoAST, "maps") || !canReferToPackage(ctx.GoAST, "slices") {
		return nil
	}

	var loop *ast.RangeStmt
	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		if loop != nil {
			return false
		}
		rangeStmt, ok := n.(*ast.RangeStmt)
		if ok && violationPosition(ctx, v, rangeStmt) {
			loop = rangeStmt
			return false
		}
		return true
	})
	if loop == nil || loop.Key == nil || loop.Body == nil {
		return nil
	}
	key, ok := loop.Key.(*ast.Ident)
	if !ok || key.Name == "_" {
		return nil // the loop does not use the key, so sorting it changes nothing
	}
	collection, ok := sourceOf(ctx, loop.X)
	if !ok {
		return nil
	}

	rewritten := "_, " + key.Name + " := range slices.Sorted(maps.Keys(" + collection + ")) {"
	if value, ok := loop.Value.(*ast.Ident); ok && value.Name != "_" {
		rewritten += "\n" + value.Name + " := " + collection + "[" + key.Name + "]"
	}

	fix, ok := nodeFix(ctx, loop.Key.Pos(), loop.Body.Lbrace+1, rewritten)
	if !ok {
		return nil
	}
	fix.Message = "Walk the map in sorted key order"
	fix.RuleName = "map-iteration-order"
	fix.Violation = v
	fix.Imports = []string{"maps", "slices"}
	return []*Fix{fix}
}

func init() {
	DefaultRegistry.Register(NewMapIterationOrderFixer())
}
