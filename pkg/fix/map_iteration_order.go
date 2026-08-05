package fix

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
)

// mapRangePattern matches the range statement the rule reports: both the
// key-only and the key-value form.
var mapRangePattern = regexp.MustCompile(`^(\s*)for\s+(\w+)(?:\s*,\s*(\w+))?\s*:=\s*range\s+([\w.\[\]]+)\s*\{\s*$`)

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

// CanFix reports whether the violation is one this fixer handles.
func (f *MapIterationOrderFixer) CanFix(v *core.Violation) bool {
	return v != nil && v.Rule == "map-iteration-order"
}

// GenerateFix rewrites `for k, v := range m {` into a sorted walk and adds the
// imports that walk needs.
func (f *MapIterationOrderFixer) GenerateFix(ctx *core.FileContext, v *core.Violation) []*Fix {
	if ctx == nil || v == nil || v.Line < 1 || v.Line > len(ctx.Lines) {
		return nil
	}

	line := ctx.Lines[v.Line-1]
	match := mapRangePattern.FindStringSubmatch(line)
	if match == nil {
		return nil
	}
	indent, key, value, collection := match[1], match[2], match[3], match[4]
	if key == "_" {
		return nil // the loop does not use the key, so sorting it changes nothing
	}

	rewritten := fmt.Sprintf("%sfor _, %s := range slices.Sorted(maps.Keys(%s)) {", indent, key, collection)
	if value != "" && value != "_" {
		rewritten += fmt.Sprintf("\n%s\t%s := %s[%s]", indent, value, collection, key)
	}

	fixes := []*Fix{{
		File:      ctx.Path,
		StartLine: v.Line,
		EndLine:   v.Line,
		OldText:   strings.TrimRight(line, " \t"),
		NewText:   rewritten,
		Message:   "Walk the map in sorted key order",
		RuleName:  "map-iteration-order",
		Violation: v,
	}}
	importFix, ok := ensureImports(ctx, "maps", "slices")
	if !ok {
		return nil // rewriting the body without its imports breaks the build
	}
	if importFix != nil {
		importFix.RuleName = "map-iteration-order"
		importFix.Violation = v
		fixes = append(fixes, importFix)
	}
	return fixes
}

func init() {
	DefaultRegistry.Register(NewMapIterationOrderFixer())
}
