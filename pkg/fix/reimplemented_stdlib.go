package fix

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
)

// linearSearchSignature matches the declaration of a helper that answers
// "is this element in that collection".
var linearSearchSignature = regexp.MustCompile(`^(\s*)func\s+(\w+)\(\s*(\w+)\s+\[\][\w.\*\[\]]+\s*,\s*(\w+)\s+[\w.\*\[\]]+\s*\)\s+bool\s*\{\s*$`)

// searchLoopBody matches the four lines the loop is always written in.
var searchLoopBody = regexp.MustCompile(
	`^\s*for\s+_\s*,\s*(\w+)\s*:=\s*range\s+(\w+)\s*\{\s*$`)

// ReimplementedStdlibFixer replaces a hand-written membership test with the
// standard library call it duplicates. Only the plain search over a parameter
// is rewritten: a helper wrapping its own list keeps its name and meaning, and
// only its body could change — which the message says instead.
type ReimplementedStdlibFixer struct{}

// NewReimplementedStdlibFixer creates the fixer
func NewReimplementedStdlibFixer() *ReimplementedStdlibFixer {
	return &ReimplementedStdlibFixer{}
}

// RuleName returns the rule this fixer is for
func (f *ReimplementedStdlibFixer) RuleName() string {
	return "reimplemented-stdlib"
}

// CanFix reports whether the violation is one this fixer handles.
func (f *ReimplementedStdlibFixer) CanFix(v *core.Violation) bool {
	if v == nil || v.Rule != "reimplemented-stdlib" {
		return false
	}
	replacement, ok := v.Context["replacement"].(string)
	return ok && replacement == "slices.Contains"
}

// GenerateFix rewrites the whole helper into a single slices.Contains call.
func (f *ReimplementedStdlibFixer) GenerateFix(ctx *core.FileContext, v *core.Violation) []*Fix {
	if ctx == nil || !f.CanFix(v) || v.Line < 1 || v.Line > len(ctx.Lines) {
		return nil
	}

	signature := linearSearchSignature.FindStringSubmatch(ctx.Lines[v.Line-1])
	if signature == nil {
		return nil
	}
	indent, name, collection, target := signature[1], signature[2], signature[3], signature[4]

	end, ok := f.matchesSearchBody(ctx, v.Line, collection)
	if !ok {
		return nil
	}

	rewritten := fmt.Sprintf("%sfunc %s(%s []%s, %s %s) bool {\n%s\treturn slices.Contains(%s, %s)\n%s}",
		indent, name, collection, elementType(ctx.Lines[v.Line-1]), target, targetType(ctx.Lines[v.Line-1]),
		indent, collection, target, indent)

	fixes := []*Fix{{
		File:      ctx.Path,
		StartLine: v.Line,
		EndLine:   end,
		OldText:   strings.Join(ctx.Lines[v.Line-1:end], "\n"),
		NewText:   rewritten,
		Message:   "Use slices.Contains",
		RuleName:  "reimplemented-stdlib",
		Violation: v,
	}}
	if importFix := ensureImports(ctx, "slices"); importFix != nil {
		importFix.RuleName = "reimplemented-stdlib"
		importFix.Violation = v
		fixes = append(fixes, importFix)
	}
	return fixes
}

// matchesSearchBody checks that the helper is exactly the loop this fixer knows
// how to replace, and returns the line its closing brace is on.
func (f *ReimplementedStdlibFixer) matchesSearchBody(ctx *core.FileContext, declaration int, collection string) (int, bool) {
	// for _, x := range collection {  /  if x == target {  /  return true  /  }
	// /  }  /  return false  /  }   — seven lines after the declaration.
	const bodyLines = 7
	if declaration+bodyLines-1 > len(ctx.Lines) {
		return 0, false
	}

	loop := searchLoopBody.FindStringSubmatch(ctx.Lines[declaration])
	if loop == nil || loop[2] != collection {
		return 0, false
	}

	expected := []string{"return true", "}", "}", "return false", "}"}
	for i, want := range expected {
		if strings.TrimSpace(ctx.Lines[declaration+2+i]) != want {
			return 0, false
		}
	}
	if !strings.HasPrefix(strings.TrimSpace(ctx.Lines[declaration+1]), "if "+loop[1]+" ==") {
		return 0, false
	}
	return declaration + bodyLines, true
}

// elementType and targetType read the types back out of the signature, so the
// rewritten helper keeps them exactly as they were written.
func elementType(signature string) string {
	_, rest, found := strings.Cut(signature, "[]")
	if !found {
		return "any"
	}
	elem, _, _ := strings.Cut(rest, ",")
	return strings.TrimSpace(elem)
}

func targetType(signature string) string {
	_, rest, found := strings.Cut(signature, ",")
	if !found {
		return "any"
	}
	rest = strings.TrimSpace(rest)
	_, typeAndTail, found := strings.Cut(rest, " ")
	if !found {
		return "any"
	}
	typeName, _, _ := strings.Cut(typeAndTail, ")")
	return strings.TrimSpace(typeName)
}

func init() {
	DefaultRegistry.Register(NewReimplementedStdlibFixer())
}
