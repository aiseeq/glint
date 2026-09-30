package patterns

import (
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewNullableObjectCallRule())
}

// NullableObjectCallRule detects Object.* calls on nested values that may be
// null/undefined in API responses. These calls throw at runtime when the target
// is not an object.
type NullableObjectCallRule struct {
	*rules.BaseRule
	// objectCall matches the opening of a call whose first argument must be an
	// object: Object.keys/values/entries/hasOwn and hasOwnProperty.call.
	objectCall *regexp.Regexp
	exitsBlock *regexp.Regexp
}

// nullableArgMaxLines bounds how far a call split over lines is followed.
const nullableArgMaxLines = 10

// nullableGuardWindow bounds how many lines above the call a guard is looked for.
const nullableGuardWindow = 40

// NewNullableObjectCallRule creates the rule
func NewNullableObjectCallRule() *NullableObjectCallRule {
	return &NullableObjectCallRule{
		BaseRule: rules.NewBaseRule(
			"nullable-object-call",
			"patterns",
			"Detects Object.* calls on possibly nullable nested values",
			core.SeverityHigh,
		),
		objectCall: regexp.MustCompile(`\bObject\.(?:keys|values|entries|hasOwn|prototype\.hasOwnProperty\.call)\s*\(`),
		exitsBlock: regexp.MustCompile(`\b(?:return|throw)\b`),
	}
}

// AnalyzeFile checks for Object.* calls on possibly nullable values
func (r *NullableObjectCallRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsTypeScriptFile() && !ctx.IsJavaScriptFile() {
		return nil
	}
	if skipFrontendPath(ctx) {
		return nil
	}

	src := newJSSource(ctx.Lines)
	var violations []*core.Violation
	for i, code := range src.code {
		for _, loc := range r.objectCall.FindAllStringIndex(code, -1) {
			arg, ok := jsFirstArgument(src, i, loc[1]-1, nullableArgMaxLines)
			if !ok || !isUnsafeNullableObjectArg(src.text[i][:loc[0]], arg) {
				continue
			}
			if r.guardedAbove(src, i, arg) {
				continue
			}
			violations = append(violations, r.violation(ctx, i+1, ctx.Lines[i], arg))
			break
		}
	}

	return violations
}

func isUnsafeNullableObjectArg(prefix string, arg string) bool {
	if arg == "" || hasObjectFallback(arg) || hasSameLineObjectGuard(prefix, arg) {
		return false
	}
	if strings.HasPrefix(arg, "{") || strings.HasPrefix(arg, "[") || strings.HasPrefix(arg, "new ") {
		return false
	}

	return strings.Contains(arg, ".") || strings.Contains(arg, "[")
}

func hasObjectFallback(arg string) bool {
	return strings.Contains(arg, "?? {}") || strings.Contains(arg, "|| {}") || strings.Contains(arg, "? {}")
}

// hasSameLineObjectGuard reports a guard written before the call on its own
// line: `x.y && Object.keys(x.y)`, `typeof x.y === 'object' && …`.
func hasSameLineObjectGuard(prefix string, arg string) bool {
	return strings.Contains(prefix, arg+" &&") || strings.Contains(prefix, "typeof "+arg+" === 'object'") || strings.Contains(prefix, "typeof "+arg+" === \"object\"")
}

// guardedAbove reports whether a line above the call, in the same block or an
// enclosing one, already rules out a missing value: an early exit
// (`if (!x.y) return []`, `if (x.y == null) { throw … }`) or an enclosing
// `if (x.y) {` / `if (x.y && …) {`. Lines inside blocks that closed before the
// call — a sibling branch, another function — do not count.
func (r *NullableObjectCallRule) guardedAbove(src jsSource, callLine int, arg string) bool {
	a := jsCompact(arg)
	earlyExits := []string{
		"if(!" + a + ")", "if(!" + a + "||", "||!" + a + ")", "||!" + a + "||",
		"if(" + a + "==null)", "if(" + a + "===null)", "if(" + a + "==undefined)", "if(" + a + "===undefined)",
		"if(" + a + "==null||", "if(" + a + "===undefined||",
	}
	enclosing := []string{"if(" + a + ")", "if(" + a + "&&"}

	// rel is the brace depth at the start of line j relative to the call line;
	// minRel is the shallowest depth seen between them.
	rel, minRel := 0, 0
	for j := callLine - 1; j >= 0 && j >= callLine-nullableGuardWindow; j-- {
		rel -= strings.Count(src.code[j], "{") - strings.Count(src.code[j], "}")
		if rel > minRel {
			continue
		}
		opensEnclosing := rel < minRel
		minRel = rel
		compact := jsCompact(src.text[j])
		if opensEnclosing && containsAny(compact, enclosing) {
			return true
		}
		if containsAny(compact, earlyExits) && r.exitsAfter(src, j, callLine) {
			return true
		}
	}
	return false
}

// exitsAfter reports whether the guard at line j leaves the block: return or
// throw on the guard line itself or on the next one.
func (r *NullableObjectCallRule) exitsAfter(src jsSource, j, callLine int) bool {
	if r.exitsBlock.MatchString(src.code[j]) {
		return true
	}
	return j+1 < callLine && r.exitsBlock.MatchString(src.code[j+1])
}

func containsAny(s string, needles []string) bool {
	for _, needle := range needles {
		if strings.Contains(s, needle) {
			return true
		}
	}
	return false
}

func (r *NullableObjectCallRule) violation(ctx *core.FileContext, lineNum int, line string, arg string) *core.Violation {
	v := r.CreateViolation(ctx.RelPath, lineNum, "Object.* call uses a nested value that may be null or undefined")
	v.WithCode(strings.TrimSpace(line))
	v.WithSuggestion("Normalize " + arg + " to a verified object before calling Object.keys/values/entries or hasOwnProperty.")
	v.WithContext("pattern", "nullable-object-call")
	v.WithContext("language", "typescript")
	v.WithContext("argument", arg)
	return v
}
