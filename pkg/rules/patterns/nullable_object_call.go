package patterns

import (
	"maps"
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewNullableObjectCallRule())
}

// NullableObjectCallRule detects Object.* calls on nested values that may be
// null/undefined in API responses. These calls throw at runtime when the target
// is not an object. A property the file itself fills with an object only
// (objectFilledProperties) is not reported, nor a field of the file's own
// constant table (fileTableRoots).
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

	src := newJSSource(ctx)
	filled := objectFilledProperties(src.code)
	table := fileTable{roots: fileTableRoots(src.code), loose: looseProperties(src.code)}
	var violations []*core.Violation
	for i, code := range src.code {
		for _, loc := range r.objectCall.FindAllStringIndex(code, -1) {
			arg, ok := jsFirstArgument(src, i, loc[1]-1, nullableArgMaxLines)
			if !ok || !isUnsafeNullableObjectArg(src.text[i][:loc[0]], arg) || filled[jsCompact(arg)] || table.holds(arg) {
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

var (
	// propertyAssignment is `a.b = value`, anywhere on the line; the value
	// runs to the end of the statement.
	propertyAssignment = regexp.MustCompile(`(?:^|[^\w$.])([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+)\s*=\s*([^=;}][^;}]*)`)
	// objectDeclaration is a local declared as an object: const m = {…}.
	objectDeclaration = regexp.MustCompile(`\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:\{|\[|new\s)`)
)

// objectFilledProperties returns the properties the file itself fills with an
// object and with nothing else: a literal object or array, a new, or a local
// declared as one (req.m = modules after const modules = {…}). Such a
// property is the code's own table, no response field; one also filled from
// a call, an await or null may be missing.
func objectFilledProperties(code []string) map[string]bool {
	objects := map[string]bool{}
	for _, line := range code {
		for _, m := range objectDeclaration.FindAllStringSubmatch(line, -1) {
			objects[m[1]] = true
		}
	}
	filled := map[string]bool{}
	other := map[string]bool{}
	for _, line := range code {
		for _, m := range propertyAssignment.FindAllStringSubmatch(line, -1) {
			value := strings.TrimSpace(m[2])
			if strings.HasPrefix(value, "{") || strings.HasPrefix(value, "[") || strings.HasPrefix(value, "new ") || objects[value] {
				filled[m[1]] = true
			} else {
				other[m[1]] = true
			}
		}
	}
	for path := range other {
		delete(filled, path)
	}
	return filled
}

var (
	// tableConst is a constant declared, with or without its type, as a
	// literal object or array the file writes itself — not spread from
	// another value.
	tableConst = regexp.MustCompile(`\bconst\s+([A-Za-z_$][\w$]*)\s*(?::[^=]*)?=\s*[\[{](?:\s*\.\.\.)?`)
	// tableRow is the variable of a loop over a named array: for (const row of rows).
	tableRow = regexp.MustCompile(`\bfor\s*\(\s*const\s+([A-Za-z_$][\w$]*)\s+of\s+([A-Za-z_$][\w$]*)\s*\)`)
	// looseField is a field its type lets be missing: name?: T, or a type
	// naming null or undefined.
	looseField = regexp.MustCompile(`\b([A-Za-z_$][\w$]*)\s*(?:\?\s*:|:[^;,{}=]*\b(?:null|undefined)\b)`)
	// fieldPath is a chain of plain property reads from one name.
	fieldPath = regexp.MustCompile(`^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+$`)
)

// fileTable is the file's own constant table: the constants it writes as
// literals and the rows of loops over them, and the fields a type of the
// file lets be missing or the file assigns something other than an object.
type fileTable struct {
	roots map[string]bool
	loose map[string]bool
}

// holds reports a field path read from the table whose every field is there:
// set.re of for (const set of sets) over const sets = [{ re: {…} }, …].
func (t fileTable) holds(arg string) bool {
	path := jsCompact(arg)
	if !fieldPath.MatchString(path) || t.loose[path] {
		return false
	}
	names := strings.Split(path, ".")
	if !t.roots[names[0]] {
		return false
	}
	for _, field := range names[1:] {
		if t.loose[field] {
			return false
		}
	}
	return true
}

// fileTableRoots returns the constants the file declares as literals, not
// spread from another value, and the variables of for-of loops over them.
func fileTableRoots(code []string) map[string]bool {
	consts := map[string]bool{}
	for _, line := range code {
		for _, m := range tableConst.FindAllStringSubmatch(line, -1) {
			if !strings.HasSuffix(m[0], "...") {
				consts[m[1]] = true
			}
		}
	}
	roots := maps.Clone(consts)
	for _, line := range code {
		for _, m := range tableRow.FindAllStringSubmatch(line, -1) {
			if consts[m[2]] {
				roots[m[1]] = true
			}
		}
	}
	return roots
}

// looseProperties returns the fields a type of the file declares optional or
// nullable, and the property paths the file assigns a value that is not a
// literal object or array.
func looseProperties(code []string) map[string]bool {
	loose := map[string]bool{}
	for _, line := range code {
		for _, m := range looseField.FindAllStringSubmatch(line, -1) {
			loose[m[1]] = true
		}
		for _, m := range propertyAssignment.FindAllStringSubmatch(line, -1) {
			if value := strings.TrimSpace(m[2]); !strings.HasPrefix(value, "{") && !strings.HasPrefix(value, "[") {
				loose[m[1]] = true
			}
		}
	}
	return loose
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
// line: `x.y && Object.keys(x.y)`, `x.y != null && …`, `typeof x.y ===
// 'object' && …`, and a check of the missing value the call sits right of:
// `x.y == null || Object.hasOwn(x.y, k)`, `!x.y || …` - the right side of
// || runs only when the left one is false. A strict check rules out a
// missing value only when it tests both null and undefined.
func hasSameLineObjectGuard(prefix string, arg string) bool {
	p, a := jsCompact(prefix), jsCompact(arg)
	present := []string{a + "&&", a + "!=null&&", a + "!=undefined&&", "typeof" + a + "==='object'", "typeof" + a + `==="object"`}
	missing := []string{a + "==null||", a + "==undefined||", "!" + a + "||"}
	if helpers.ContainsAny(p, present) || helpers.ContainsAny(p, missing) {
		return true
	}
	return strings.Contains(p, a+"!==null&&") && strings.Contains(p, a+"!==undefined&&") ||
		strings.Contains(p, a+"===null||") && strings.Contains(p, a+"===undefined||")
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
		if opensEnclosing && helpers.ContainsAny(compact, enclosing) {
			return true
		}
		if helpers.ContainsAny(compact, earlyExits) && r.exitsAfter(src, j, callLine) {
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

func (r *NullableObjectCallRule) violation(ctx *core.FileContext, lineNum int, line string, arg string) *core.Violation {
	v := r.CreateViolation(ctx.RelPath, lineNum, "Object.* call uses a nested value that may be null or undefined")
	v.WithCode(strings.TrimSpace(line))
	v.WithSuggestion("Normalize " + arg + " to a verified object before calling Object.keys/values/entries or hasOwnProperty.")
	v.WithContext("pattern", "nullable-object-call")
	v.WithContext("language", "typescript")
	v.WithContext("argument", arg)
	return v
}
