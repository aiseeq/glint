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
	objectCollectionCall *regexp.Regexp
	hasOwnPropertyCall   *regexp.Regexp
	objectHasOwnCall     *regexp.Regexp
}

func NewNullableObjectCallRule() *NullableObjectCallRule {
	return &NullableObjectCallRule{
		BaseRule: rules.NewBaseRule(
			"nullable-object-call",
			"patterns",
			"Detects Object.* calls on possibly nullable nested values",
			core.SeverityHigh,
		),
		objectCollectionCall: regexp.MustCompile(`Object\.(?:keys|values|entries)\s*\(([^)]*)\)`),
		hasOwnPropertyCall:   regexp.MustCompile(`Object\.prototype\.hasOwnProperty\.call\s*\(([^,)]*)`),
		objectHasOwnCall:     regexp.MustCompile(`Object\.hasOwn\s*\(([^,)]*)`),
	}
}

func (r *NullableObjectCallRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsTypeScriptFile() && !ctx.IsJavaScriptFile() {
		return nil
	}
	if r.shouldSkip(ctx) {
		return nil
	}

	var violations []*core.Violation
	for i, line := range ctx.Lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") {
			continue
		}

		if arg, ok := r.unsafeObjectCollectionArg(line); ok {
			violations = append(violations, r.violation(ctx, i+1, line, arg))
			continue
		}

		if arg, ok := r.unsafeHasOwnArg(line); ok {
			violations = append(violations, r.violation(ctx, i+1, line, arg))
		}
	}

	return violations
}

func (r *NullableObjectCallRule) unsafeObjectCollectionArg(line string) (string, bool) {
	matches := r.objectCollectionCall.FindAllStringSubmatch(line, -1)
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		arg := strings.TrimSpace(match[1])
		if isUnsafeNullableObjectArg(line, arg) {
			return arg, true
		}
	}
	return "", false
}

func (r *NullableObjectCallRule) unsafeHasOwnArg(line string) (string, bool) {
	for _, pattern := range []*regexp.Regexp{r.hasOwnPropertyCall, r.objectHasOwnCall} {
		matches := pattern.FindAllStringSubmatch(line, -1)
		for _, match := range matches {
			if len(match) < 2 {
				continue
			}
			arg := strings.TrimSpace(match[1])
			if isUnsafeNullableObjectArg(line, arg) {
				return arg, true
			}
		}
	}
	return "", false
}

func isUnsafeNullableObjectArg(line string, arg string) bool {
	if arg == "" || hasObjectFallback(arg) || hasSameLineObjectGuard(line, arg) {
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

func hasSameLineObjectGuard(line string, arg string) bool {
	idx := strings.Index(line, "Object.")
	if idx <= 0 {
		return false
	}
	prefix := line[:idx]
	return strings.Contains(prefix, arg+" &&") || strings.Contains(prefix, "typeof "+arg+" === 'object'") || strings.Contains(prefix, "typeof "+arg+" === \"object\"")
}

func (r *NullableObjectCallRule) shouldSkip(ctx *core.FileContext) bool {
	path := ctx.RelPath
	if ctx.IsTestFile() {
		return true
	}
	return strings.Contains(path, "/node_modules/") ||
		strings.Contains(path, "/.next/") ||
		strings.Contains(path, "/out/") ||
		strings.Contains(path, "/dist/") ||
		strings.Contains(path, "/generated/") ||
		strings.Contains(path, "generated-") ||
		strings.Contains(path, ".generated")
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
