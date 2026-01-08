package patterns

import (
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewDeprecatedIoutilRule())
}

// DeprecatedIoutilRule detects usage of deprecated io/ioutil package
type DeprecatedIoutilRule struct {
	*rules.BaseRule
}

// NewDeprecatedIoutilRule creates the rule
func NewDeprecatedIoutilRule() *DeprecatedIoutilRule {
	return &DeprecatedIoutilRule{
		BaseRule: rules.NewBaseRule(
			"deprecated-ioutil",
			"patterns",
			"Detects deprecated io/ioutil package usage (use io and os packages instead)",
			core.SeverityMedium,
		),
	}
}

// AnalyzeFile checks for io/ioutil usage
func (r *DeprecatedIoutilRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() {
		return nil
	}

	var violations []*core.Violation
	inMultiLineBacktick := false

	for lineNum, line := range ctx.Lines {
		wasInBacktick := inMultiLineBacktick
		inMultiLineBacktick = r.updateBacktickState(line, inMultiLineBacktick)

		if r.shouldSkipLine(line, wasInBacktick) {
			continue
		}

		if v := r.checkLine(ctx, lineNum, line); v != nil {
			violations = append(violations, v)
		}
	}

	return violations
}

func (r *DeprecatedIoutilRule) updateBacktickState(line string, current bool) bool {
	backtickCount := strings.Count(line, "`")
	if backtickCount > 0 && backtickCount%2 == 1 {
		return !current
	}
	return current
}

func (r *DeprecatedIoutilRule) shouldSkipLine(line string, wasInBacktick bool) bool {
	backtickCount := strings.Count(line, "`")

	// Skip lines completely inside multi-line backtick strings
	if wasInBacktick && backtickCount == 0 {
		return true
	}

	// Skip if ioutil. appears in the backtick portion of this line
	if r.isIoutilInBacktickPortion(line, wasInBacktick, backtickCount) {
		return true
	}

	trimmed := strings.TrimSpace(line)
	return strings.HasPrefix(trimmed, "//")
}

func (r *DeprecatedIoutilRule) checkLine(ctx *core.FileContext, lineNum int, line string) *core.Violation {
	trimmed := strings.TrimSpace(line)

	if r.isIoutilImport(line) {
		v := r.CreateViolation(ctx.RelPath, lineNum+1, "io/ioutil is deprecated since Go 1.16")
		v.WithCode(trimmed)
		v.WithSuggestion("Use io.ReadAll, os.ReadFile, os.WriteFile instead")
		return v
	}

	if strings.Contains(line, "ioutil.") {
		if isInsideLiteral(line, "ioutil.") || isInInlineComment(line, "ioutil.") {
			return nil
		}

		v := r.CreateViolation(ctx.RelPath, lineNum+1, "ioutil functions are deprecated")
		v.WithCode(trimmed)
		v.WithSuggestion(r.getSuggestion(line))
		return v
	}

	return nil
}

// isIoutilInBacktickPortion checks if ioutil. is in the backtick-enclosed portion of a line
func (r *DeprecatedIoutilRule) isIoutilInBacktickPortion(line string, wasInBacktick bool, backtickCount int) bool {
	if !strings.Contains(line, "ioutil.") {
		return false
	}

	ioutilIdx := strings.Index(line, "ioutil.")
	backtickIdx := strings.Index(line, "`")

	// If we were inside a backtick and this line closes it,
	// check if ioutil. is before the closing backtick
	if wasInBacktick && backtickCount > 0 && backtickIdx >= 0 {
		if ioutilIdx < backtickIdx {
			return true // ioutil. is inside the backtick string
		}
	}

	return false
}

// isIoutilImport checks if this line imports io/ioutil
func (r *DeprecatedIoutilRule) isIoutilImport(line string) bool {
	// Must have the import path in double quotes, not inside backticks
	if !strings.Contains(line, `"io/ioutil"`) {
		return false
	}

	// Skip if inside backtick string (test data, etc.)
	if isInsideBackticks(line, `"io/ioutil"`) {
		return false
	}

	return true
}

// isInsideLiteral checks if substr is inside any string literal
func isInsideLiteral(line, substr string) bool {
	return isInsideString(line, substr) || isInsideBackticks(line, substr)
}

// isInInlineComment checks if substr appears only after // in the line
func isInInlineComment(line, substr string) bool {
	commentIdx := strings.Index(line, "//")
	if commentIdx < 0 {
		return false
	}

	substrIdx := strings.Index(line, substr)
	if substrIdx < 0 {
		return false
	}

	// substr is in comment if it appears after //
	return substrIdx > commentIdx
}

// isInsideString checks if a substring appears inside a double-quoted string
func isInsideString(line, substr string) bool {
	idx := strings.Index(line, substr)
	if idx < 0 {
		return false
	}

	beforeSubstr := line[:idx]
	quoteCount := strings.Count(beforeSubstr, `"`)
	return quoteCount%2 == 1
}

// isInsideBackticks checks if a substring appears inside a backtick string
func isInsideBackticks(line, substr string) bool {
	idx := strings.Index(line, substr)
	if idx < 0 {
		return false
	}

	beforeSubstr := line[:idx]
	backtickCount := strings.Count(beforeSubstr, "`")
	return backtickCount%2 == 1
}

func (r *DeprecatedIoutilRule) getSuggestion(line string) string {
	switch {
	case strings.Contains(line, "ioutil.ReadAll"):
		return "Replace with io.ReadAll"
	case strings.Contains(line, "ioutil.ReadFile"):
		return "Replace with os.ReadFile"
	case strings.Contains(line, "ioutil.WriteFile"):
		return "Replace with os.WriteFile"
	case strings.Contains(line, "ioutil.ReadDir"):
		return "Replace with os.ReadDir"
	case strings.Contains(line, "ioutil.TempDir"):
		return "Replace with os.MkdirTemp"
	case strings.Contains(line, "ioutil.TempFile"):
		return "Replace with os.CreateTemp"
	case strings.Contains(line, "ioutil.NopCloser"):
		return "Replace with io.NopCloser"
	case strings.Contains(line, "ioutil.Discard"):
		return "Replace with io.Discard"
	default:
		return "Replace with equivalent functions from io or os packages"
	}
}
