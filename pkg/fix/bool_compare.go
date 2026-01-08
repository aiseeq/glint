package fix

import (
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
)

// BoolCompareFixer fixes redundant boolean comparisons
type BoolCompareFixer struct{}

// NewBoolCompareFixer creates the fixer
func NewBoolCompareFixer() *BoolCompareFixer {
	return &BoolCompareFixer{}
}

// RuleName returns the rule name
func (f *BoolCompareFixer) RuleName() string {
	return "bool-compare"
}

// Patterns for bool comparisons
var (
	// x == true, x == false
	boolCompareRight = regexp.MustCompile(`(\w+(?:\.\w+)*)\s*==\s*(true|false)`)
	// true == x, false == x
	boolCompareLeft = regexp.MustCompile(`(true|false)\s*==\s*(\w+(?:\.\w+)*)`)
	// x != true, x != false
	boolNotCompareRight = regexp.MustCompile(`(\w+(?:\.\w+)*)\s*!=\s*(true|false)`)
	// true != x, false != x
	boolNotCompareLeft = regexp.MustCompile(`(true|false)\s*!=\s*(\w+(?:\.\w+)*)`)
)

// CanFix returns true if the violation can be fixed
func (f *BoolCompareFixer) CanFix(v *core.Violation) bool {
	return v != nil && v.Rule == "bool-compare"
}

// GenerateFix generates the fix for a violation
func (f *BoolCompareFixer) GenerateFix(ctx *core.FileContext, v *core.Violation) *Fix {
	if ctx == nil || v == nil {
		return nil
	}

	if v.Line < 1 || v.Line > len(ctx.Lines) {
		return nil
	}

	line := ctx.Lines[v.Line-1]

	// Try each pattern
	if fix := f.tryFixPattern(ctx.Path, v.Line, line, boolCompareRight, true, false); fix != nil {
		return fix
	}
	if fix := f.tryFixPattern(ctx.Path, v.Line, line, boolCompareLeft, true, true); fix != nil {
		return fix
	}
	if fix := f.tryFixPattern(ctx.Path, v.Line, line, boolNotCompareRight, false, false); fix != nil {
		return fix
	}
	if fix := f.tryFixPattern(ctx.Path, v.Line, line, boolNotCompareLeft, false, true); fix != nil {
		return fix
	}

	return nil
}

func (f *BoolCompareFixer) tryFixPattern(file string, line int, content string, pattern *regexp.Regexp, isEqual bool, boolFirst bool) *Fix {
	matches := pattern.FindStringSubmatch(content)
	if matches == nil {
		return nil
	}

	var varName, boolVal string
	if boolFirst {
		boolVal = matches[1]
		varName = matches[2]
	} else {
		varName = matches[1]
		boolVal = matches[2]
	}

	oldText := matches[0]
	var newText string

	// Determine the replacement based on operator and bool value
	if isEqual {
		// == operator
		if boolVal == "true" {
			newText = varName // x == true -> x
		} else {
			newText = "!" + varName // x == false -> !x
		}
	} else {
		// != operator
		if boolVal == "true" {
			newText = "!" + varName // x != true -> !x
		} else {
			newText = varName // x != false -> x
		}
	}

	// Handle already negated variables (!x == false -> x, not !!x)
	if strings.HasPrefix(varName, "!") && strings.HasPrefix(newText, "!") {
		newText = varName[1:] // Remove double negation
	}

	return &Fix{
		File:      file,
		StartLine: line,
		EndLine:   line,
		OldText:   oldText,
		NewText:   newText,
		Message:   "Simplify boolean comparison",
		RuleName:  "bool-compare",
	}
}

func init() {
	DefaultRegistry.Register(NewBoolCompareFixer())
}
