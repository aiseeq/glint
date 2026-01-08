package fix

import (
	"strings"

	"github.com/aiseeq/glint/pkg/core"
)

// DeprecatedIoutilFixer fixes deprecated io/ioutil usage
type DeprecatedIoutilFixer struct{}

// NewDeprecatedIoutilFixer creates the fixer
func NewDeprecatedIoutilFixer() *DeprecatedIoutilFixer {
	return &DeprecatedIoutilFixer{}
}

// RuleName returns the rule name
func (f *DeprecatedIoutilFixer) RuleName() string {
	return "deprecated-ioutil"
}

// Replacement mappings for ioutil functions
var ioutilReplacements = map[string]string{
	"ioutil.ReadFile":  "os.ReadFile",
	"ioutil.WriteFile": "os.WriteFile",
	"ioutil.ReadAll":   "io.ReadAll",
	"ioutil.ReadDir":   "os.ReadDir",
	"ioutil.TempFile":  "os.CreateTemp",
	"ioutil.TempDir":   "os.MkdirTemp",
	"ioutil.NopCloser": "io.NopCloser",
	"ioutil.Discard":   "io.Discard",
}

// CanFix returns true if the violation can be fixed
func (f *DeprecatedIoutilFixer) CanFix(v *core.Violation) bool {
	return v != nil && v.Rule == "deprecated-ioutil"
}

// GenerateFix generates the fix for a violation
func (f *DeprecatedIoutilFixer) GenerateFix(ctx *core.FileContext, v *core.Violation) *Fix {
	if ctx == nil || v == nil {
		return nil
	}

	if v.Line < 1 || v.Line > len(ctx.Lines) {
		return nil
	}

	line := ctx.Lines[v.Line-1]

	// Find which ioutil function is used
	for old, replacement := range ioutilReplacements {
		if strings.Contains(line, old) {
			return &Fix{
				File:      ctx.Path,
				StartLine: v.Line,
				EndLine:   v.Line,
				OldText:   old,
				NewText:   replacement,
				Message:   "Replace deprecated " + old + " with " + replacement,
				RuleName:  "deprecated-ioutil",
				Violation: v,
			}
		}
	}

	return nil
}

func init() {
	DefaultRegistry.Register(NewDeprecatedIoutilFixer())
}
