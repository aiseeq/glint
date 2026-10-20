package architecture

import (
	"path/filepath"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewPythonFileRule())
}

// PythonFileRule reports a Python source in a project that keeps its code
// where glint can analyze it: Go, TypeScript, shell. The rest of glint does
// not read Python, so a script written in it goes unchecked.
//
// The rule is off by default; a project turns it on and lists the Python it
// keeps on purpose as exceptions with a reason - a neural network, someone
// else's code, data.
type PythonFileRule struct {
	*rules.BaseRule
}

// NewPythonFileRule creates the rule
func NewPythonFileRule() *PythonFileRule {
	return &PythonFileRule{BaseRule: rules.NewBaseRule(
		"python-file",
		"architecture",
		"Reports Python sources, which glint does not analyze - scripts are written in Go, TypeScript or shell",
		core.SeverityMedium,
	)}
}

// AnalyzeFile reports a Python source at its first line.
func (r *PythonFileRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !strings.EqualFold(filepath.Ext(ctx.Path), ".py") {
		return nil
	}
	v := r.CreateViolation(ctx.RelPath, 1, "Python source — glint does not analyze it, so nothing here is checked")
	v.WithSuggestion("Rewrite the script in Go, TypeScript or shell, or list the file in the rule's exceptions with a reason (a neural network, someone else's code, data)")
	return []*core.Violation{v}
}
