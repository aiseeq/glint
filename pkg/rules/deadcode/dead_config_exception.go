package deadcode

import (
	"fmt"
	"path/filepath"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewDeadConfigExceptionRule())
}

// DeadConfigExceptionRule detects a rule exception of the configuration
// that names files (file, files) none of which exists under the
// configuration's directory:
//
//	exceptions:
//	  - files: "services/billing/**"   # the tree is backend/services/billing
//
// Exception paths are relative to the directory of the configuration file.
// An exception written for a path that moved, or relative to a checked
// subdirectory, suppresses nothing: the findings it was meant for come back,
// and nothing says why. The check runs once per configuration, over every
// file of its directory, whichever directories the run checks.
type DeadConfigExceptionRule struct {
	*rules.BaseRule
}

// NewDeadConfigExceptionRule creates the rule
func NewDeadConfigExceptionRule() *DeadConfigExceptionRule {
	return &DeadConfigExceptionRule{BaseRule: rules.NewBaseRule(
		"dead-config-exception",
		"deadcode",
		"Detects a configuration exception whose file or files match no file under the configuration's directory — it suppresses nothing",
		core.SeverityMedium,
	)}
}

// AnalyzeFile is a no-op: the check reads the configuration, not a file.
func (r *DeadConfigExceptionRule) AnalyzeFile(_ *core.FileContext) []*core.Violation { return nil }

// CheckConfig reports the dead exceptions of a configuration; files are the
// files under its directory, relative to it. Findings name the configuration
// file relative to base.
func (r *DeadConfigExceptionRule) CheckConfig(cfg *core.Config, files []string, base string) ([]*core.Violation, error) {
	var violations []*core.Violation
	for _, dead := range cfg.DeadExceptions(files) {
		source, err := filepath.Rel(base, dead.Source)
		if err != nil {
			return nil, fmt.Errorf("name configuration %q relative to %q: %w", dead.Source, base, err)
		}
		pattern := dead.Exception.Files
		if pattern == "" {
			pattern = dead.Exception.File
		}
		v := r.CreateViolation(source, dead.Line, fmt.Sprintf(
			"Exception of %s names %q, which matches no file under the configuration's directory — it suppresses nothing",
			dead.Rule, pattern))
		v.WithSuggestion("Write the path relative to the directory of the configuration file, or delete the exception")
		v.WithContext("category", dead.Category)
		violations = append(violations, v)
	}
	return violations, nil
}
