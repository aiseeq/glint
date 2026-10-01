package deadcode

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewDeadConfigExceptionRule())
}

// DeadConfigExceptionRule detects a rule exception of the configuration
// that names files (file, files) none of which exists under the
// configuration's directory, or a function none of its Go files declares:
//
//	exceptions:
//	  - files: "services/billing/**"   # the tree is backend/services/billing
//	  - file: backend/sync/wallets.go
//	    function: syncWallet            # renamed to syncWallets
//
// Exception paths are relative to the directory of the configuration file.
// An exception written for a path or a function that moved, or relative to
// a checked subdirectory, suppresses nothing: the findings it was meant for
// come back, and nothing says why. The check runs once per configuration,
// over every file of its directory, whichever directories the run checks.
type DeadConfigExceptionRule struct {
	*rules.BaseRule
}

// NewDeadConfigExceptionRule creates the rule
func NewDeadConfigExceptionRule() *DeadConfigExceptionRule {
	return &DeadConfigExceptionRule{BaseRule: rules.NewBaseRule(
		"dead-config-exception",
		"deadcode",
		"Detects a configuration exception whose files or function do not exist under the configuration's directory — it suppresses nothing",
		core.SeverityMedium,
	)}
}

// AnalyzeFile is a no-op: the check reads the configuration, not a file.
func (r *DeadConfigExceptionRule) AnalyzeFile(_ *core.FileContext) []*core.Violation { return nil }

// CheckConfig reports the dead exceptions of a configuration; files are the
// files under its directory, relative to it. Findings name the configuration
// file relative to base.
func (r *DeadConfigExceptionRule) CheckConfig(cfg *core.Config, files []string, base string) ([]*core.Violation, error) {
	dir := filepath.Dir(cfg.ConfigPath())
	var violations []*core.Violation
	deadExceptions, err := cfg.DeadExceptions(files, func(path string) ([]string, bool, error) { return goFunctions(filepath.Join(dir, path)) })
	if err != nil {
		return nil, err
	}
	for _, dead := range deadExceptions {
		source, err := filepath.Rel(base, dead.Source)
		if err != nil {
			return nil, fmt.Errorf("name configuration %q relative to %q: %w", dead.Source, base, err)
		}
		pattern := dead.Exception.Files
		if pattern == "" {
			pattern = dead.Exception.File
		}
		message := fmt.Sprintf("Exception of %s names %q, which matches no file under the configuration's directory — it suppresses nothing", dead.Rule, pattern)
		suggestion := "Write the path relative to the directory of the configuration file, or delete the exception"
		if dead.NoFunction {
			message = fmt.Sprintf("Exception of %s names function %s, which %q does not declare — it suppresses nothing", dead.Rule, dead.Exception.Function, pattern)
			suggestion = "Name the function the finding is in, or delete the exception"
		}
		v := r.CreateViolation(source, dead.Line, message)
		v.WithSuggestion(suggestion)
		v.WithContext("category", dead.Category)
		violations = append(violations, v)
	}
	return violations, nil
}

// goFunctions returns the names of the functions and methods a Go file
// declares; known is false for a file that is not Go.
func goFunctions(path string) (names []string, known bool, err error) {
	if filepath.Ext(path) != ".go" {
		return nil, false, nil
	}
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
	if err != nil {
		return nil, false, fmt.Errorf("list the functions of %s for a configuration exception: %w", path, err)
	}
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok {
			names = append(names, fn.Name.Name)
		}
	}
	return names, true, nil
}
