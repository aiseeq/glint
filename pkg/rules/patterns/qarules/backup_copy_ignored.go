package qarules

import (
	"fmt"
	"path/filepath"
	"regexp"
	"sync"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewBackupCopyOfIgnoredFileRule())
}

var backupCopySuffix = regexp.MustCompile(`(?:\.bak(?:[^[:alnum:]].*)?|\.orig(?:[^[:alnum:]].*)?|~)$`)

// BackupCopyOfIgnoredFileRule detects a backup beside a file excluded by
// .gitignore, where the backup's different name makes it visible to Git.
type BackupCopyOfIgnoredFileRule struct {
	*rules.BaseRule
	mu       sync.Mutex
	checkers map[string]*core.GitIgnoreChecker
}

// NewBackupCopyOfIgnoredFileRule creates the rule.
func NewBackupCopyOfIgnoredFileRule() *BackupCopyOfIgnoredFileRule {
	return &BackupCopyOfIgnoredFileRule{BaseRule: rules.NewBaseRule(
		"backup-copy-of-ignored-file", "patterns",
		"Detects a backup copy beside a file ignored by the project's .gitignore, where the copy's name is no longer ignored and may expose the original's contents in a commit",
		core.SeverityHigh,
	)}
}

// ReadsOtherFiles reports that findings depend on the project's .gitignore files.
func (r *BackupCopyOfIgnoredFileRule) ReadsOtherFiles() bool { return true }

// RequiresFile selects files with a recognized backup suffix, regardless of extension.
func (r *BackupCopyOfIgnoredFileRule) RequiresFile(path string) bool {
	return backupCopySuffix.MatchString(filepath.Base(path))
}

// RequiresAdditionalFile includes backup names outside the walker's standard extensions.
func (r *BackupCopyOfIgnoredFileRule) RequiresAdditionalFile(path string) bool {
	return r.RequiresFile(path)
}

func (r *BackupCopyOfIgnoredFileRule) checker(root string) (*core.GitIgnoreChecker, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if checker := r.checkers[root]; checker != nil {
		return checker, nil
	}
	checker, err := core.NewGitIgnoreChecker(root)
	if err != nil {
		return nil, err
	}
	if r.checkers == nil {
		r.checkers = make(map[string]*core.GitIgnoreChecker)
	}
	r.checkers[root] = checker
	return checker, nil
}

// AnalyzeFile reports a backup whose corresponding original is ignored.
func (r *BackupCopyOfIgnoredFileRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	base := filepath.Base(ctx.Path)
	match := backupCopySuffix.FindStringIndex(base)
	if match == nil || match[0] == 0 {
		return nil
	}
	original := filepath.Join(filepath.Dir(ctx.Path), base[:match[0]])
	originalRel := filepath.ToSlash(filepath.Join(filepath.Dir(ctx.RelPath), base[:match[0]]))
	checker, err := r.checker(ctx.ProjectRoot)
	if err == nil {
		var ignored bool
		ignored, err = checker.Ignored(original)
		if err == nil && !ignored {
			return nil
		}
	}
	if err != nil {
		return []*core.Violation{r.CreateViolation(ctx.RelPath, 1,
			fmt.Sprintf("could not check whether original %s is ignored by .gitignore: %v", originalRel, err))}
	}
	v := r.CreateViolation(ctx.RelPath, 1,
		"backup copy is visible to Git although its original "+originalRel+" is ignored by .gitignore")
	v.Suggestion = "Keep the copy outside the repository, such as in a scratchpad or temporary directory"
	return []*core.Violation{v}
}
