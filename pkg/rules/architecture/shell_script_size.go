package architecture

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewShellScriptSizeRule())
}

// defaultShellScriptMaxBytes is about the 95th percentile of the shell
// scripts the consumer projects keep: shell is for small scripts, anything
// larger is written in Go or TypeScript, where it is typed and tested.
const defaultShellScriptMaxBytes = 20 * 1024

// ShellScriptSizeRule reports a shell script larger than max_bytes. A shell
// script grows by copy and paste, without types, and its tests are other
// shell scripts; past a few hundred lines it is a program, and a program is
// written in Go or TypeScript.
//
// The rule is a ratchet against the HEAD commit of the script's repository: a
// new script over the limit, or one that grew past the limit or beyond its HEAD
// size, is reported; a large script that kept or lost size is not, so a fix
// inside it does not have to wait for its move to another language.
type ShellScriptSizeRule struct {
	*rules.BaseRule
	maxBytes int
}

// NewShellScriptSizeRule creates the rule
func NewShellScriptSizeRule() *ShellScriptSizeRule {
	return &ShellScriptSizeRule{
		BaseRule: rules.NewBaseRule(
			"shell-script-size",
			"architecture",
			"Detects a shell script larger than max_bytes (20 KB) — shell is for small scripts, a larger one is moved to Go or TypeScript",
			core.SeverityMedium,
		),
		maxBytes: defaultShellScriptMaxBytes,
	}
}

// Configure reads max_bytes, the largest shell script that is not reported.
func (r *ShellScriptSizeRule) Configure(settings map[string]any) error {
	if err := r.BaseRule.Configure(settings); err != nil {
		return err
	}
	value, present, err := rules.IntSetting(settings, r.Name(), "max_bytes")
	if err != nil || !present {
		return err
	}
	if value <= 0 {
		return fmt.Errorf("configure %s: max_bytes must be positive, got %d", r.Name(), value)
	}
	r.maxBytes = value
	return nil
}

// ReadsOtherFiles tells the result cache that a finding depends on the HEAD
// commit as well as on the script, so it is never reused.
func (r *ShellScriptSizeRule) ReadsOtherFiles() bool { return true }

// AnalyzeFile reports, at its first line, a shell script over the limit that is
// new or larger than in HEAD.
func (r *ShellScriptSizeRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	size := len(ctx.Content)
	if !ctx.IsShellFile() || size <= r.maxBytes {
		return nil
	}
	headSize, tracked := committedSize(ctx.Path)
	if size <= headSize { // an untracked script has headSize 0
		return nil
	}
	growth := "a new shell script"
	if tracked {
		growth = "grown from " + sizeText(headSize) + " in HEAD"
	}
	v := r.CreateViolation(ctx.RelPath, 1, fmt.Sprintf("Shell script of %s, over the %s limit for shell: %s", sizeText(size), sizeText(r.maxBytes), growth))
	v.WithSuggestion("Move the script to Go or TypeScript; keep in shell only a short wrapper that runs it. A large script may be fixed without growing")
	return []*core.Violation{v}
}

// committedSize is the size of path in the HEAD commit of the git repository
// holding it, read by the git command. A path outside a repository, in one
// without commits, or absent from HEAD is untracked, as is any path when git
// is missing: it counts as a new script.
func committedSize(path string) (int, bool) {
	cmd := exec.Command("git", "-C", filepath.Dir(path), "cat-file", "-s", "HEAD:./"+filepath.Base(path))
	cmd.Env = repositoryNeutralEnv(os.Environ())
	out, err := cmd.Output()
	if err != nil {
		return 0, false
	}
	size, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil {
		return 0, false
	}
	return size, true
}

// repositoryNeutralEnv drops the variables a git hook sets for its own
// repository, so git finds the repository from the script's directory.
func repositoryNeutralEnv(env []string) []string {
	kept := make([]string, 0, len(env))
	for _, entry := range env {
		name, _, _ := strings.Cut(entry, "=")
		switch name {
		case "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY", "GIT_COMMON_DIR", "GIT_PREFIX":
			continue
		}
		kept = append(kept, entry)
	}
	return kept
}

// sizeText prints a byte count in kilobytes rounded up to a tenth, trailing
// .0 dropped: a script even one byte over the limit reads as larger than it.
func sizeText(n int) string {
	if n < 1024 {
		return fmt.Sprintf("%d bytes", n)
	}
	tenths := (n*10 + 1023) / 1024
	return strings.TrimSuffix(fmt.Sprintf("%d.%d", tenths/10, tenths%10), ".0") + " KB"
}
