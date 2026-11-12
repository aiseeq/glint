package architecture

import (
	"errors"
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
// new or larger than in HEAD. A link is skipped: HEAD keeps the link's target
// path, and the script it points to is checked under its own name.
func (r *ShellScriptSizeRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	size := len(ctx.Content)
	if !ctx.IsShellFile() || size <= r.maxBytes {
		return nil
	}
	if info, err := os.Lstat(ctx.Path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return nil
	}
	headSize, tracked, err := committedSize(ctx.Path)
	if !tracked {
		headSize = -1
	}
	if size <= headSize {
		return nil
	}
	v := r.CreateViolation(ctx.RelPath, 1, sizeMessage(size, r.maxBytes, headSize, err))
	v.WithSuggestion("Move the script to Go or TypeScript; keep in shell only a short wrapper that runs it. A large script may be fixed without growing")
	return []*core.Violation{v}
}

// sizeMessage tells the size against the limit and against HEAD, headSize -1
// for a new script, headErr when HEAD was not read. A number that rounds to the
// same text as the one it is compared with is given in bytes, both of them.
func sizeMessage(size, limit, headSize int, headErr error) string {
	sizeShown, limitShown := sizeText(size), sizeText(limit)
	if sizeShown == limitShown {
		sizeShown, limitShown = byteText(size), byteText(limit)
	}
	growth := "a new shell script"
	if headErr != nil {
		growth = "its size in HEAD not read: " + headErr.Error()
	}
	if headSize >= 0 {
		headShown := sizeText(headSize)
		if headShown == sizeText(size) {
			sizeShown, headShown = byteText(size), byteText(headSize)
		}
		growth = "grown from " + headShown + " in HEAD"
	}
	return fmt.Sprintf("Shell script of %s, over the %s limit for shell: %s", sizeShown, limitShown, growth)
}

// committedSize is the size of path in the HEAD commit of the git repository
// holding it, read by the git command. A path outside a repository, in one
// without commits, or absent from HEAD is untracked, which git tells by exit
// code 128; any other failure, git missing too, is an error.
func committedSize(path string) (int, bool, error) {
	cmd := exec.Command("git", "--no-replace-objects", "-C", filepath.Dir(path), "cat-file", "-s", "HEAD:./"+filepath.Base(path))
	cmd.Env = repositoryNeutralEnv(os.Environ())
	out, err := cmd.Output()
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == 128 {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("git cat-file: %w", err)
	}
	size, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil {
		return 0, false, fmt.Errorf("git cat-file size %q: %w", out, err)
	}
	return size, true, nil
}

// repositoryNeutralEnv drops the variables a hook may have set for its own
// repository that change what HEAD:path reads, so git finds the repository
// from the script's directory. The other local ones of `git rev-parse
// --local-env-vars` (index, prefix, config, alternates) leave it as is.
func repositoryNeutralEnv(env []string) []string {
	kept := make([]string, 0, len(env))
	for _, entry := range env {
		name, _, _ := strings.Cut(entry, "=")
		switch name {
		case "GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_OBJECT_DIRECTORY":
			continue
		}
		kept = append(kept, entry)
	}
	return kept
}

// sizeText prints a byte count in kilobytes rounded up to a tenth, trailing
// .0 dropped: a script even one byte over the limit reads as larger than it.
func sizeText(n int) string {
	const kilobyte = 1024
	if n < kilobyte {
		return byteText(n)
	}
	tenths := (n*10 + kilobyte - 1) / kilobyte
	return strings.TrimSuffix(fmt.Sprintf("%d.%d", tenths/10, tenths%10), ".0") + " KB"
}

func byteText(n int) string { return fmt.Sprintf("%d bytes", n) }
