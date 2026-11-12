package architecture

import (
	"errors"
	"fmt"
	"io/fs"
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
// new or larger than in HEAD, under its own path or the one it moved from. A
// link is skipped: HEAD keeps the link's target
// path, and the script it points to is checked under its own name.
func (r *ShellScriptSizeRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	size := len(ctx.Content)
	if !ctx.IsShellFile() || size <= r.maxBytes {
		return nil
	}
	if info, err := os.Lstat(ctx.Path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return nil
	}
	head, err := committedVersion(ctx.Path)
	if size <= head.size {
		return nil
	}
	v := r.CreateViolation(ctx.RelPath, 1, sizeMessage(size, r.maxBytes, head, err))
	v.WithSuggestion("Move the script to Go or TypeScript; keep in shell only a short wrapper that runs it. A large script may be fixed without growing")
	return []*core.Violation{v}
}

// headVersion is a script as HEAD has it: size -1 when HEAD has no version of
// it, from the HEAD path when the script moved.
type headVersion struct {
	size int
	from string
}

// sizeMessage tells the size against the limit and against HEAD, headErr
// when HEAD was not read. A number that rounds to the same text as the one it
// is compared with is given in bytes, both of them.
func sizeMessage(size, limit int, head headVersion, headErr error) string {
	sizeShown, limitShown := sizeText(size), sizeText(limit)
	if sizeShown == limitShown {
		sizeShown, limitShown = byteText(size), byteText(limit)
	}
	growth := "a new shell script"
	if headErr != nil {
		growth = "its size in HEAD not read: " + headErr.Error()
	}
	if head.size >= 0 {
		headShown := sizeText(head.size)
		if headShown == sizeText(size) {
			sizeShown, headShown = byteText(size), byteText(head.size)
		}
		growth = "grown from " + headShown + " in HEAD"
		if head.from != "" {
			growth += " as " + head.from
		}
	}
	return fmt.Sprintf("Shell script of %s, over the %s limit for shell: %s", sizeShown, limitShown, growth)
}

// committedVersion finds the script in HEAD: under its own path, under the
// path git's rename detection pairs it with, or, for a move git does not
// track, as a blob of HEAD with the same content whose path is gone from disk
// and taken by no rename. A copy beside its original is new shell code. Before
// git add, a move and a copy of one script both match the gone path; the gate
// of graft commit sees them staged, where the rename takes it.
func committedVersion(path string) (headVersion, error) {
	dir, base := filepath.Dir(path), filepath.Base(path)
	size, found, err := committedSize(dir, "./"+base)
	if err != nil || found != headPathAbsent {
		return headVersion{size: size}, err
	}
	none := headVersion{size: -1}
	where, err := gitOutput(dir, "rev-parse", "--show-toplevel", "--show-prefix")
	if err != nil {
		return none, err
	}
	top, prefix, _ := strings.Cut(strings.TrimSuffix(where, "\n"), "\n")
	diff, err := gitOutput(dir, "diff", "-M", "-z", "--name-status", "HEAD", "--")
	if err != nil {
		return none, err
	}
	pairs := renames(diff)
	if from := pairs[prefix+base]; from != "" {
		size, _, err := committedSize(dir, ":"+from)
		if err != nil {
			return none, err
		}
		return headVersion{size: size, from: from}, nil
	}
	blob, err := gitOutput(dir, "hash-object", "--", base)
	if err != nil {
		return none, err
	}
	tree, err := gitOutput(dir, "ls-tree", "-r", "-z", "--full-tree", "HEAD")
	if err != nil {
		return none, err
	}
	taken := make(map[string]bool, len(pairs))
	for _, from := range pairs {
		taken[from] = true
	}
	if from := movedBlobPath(tree, strings.TrimSpace(blob), top, taken); from != "" {
		size, _, err := committedSize(dir, ":"+from)
		return headVersion{size: size, from: from}, err
	}
	return none, nil
}

// renames maps each new path of `git diff -M -z --name-status` to the HEAD
// path it was renamed from.
func renames(diff string) map[string]string {
	pairs := make(map[string]string)
	fields := strings.Split(diff, "\x00")
	for i := 0; i < len(fields); i++ {
		if !strings.HasPrefix(fields[i], "R") {
			i++ // one path
			continue
		}
		if i+2 < len(fields) {
			pairs[fields[i+2]] = fields[i+1]
		}
		i += 2
	}
	return pairs
}

// movedBlobPath is a path of `git ls-tree -r -z` whose blob is hash, which is
// gone from the work tree at top and which no rename has taken, or "".
func movedBlobPath(tree, hash, top string, taken map[string]bool) string {
	for entry := range strings.SplitSeq(tree, "\x00") {
		meta, path, ok := strings.Cut(entry, "\t")
		if !ok || !strings.HasSuffix(meta, " "+hash) || taken[path] {
			continue
		}
		if _, err := os.Lstat(filepath.Join(top, filepath.FromSlash(path))); errors.Is(err, fs.ErrNotExist) {
			return path
		}
	}
	return ""
}

// headLookup is what HEAD has for a path.
type headLookup int

const (
	headPathFound  headLookup = iota
	headPathAbsent            // HEAD is there, the path is not
	headMissing               // outside a repository, or one without commits
)

// committedSize is the size of a path in HEAD, "./name" from dir or ":path"
// from the top of the repository holding dir; size -1 when it is not there.
// git tells an absent path and a missing HEAD by the text of its exit 128,
// which is also its code for a real failure (another owner, a missing
// object), so the text decides. A repository whose HEAD names a broken ref
// reads as one without commits: git words both alike.
func committedSize(dir, path string) (int, headLookup, error) {
	out, err := gitOutput(dir, "cat-file", "-s", "HEAD:"+strings.TrimPrefix(path, ":"))
	switch {
	case gitSaid(err, "exists on disk, but not in 'HEAD'"):
		return -1, headPathAbsent, nil
	case gitSaid(err, "not a git repository", "invalid object name 'HEAD'"):
		return -1, headMissing, nil
	case err != nil:
		return -1, headMissing, err
	}
	size, err := strconv.Atoi(strings.TrimSpace(out))
	if err != nil {
		return -1, headMissing, fmt.Errorf("git cat-file size %q: %w", out, err)
	}
	return size, headPathFound, nil
}

// gitSaid tells a git failure whose words hold one of the texts.
func gitSaid(err error, texts ...string) bool {
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		return false
	}
	for _, text := range texts {
		if strings.Contains(string(exit.Stderr), text) {
			return true
		}
	}
	return false
}

// gitOutput runs git in dir with replace refs off, its messages in English,
// and without the variables that would point it at another repository. A
// failure carries git's own words.
func gitOutput(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", append([]string{"--no-replace-objects", "-C", dir}, args...)...)
	cmd.Env = append(repositoryNeutralEnv(os.Environ()), "LC_ALL=C")
	out, err := cmd.Output()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return string(out), fmt.Errorf("git %s: %w: %s", args[0], err, strings.TrimSpace(string(exit.Stderr)))
	}
	if err != nil {
		return string(out), fmt.Errorf("git %s: %w", args[0], err)
	}
	return string(out), nil
}

// repositoryNeutralEnv drops the variables a hook may have set for its own
// repository that change what HEAD:path or the diff against HEAD reads, so git
// finds the repository from the script's directory. The other local ones of
// `git rev-parse --local-env-vars` (prefix, config, alternates) leave them as
// they are.
func repositoryNeutralEnv(env []string) []string {
	kept := make([]string, 0, len(env))
	for _, entry := range env {
		name, _, _ := strings.Cut(entry, "=")
		switch name {
		case "GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_OBJECT_DIRECTORY", "GIT_INDEX_FILE":
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
