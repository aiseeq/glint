package shellrules

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/toolcache"
)

func init() {
	rules.Register(NewShellcheckRule())
}

// shellcheckCache keeps shellcheck's answers between runs.
var shellcheckCache = toolcache.New("shellcheck")

// ShellcheckRule runs shellcheck on every shell script: its errors are high
// findings, its warnings medium ones; info and style notes are not reported.
// shellcheck reads the project's .shellcheckrc and the files a script
// sources, so the rule is not file-local: it keeps shellcheck's answers in
// a cache of its own, keyed by everything shellcheck read.
type ShellcheckRule struct {
	*rules.BaseRule
	// program is the shellcheck to run; tests point it at a stand-in.
	program string
	version func() (string, error)
}

// NewShellcheckRule creates the shellcheck rule.
func NewShellcheckRule() *ShellcheckRule {
	r := &ShellcheckRule{
		BaseRule: rules.NewBaseRule("shellcheck", "patterns",
			"Runs shellcheck on shell scripts (.sh, .bash, and files whose shebang runs a shell): its errors are high, its warnings medium",
			core.SeverityHigh),
		program: "shellcheck",
	}
	r.version = sync.OnceValues(func() (string, error) {
		out, err := exec.Command(r.program, "--version").Output()
		if err != nil {
			return "", fmt.Errorf("%s --version: %w", r.program, err)
		}
		return string(out), nil
	})
	return r
}

// ReadsOtherFiles reports that the findings depend on .shellcheckrc and on
// sourced files, not on the script alone.
func (r *ShellcheckRule) ReadsOtherFiles() bool { return true }

// CheckTools fails when the files hold a shell script and shellcheck is
// not installed.
func (r *ShellcheckRule) CheckTools(files []*core.FileContext) error {
	scripts := 0
	for _, ctx := range files {
		if ctx.IsShellFile() {
			scripts++
		}
	}
	if scripts == 0 {
		return nil
	}
	if _, err := exec.LookPath(r.program); err != nil {
		return fmt.Errorf("%d shell scripts need shellcheck, which is not installed (dnf install ShellCheck, apt install shellcheck): %w", scripts, err)
	}
	if _, err := r.version(); err != nil {
		return err
	}
	return nil
}

// shellcheckComment is one finding of shellcheck --format=json1.
type shellcheckComment struct {
	File    string `json:"file"`
	Line    int    `json:"line"`
	Column  int    `json:"column"`
	Level   string `json:"level"`
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// AnalyzeFile reports what shellcheck finds in a shell script.
func (r *ShellcheckRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsShellFile() {
		return nil
	}
	comments, err := r.check(ctx)
	if err != nil {
		v := r.CreateViolation(ctx.RelPath, 1, "shellcheck could not check this script, so nothing in it was checked: "+err.Error())
		return []*core.Violation{v.WithSuggestion("Fix what the error names: the script, its .shellcheckrc or a file it sources")}
	}
	var found []*core.Violation
	for _, c := range comments {
		v := r.CreateViolation(ctx.RelPath, c.Line, fmt.Sprintf("SC%d: %s", c.Code, c.Message)).
			WithColumn(c.Column).
			WithCode(ctx.GetLine(c.Line)).
			WithSuggestion(fmt.Sprintf("See https://www.shellcheck.net/wiki/SC%d", c.Code))
		if c.Level != "error" {
			v.Severity = core.SeverityMedium
		}
		found = append(found, v)
	}
	return found
}

// check returns shellcheck's errors and warnings on the script, from the
// cache when nothing shellcheck reads has changed.
func (r *ShellcheckRule) check(ctx *core.FileContext) ([]shellcheckComment, error) {
	version, err := r.version()
	if err != nil {
		return nil, err
	}
	inputs, err := shellcheckInputs(ctx)
	if err != nil {
		return nil, err
	}
	key := toolcache.Key(append([][]byte{[]byte(version), []byte(ctx.RelPath), ctx.Content}, inputs...)...)
	var comments []shellcheckComment
	found, err := shellcheckCache.Load(key, &comments)
	if err != nil {
		return nil, err
	}
	if found {
		return comments, nil
	}
	// From the project root, as a developer runs it: a source path
	// relative to the working directory resolves the same way.
	cmd := exec.Command(r.program, "--format=json1", "--severity=warning", ctx.Path)
	cmd.Dir = ctx.ProjectRoot
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err = cmd.Run()
	// Exit status 1 means findings; anything else is a failure.
	var exit *exec.ExitError
	if err != nil && (!errors.As(err, &exit) || exit.ExitCode() != 1) {
		return nil, fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
	}
	var report struct {
		Comments []shellcheckComment `json:"comments"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		return nil, fmt.Errorf("read shellcheck output: %w", err)
	}
	// A sourced file's own findings belong to its own check.
	comments = []shellcheckComment{}
	for _, c := range report.Comments {
		if c.File == ctx.Path {
			comments = append(comments, c)
		}
	}
	if err := shellcheckCache.Store(key, comments); err != nil {
		return nil, err
	}
	return comments, nil
}

// sourceLine finds a file a script sources by a literal name, and the
// name a shellcheck source= directive gives one.
var sourceLine = regexp.MustCompile(`(?m)^\s*(?:(?:source|\.)\s+["']?([^"'\s;&|$` + "`" + `]+)|#\s*shellcheck\s+source=(\S+))`)

// maxSourceDepth bounds how far sourced files are followed.
const maxSourceDepth = 4

// shellcheckInputs returns the contents of everything besides the script
// that shellcheck reads for it: the .shellcheckrc files that apply and the
// files the script sources, followed as shellcheck follows them, from the
// script's directory and from the project root.
func shellcheckInputs(ctx *core.FileContext) ([][]byte, error) {
	rcFiles, err := shellcheckRCFiles(filepath.Dir(ctx.Path))
	if err != nil {
		return nil, err
	}
	var inputs [][]byte
	for _, rc := range rcFiles {
		data, err := readIfExists(rc)
		if err != nil {
			return nil, err
		}
		inputs = append(inputs, []byte(rc), data)
	}
	seen := map[string]bool{ctx.Path: true}
	var follow func(path string, content []byte, depth int) error
	follow = func(path string, content []byte, depth int) error {
		if depth == maxSourceDepth {
			return nil
		}
		for _, m := range sourceLine.FindAllSubmatch(content, -1) {
			name := string(m[1]) + string(m[2])
			for _, candidate := range []string{filepath.Join(filepath.Dir(path), name), filepath.Join(ctx.ProjectRoot, name)} {
				if filepath.IsAbs(name) {
					candidate = name
				}
				if seen[candidate] {
					continue
				}
				seen[candidate] = true
				data, err := readIfExists(candidate)
				if err != nil {
					return err
				}
				inputs = append(inputs, []byte(candidate), data)
				if data != nil {
					if err := follow(candidate, data, depth+1); err != nil {
						return err
					}
				}
			}
		}
		return nil
	}
	if err := follow(ctx.Path, ctx.Content, 0); err != nil {
		return nil, err
	}
	return inputs, nil
}

// shellcheckRCFiles are the configuration files shellcheck may read for a
// script in dir: .shellcheckrc in dir and every directory above it, and
// the user's own.
func shellcheckRCFiles(dir string) ([]string, error) {
	var files []string
	for {
		files = append(files, filepath.Join(dir, ".shellcheckrc"))
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("locate the user's .shellcheckrc: %w", err)
	}
	config, err := os.UserConfigDir()
	if err != nil {
		return nil, fmt.Errorf("locate the user's shellcheckrc: %w", err)
	}
	return append(files, filepath.Join(home, ".shellcheckrc"), filepath.Join(config, "shellcheckrc")), nil
}

// readIfExists returns a file's content, or nil when there is no such
// file: a missing file is part of the input too.
func readIfExists(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("look up a file shellcheck reads: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, nil
	}
	return os.ReadFile(path)
}
