// Package hist holds what the history tools share: git and glint runs and
// command lines whose flags may follow the positional arguments.
package hist

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os/exec"
	"strings"

	"github.com/aiseeq/glint/pkg/output"
)

// Git runs git in dir and returns its standard output; a failure carries
// the command and git's own message.
func Git(dir string, args ...string) (string, error) {
	out, err := Run(exec.Command("git", append([]string{"-C", dir}, args...)...))
	return string(out), err
}

// Run runs cmd and returns its standard output; a failure carries the
// command and the start of its standard error.
func Run(cmd *exec.Cmd) ([]byte, error) {
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return out, fmt.Errorf("%s: %w: %s", strings.Join(cmd.Args, " "), err, Head(strings.TrimSpace(stderr.String()), 300))
	}
	return out, nil
}

// Head returns at most n first characters of s.
func Head(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}

// Tail returns at most n last characters of s.
func Tail(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[len(r)-n:])
}

// Check is one glint run: its exit status, its output and the report when
// the standard output is one.
type Check struct {
	Report *output.JSONReport
	Exit   int
	Stdout string
	Stderr string
}

// RunCheck runs the glint binary in dir with args. A run that ends with a
// status is a Check whatever the status (glint exits 1 on findings, and a
// broken tree makes it fail); an error means glint did not run at all.
func RunCheck(glint, dir string, args ...string) (Check, error) {
	cmd := exec.Command(glint, args...)
	cmd.Dir = dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	var exit *exec.ExitError
	if err != nil && !errors.As(err, &exit) {
		return Check{}, fmt.Errorf("run %s in %s: %w", glint, dir, err)
	}
	c := Check{Exit: cmd.ProcessState.ExitCode(), Stdout: stdout.String(), Stderr: stderr.String()}
	var report output.JSONReport
	if json.Unmarshal(stdout.Bytes(), &report) == nil {
		c.Report = &report
	}
	return c, nil
}

// WriteLine writes v as one JSON line, with <, > and & as they are.
func WriteLine(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

// Parse parses args with fs, letting flags come before, between and after
// the positional arguments as the tools' usage lines show them, and returns
// the positional ones.
func Parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return positional, nil
		}
		positional = append(positional, args[0])
		args = args[1:]
	}
}
