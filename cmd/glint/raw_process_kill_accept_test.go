package main

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const rawKillAkitProc = `package proc

import (
	"syscall"
	"time"
)

type StopResult struct{ Killed int }

func StopChild(pid int, grace time.Duration, request func() error) (StopResult, error) {
	if err := request(); err != nil {
		return StopResult{}, err
	}
	return StopResult{}, syscall.Kill(pid, syscall.SIGKILL)
}

func StopFromShell(pid int, grace time.Duration, sig syscall.Signal) (StopResult, error) {
	return StopResult{}, syscall.Kill(pid, sig)
}
`

const rawKillAcceptGo = `package check

import (
	"context"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/aiseeq/akit/proc"
	"golang.org/x/sys/unix"
)

func kills(cmd *exec.Cmd, p *os.Process, pid int, s os.Signal) {
	_ = cmd.Process.Kill() // WANT
	_ = p.Kill() // WANT
	_ = p.Signal(syscall.SIGTERM) // WANT
	_ = p.Signal(os.Interrupt) // WANT
	_ = p.Signal(os.Kill) // WANT
	_ = p.Signal(s) // WANT
	sig := syscall.SIGTERM
	_ = p.Signal(sig) // WANT
	_ = syscall.Kill(pid, syscall.SIGKILL) // WANT
	_ = syscall.Kill(pid, 15) // WANT
	_ = unix.Kill(pid, unix.SIGTERM) // WANT
	_ = syscall.Tgkill(pid, pid, syscall.SIGTERM) // WANT
	_ = syscall.Kill(-pid, syscall.SIGTERM) // WANT
	if q, err := os.FindProcess(pid); err == nil {
		_ = q.Kill() // WANT
	}
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) } // WANT
	go func() { _ = p.Signal(syscall.SIGINT) }() // WANT
	defer p.Kill() // WANT
}

func allowed(cmd *exec.Cmd, p *os.Process, pid int) {
	_ = p.Signal(syscall.Signal(0))
	_ = syscall.Kill(pid, 0)
	_ = unix.Kill(pid, 0)
	_ = p.Signal(syscall.SIGHUP)
	_ = p.Signal(syscall.SIGUSR1)
	_ = syscall.Kill(pid, syscall.SIGUSR2)
	_ = syscall.Kill(pid, syscall.SIGSTOP)
	_ = syscall.Kill(pid, syscall.SIGCONT)
	_ = p.Signal(syscall.SIGCHLD)
	_ = p.Signal(syscall.SIGWINCH)
	_ = syscall.Kill(os.Getpid(), syscall.SIGTERM)
	_ = syscall.Kill(syscall.Getpid(), syscall.SIGKILL)
	if self, err := os.FindProcess(os.Getpid()); err == nil {
		_ = self.Signal(syscall.SIGTERM)
	}
	_, _ = proc.StopChild(pid, time.Second, func() error { return cmd.Process.Signal(syscall.SIGTERM) })
	_, _ = proc.StopChild(pid, time.Second, func() error {
		return syscall.Kill(pid, syscall.SIGINT)
	})
	_, _ = proc.StopFromShell(pid, time.Second, syscall.SIGTERM)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = exec.CommandContext(ctx, "sleep", "1").Run()
}

// The implicit targets belong to signal-implicit-target: no second finding here.
func implicit(p *os.Process) {
	_ = syscall.Kill(0, syscall.SIGTERM)
	_ = syscall.Kill(-1, syscall.SIGKILL)
	_ = syscall.Kill(os.Getppid(), syscall.SIGTERM)
	if parent, err := os.FindProcess(os.Getppid()); err == nil {
		_ = parent.Kill()
	}
}
`

const rawKillAcceptGoTest = `package check

import (
	"os/exec"
	"testing"
)

func TestChild(t *testing.T) {
	cmd := exec.Command("sleep", "5")
	_ = cmd.Start()
	_ = cmd.Process.Kill() // WANT
	_ = cmd.Wait()
}
`

func rawKillRoot(t *testing.T, files map[string]string) []string {
	t.Helper()
	root := t.TempDir()
	var want []string
	for name, content := range files {
		path := filepath.Join(root, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
		for i, line := range strings.Split(content, "\n") {
			if strings.Contains(line, "WANT") {
				want = append(want, fmt.Sprintf("%s:%d", name, i+1))
			}
		}
	}
	findings, _ := analyzeWithRules(t, root, nil, "raw-process-kill")
	got := foundAt(findings)
	slices.Sort(got)
	slices.Sort(want)
	assert.Equal(t, want, got)
	return got
}

func TestRawProcessKillAcceptance(t *testing.T) {
	rawKillRoot(t, map[string]string{
		"go.mod": "module example.com/check\n\ngo 1.24\n\nrequire (\n\tgithub.com/aiseeq/akit v0.0.0\n\tgolang.org/x/sys v0.0.0\n)\n\n" +
			"replace github.com/aiseeq/akit => ./akit\n\nreplace golang.org/x/sys => ./xsys\n",
		".glint.yaml":       "version: 1\n",
		"akit/go.mod":       "module github.com/aiseeq/akit\n\ngo 1.24\n",
		"akit/proc/stop.go": rawKillAkitProc,
		"xsys/go.mod":       "module golang.org/x/sys\n\ngo 1.24\n",
		"xsys/unix/unix.go": "package unix\n\nimport \"syscall\"\n\nconst SIGTERM = syscall.SIGTERM\n\nfunc Kill(pid int, sig syscall.Signal) error { return nil }\n",
		"check.go":          rawKillAcceptGo,
		"check_test.go":     rawKillAcceptGoTest,
	})
}

// The helper itself sends the signals: its package is not a finding.
func TestRawProcessKillHelperPackageIsExempt(t *testing.T) {
	rawKillRoot(t, map[string]string{
		"go.mod":        "module github.com/aiseeq/akit\n\ngo 1.24\n",
		".glint.yaml":   "version: 1\n",
		"proc/stop.go":  rawKillAkitProc,
		"other/kill.go": "package other\n\nimport \"syscall\"\n\nfunc Stop(pid int) error { return syscall.Kill(pid, syscall.SIGTERM) } // WANT\n",
	})
}
