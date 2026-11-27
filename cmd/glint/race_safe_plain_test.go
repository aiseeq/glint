//go:build !race

package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/fix"
)

// These CLI checks parse commands or render help and metadata. They do not
// run check analysis in the test process or in a child whose status they read.

func TestMainMissingDirectoryIsUsageError(t *testing.T) {
	base := t.TempDir()
	t.Chdir(base)
	cmd := mainSubprocess(t, []string{"-C", "missing", "rules"})
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("missing -C directory succeeded: %s", output)
	}
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != exitUsage {
		t.Fatalf("got exit error %v, want usage exit code 2 (output: %s)", err, output)
	}
	if !strings.Contains(string(output), `-C "missing"`) {
		t.Fatalf("error does not name missing -C directory: %s", output)
	}
}

// A path where the command goes, as in go vet ./..., is a call of check
// without its name: the error says how to write it.
func TestMainPathWithoutCommandSuggestsCheck(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := os.Mkdir("internal", 0o755); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"./..."}, {"."}, {"internal"}, {"/nowhere/..."}, {"-C", ".", "./...", "internal"}, {"./...", "-r", "ignored-error"}} {
		output, err := mainSubprocess(t, args).CombinedOutput()
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != exitUsage {
			t.Fatalf("glint %v: got exit error %v, want usage exit code 2 (output: %s)", args, err, output)
		}
		want := "glint check " + strings.Join(args, " ")
		if !strings.Contains(string(output), want) {
			t.Fatalf("glint %v: error does not suggest %q: %s", args, want, output)
		}
	}
}

func TestMainUnknownCommandSuggestsSimilarOne(t *testing.T) {
	output, err := mainSubprocess(t, []string{"chek"}).CombinedOutput()
	if err == nil {
		t.Fatalf("unknown command succeeded: %s", output)
	}
	if !strings.Contains(string(output), `unknown command "chek"`) || !strings.Contains(string(output), "\tcheck") {
		t.Fatalf("error does not name the command and suggest check: %s", output)
	}
	if strings.Contains(string(output), "glint check chek") {
		t.Fatalf("a word that is not a path got the path hint: %s", output)
	}
}

func TestMainWithoutArgumentsPrintsHelp(t *testing.T) {
	output, err := mainSubprocess(t, nil).CombinedOutput()
	if err != nil {
		t.Fatalf("glint without arguments failed: %v (output: %s)", err, output)
	}
	if !strings.Contains(string(output), "Available Commands:") {
		t.Fatalf("glint without arguments does not print help: %s", output)
	}
}

// A run takes four threads unless told otherwise: the machine is shared with
// other jobs, and every CPU at once slows them down for little gain.
func TestJobsDefaultsToFourAndRejectsZero(t *testing.T) {
	for _, cmd := range []*cobra.Command{checkCmd, fixCmd} {
		if def := cmd.Flags().Lookup("jobs").DefValue; def != "4" {
			t.Fatalf("%s --jobs default = %s, want 4", cmd.Name(), def)
		}
	}
	prev := flagJobs
	t.Cleanup(func() { flagJobs = prev; runtime.GOMAXPROCS(runtime.NumCPU()) })
	flagJobs = 0
	if err := applyJobs(); err == nil {
		t.Fatal("--jobs 0 must be an error")
	}
	flagJobs = 3
	if err := applyJobs(); err != nil || runtime.GOMAXPROCS(0) != 3 {
		t.Fatalf("--jobs 3 must set GOMAXPROCS to 3, got %d, %v", runtime.GOMAXPROCS(0), err)
	}
}

// glint fix --help names every registered fixer: the list is written by hand
// and fell behind twice.
func TestFixHelpNamesEveryFixer(t *testing.T) {
	for name := range fix.DefaultRegistry.All() {
		if !strings.Contains(fixCmd.Long, name) {
			t.Errorf("glint fix --help does not name the %s fixer", name)
		}
	}
}

func TestRulesCommandShowsSettings(t *testing.T) {
	list, err := captureRuleOutput(t, func() error { return runRules(nil, nil) })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(list, "settings:") || !strings.Contains(list, "period_modules (string list)") {
		t.Fatalf("settings absent from list:\n%s", list)
	}
	for _, name := range []string{"ts-period-boundary-by-hand", "sql-concept-table-outside-owner"} {
		card, err := captureRuleOutput(t, func() error { return showRule(name) })
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(card, "YAML (.glint.yaml):") || !strings.Contains(card, "settings:") {
			t.Errorf("%s card lacks settings YAML:\n%s", name, card)
		}
		if name == "ts-period-boundary-by-hand" {
			block := card[strings.Index(card, "categories:"):]
			path := filepath.Join(t.TempDir(), ".glint.yaml")
			if err := os.WriteFile(path, []byte(block), 0600); err != nil {
				t.Fatal(err)
			}
			cfg, err := core.LoadConfig(path)
			if err != nil {
				t.Fatalf("card YAML does not load: %v\n%s", err, block)
			}
			if _, ok := cfg.Categories["patterns"].Rules[name].Settings["period_modules"]; !ok {
				t.Fatalf("card YAML lost period_modules: %+v", cfg.Categories["patterns"].Rules[name])
			}
		}
	}
}

func TestRulesCommandUnknownRule(t *testing.T) {
	err := showRule("clock-bypas")
	if err == nil || !strings.Contains(err.Error(), "clock-bypass") {
		t.Fatalf("expected unknown rule suggestion, got %v", err)
	}
}
