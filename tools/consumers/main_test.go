package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/aiseeq/glint/pkg/output"
)

func TestReadConfigExpandsHomeAndRequiresRoot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "consumers.txt")
	if err := os.WriteFile(path, []byte("# roots\nroot ~/synthetic\nskip frozen\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := readConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	home, _ := os.UserHomeDir()
	want, _ := filepath.Abs(filepath.Join(home, "synthetic"))
	if !reflect.DeepEqual(c.roots, []string{want}) || !c.skips["frozen"] {
		t.Fatalf("config = %+v", c)
	}
	if err := os.WriteFile(path, []byte("skip frozen\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readConfig(path); err == nil {
		t.Fatal("expected missing root error")
	}
}

func TestFindProjectsHonorsDepthAndIgnoredDirectories(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{"alpha", "group/tool", "deep/level/third", "too/deep/third/fourth", "vendor/hidden", ".hidden/hidden", "node_modules/hidden"} {
		path := filepath.Join(root, dir)
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, ".glint.yaml"), []byte("version: 1\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got, err := findProjects(config{roots: []string{root}, skips: map[string]bool{}})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{filepath.Join(root, "alpha"), filepath.Join(root, "deep/level/third"), filepath.Join(root, "group/tool")}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("projects = %v, want %v", got, want)
	}
}

func TestFindProjectsSkipsLinkedWorktrees(t *testing.T) {
	root := t.TempDir()
	for dir, gitEntry := range map[string]string{"main": "dir", "main-old": "file"} {
		path := filepath.Join(root, dir)
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, ".glint.yaml"), []byte("version: 1\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if gitEntry == "dir" {
			if err := os.Mkdir(filepath.Join(path, ".git"), 0o755); err != nil {
				t.Fatal(err)
			}
			continue
		}
		link := []byte("gitdir: " + filepath.Join(root, "main/.git/worktrees/main-old") + "\n")
		if err := os.WriteFile(filepath.Join(path, ".git"), link, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got, err := findProjects(config{roots: []string{root}, skips: map[string]bool{}})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{filepath.Join(root, "main")}; !reflect.DeepEqual(got, want) {
		t.Fatalf("projects = %v, want %v: a linked worktree repeats its repository's findings", got, want)
	}
}

func TestDifferenceTreatsFindingsAsMultisetAndIgnoresOtherFields(t *testing.T) {
	old := []output.JSONIssue{{Rule: "r", File: "a.go", Line: 1, Message: "same", Severity: "low"}, {Rule: "r", File: "a.go", Line: 1, Message: "same"}}
	newIssues := []output.JSONIssue{{Rule: "r", File: "a.go", Line: 1, Message: "same", Severity: "high"}, {Rule: "x", File: "b.go", Line: 2, Message: "new"}}
	added, removed := difference(old, newIssues)
	if len(added) != 1 || added[0].Rule != "x" || len(removed) != 1 || removed[0].Rule != "r" {
		t.Fatalf("difference = +%v -%v", added, removed)
	}
}

func TestOldBinaryWithoutTheNewRuleCountsAsNoFindings(t *testing.T) {
	root := t.TempDir()
	project := filepath.Join(root, "alpha")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, ".glint.yaml"), []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := filepath.Join(root, "old")
	oldScript := "#!/bin/sh\necho 'Error: unknown rule \"fresh-rule\"' >&2\nexit 1\n"
	newer := filepath.Join(root, "new")
	newScript := "#!/bin/sh\necho '{\"issues\":[{\"rule\":\"fresh-rule\",\"file\":\"a.go\",\"line\":3,\"message\":\"m\"}]}'\nexit 1\n"
	for path, script := range map[string]string{old: oldScript, newer: newScript} {
		if err := os.WriteFile(path, []byte(script), 0o700); err != nil { //nolint:gosec // an executable test double
			t.Fatal(err)
		}
	}
	cfg := filepath.Join(root, "consumers.txt")
	if err := os.WriteFile(cfg, []byte("root "+root+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr strings.Builder
	code := run([]string{"-config", cfg, "-old", old, "-new", newer, "-r", "fresh-rule"}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stdout.String(), "+ a.go:3 fresh-rule") {
		t.Fatalf("code %d, stdout %q, stderr %q: want the new rule's finding as added", code, stdout.String(), stderr.String())
	}
}
