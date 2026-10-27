package main

import (
	"os"
	"path/filepath"
	"reflect"
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

func TestDifferenceTreatsFindingsAsMultisetAndIgnoresOtherFields(t *testing.T) {
	old := []output.JSONIssue{{Rule: "r", File: "a.go", Line: 1, Message: "same", Severity: "low"}, {Rule: "r", File: "a.go", Line: 1, Message: "same"}}
	newIssues := []output.JSONIssue{{Rule: "r", File: "a.go", Line: 1, Message: "same", Severity: "high"}, {Rule: "x", File: "b.go", Line: 2, Message: "new"}}
	added, removed := difference(old, newIssues)
	if len(added) != 1 || added[0].Rule != "x" || len(removed) != 1 || removed[0].Rule != "r" {
		t.Fatalf("difference = +%v -%v", added, removed)
	}
}
