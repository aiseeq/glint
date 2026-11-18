package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestInstructionSizeCommand(t *testing.T) {
	root := t.TempDir()
	write := func(name, content string) {
		t.Helper()
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	write(".glint.yaml", "version: 1\ncategories:\n  documentation:\n    rules:\n      instruction-size:\n        settings:\n          max_bytes: 2002\n")
	write("CLAUDE.md", strings.Repeat("a", 1001))
	write(".claude/rules/go.md", strings.Repeat("a", 2457))
	write("skills/demo/SKILL.md", strings.Repeat("я", 6000))
	write("README.md", strings.Repeat("a", 5000))
	t.Chdir(root)
	cmd := &cobra.Command{}
	var out bytes.Buffer
	cmd.SetOut(&out)
	if err := runInstructionSize(cmd, nil); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	for _, want := range []string{"CLAUDE.md  1001 bytes  50% of 2002", ".claude/rules/go.md  2457 bytes  122% of 2002", "skills/demo/SKILL.md  6000 characters  50% of 12000"} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "README.md") {
		t.Errorf("non-instruction file included:\n%s", got)
	}
	out.Reset()
	if err := runInstructionSize(cmd, []string{"skills/demo/SKILL.md"}); err != nil {
		t.Fatal(err)
	}
	if lines := strings.Split(strings.TrimSpace(out.String()), "\n"); len(lines) != 1 || !strings.Contains(lines[0], "6000 characters") {
		t.Fatalf("argument output = %q", out.String())
	}
}

func TestInstructionSizeUsesConfigNearestToEachArgument(t *testing.T) {
	base := t.TempDir()
	configured := filepath.Join(base, "configured")
	other := filepath.Join(base, "other")
	configuredFile := filepath.Join(configured, "CLAUDE.md")
	otherFile := filepath.Join(other, "CLAUDE.md")
	write := func(path, content string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(configured, ".glint.yaml"), "version: 1\ncategories:\n  documentation:\n    rules:\n      instruction-size:\n        settings:\n          max_bytes: 4000\n")
	write(configuredFile, strings.Repeat("a", 1001))
	write(otherFile, strings.Repeat("a", 2000))
	if err := os.MkdirAll(filepath.Join(configured, "sub", "deep"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(base, "neighbor"), 0755); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name, cwd, arg, want string
	}{
		{"project root", configured, configuredFile, "1001 bytes  25% of 4000"},
		{"subdirectory", filepath.Join(configured, "sub", "deep"), configuredFile, "1001 bytes  25% of 4000"},
		{"neighbor tree", filepath.Join(base, "neighbor"), configuredFile, "1001 bytes  25% of 4000"},
		{"absolute path", base, configuredFile, "1001 bytes  25% of 4000"},
		{"no config despite configured cwd", configured, otherFile, "2000 bytes  8% of 24576"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Chdir(tc.cwd)
			cmd := &cobra.Command{}
			var out bytes.Buffer
			cmd.SetOut(&out)
			if err := runInstructionSize(cmd, []string{tc.arg}); err != nil {
				t.Fatalf("runInstructionSize: %v", err)
			}
			if !strings.Contains(out.String(), tc.want) {
				t.Fatalf("output %q missing %q", out.String(), tc.want)
			}
		})
	}
}

func TestInstructionSizeArgumentsUseTheirOwnTrees(t *testing.T) {
	base := t.TempDir()
	configured := filepath.Join(base, "configured")
	plain := filepath.Join(base, "plain")
	if err := os.MkdirAll(configured, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(plain, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configured, ".glint.yaml"), []byte("version: 1\ncategories:\n  documentation:\n    rules:\n      instruction-size:\n        settings:\n          max_bytes: 4000\n"), 0644); err != nil {
		t.Fatal(err)
	}
	configuredFile := filepath.Join(configured, "CLAUDE.md")
	plainFile := filepath.Join(plain, "CLAUDE.md")
	for path, size := range map[string]int{configuredFile: 1001, plainFile: 2000} {
		if err := os.WriteFile(path, []byte(strings.Repeat("a", size)), 0644); err != nil {
			t.Fatal(err)
		}
	}
	t.Chdir(base)
	cmd := &cobra.Command{}
	var out bytes.Buffer
	cmd.SetOut(&out)
	if err := runInstructionSize(cmd, []string{configuredFile, plainFile}); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], "25% of 4000") || !strings.Contains(lines[1], "8% of 24576") {
		t.Fatalf("output = %q", out.String())
	}
}
