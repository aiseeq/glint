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
