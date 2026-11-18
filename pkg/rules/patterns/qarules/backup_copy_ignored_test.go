package qarules

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/stretchr/testify/require"
)

func TestBackupCopyOfIgnoredFile(t *testing.T) {
	root := t.TempDir()
	git(t, root, "init", "-q")
	write := func(rel, content string) {
		t.Helper()
		path := filepath.Join(root, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	}
	write(".gitignore", "x.json\nmissing.json\n*.local.yaml\nsecrets/\n")
	write("x.json.bak-1118", "copy")
	write("app.local.yaml.orig", "copy")
	write("missing.json~", "copy")
	write("README.md.bak", "copy")
	write("ordinary.txt", "ordinary")
	write("sub/.gitignore", "config.yaml\n")
	write("sub/config.yaml.bak", "copy")
	write("x.json.bak", "committed copy")
	git(t, root, "add", ".gitignore", "x.json.bak")
	git(t, root, "-c", "user.email=test@example.invalid", "-c", "user.name=test", "commit", "-qm", "backup copy")

	rule := NewBackupCopyOfIgnoredFileRule()
	for _, rel := range []string{"x.json.bak", "x.json.bak-1118", "app.local.yaml.orig", "app.local.yaml.orig.old", "x.json~"} {
		require.True(t, rule.RequiresFile(rel), rel)
		require.True(t, rule.RequiresAdditionalFile(rel), rel)
	}
	require.False(t, rule.RequiresFile("README.md"))
	require.False(t, rule.RequiresFile("README.md.bakwhatever"))
	for rel, original := range map[string]string{
		"x.json.bak-1118": "x.json", "app.local.yaml.orig": "app.local.yaml",
		"missing.json~": "missing.json", "sub/config.yaml.bak": "sub/config.yaml",
		"x.json.bak": "x.json",
	} {
		t.Run(rel, func(t *testing.T) {
			ctx := core.NewFileContext(filepath.Join(root, filepath.FromSlash(rel)), root, nil, &core.Config{})
			got := rule.AnalyzeFile(ctx)
			require.Len(t, got, 1)
			require.Contains(t, got[0].Message, original)
			require.Contains(t, got[0].Suggestion, "scratchpad")
		})
	}
	for _, rel := range []string{"README.md.bak", "ordinary.txt"} {
		t.Run(rel, func(t *testing.T) {
			ctx := core.NewFileContext(filepath.Join(root, rel), root, nil, &core.Config{})
			require.Empty(t, rule.AnalyzeFile(ctx))
		})
	}
}

func git(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "%s: %s", cmd.Args, output)
}
