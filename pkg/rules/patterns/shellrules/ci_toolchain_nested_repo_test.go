package shellrules

import (
	"maps"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patterntest"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

const ciOldImage = `jobs:
  test:
    runs-on: ubuntu-latest
    container:
      image: golang:1.21
    steps:
      - run: cd backend && go test ./...
`

// ciToolchainFindings writes a repository with a CI config at its top, no
// go.mod there, and the module backend/ on go 1.23, adds the files, and runs
// the rule on the CI config.
func ciToolchainFindings(t *testing.T, rule *CIToolchainImageOlderThanGoModRule, files map[string]string) []string {
	t.Helper()
	root := t.TempDir()
	all := map[string]string{
		".git/HEAD":                "ref: refs/heads/main\n",
		"backend/go.mod":           "module example.com/app\n\ngo 1.23\n",
		".github/workflows/ci.yml": ciOldImage,
	}
	maps.Copy(all, files)
	for name, content := range all {
		path := filepath.Join(root, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
	}
	ci := filepath.Join(root, ".github/workflows/ci.yml")
	ctx, err := core.NewFileContextChecked(ci, root, []byte(ciOldImage), core.DefaultConfig())
	require.NoError(t, err)
	return patterntest.FoundLines(rule.AnalyzeFile(ctx))
}

// A clone of another repository at the top (its own .git, a go.mod on an
// older go) is not a module the pipeline builds: the run does not walk it,
// and the pipeline's module stays the single one below the top.
func TestCIToolchainImageIgnoresModuleOfNestedRepository(t *testing.T) {
	got := ciToolchainFindings(t, NewCIToolchainImageOlderThanGoModRule(), map[string]string{
		"lib/.git/HEAD": "ref: refs/heads/main\n",
		"lib/go.mod":    "module example.com/lib\n\ngo 1.20\n",
	})
	assert.Equal(t, []string{".github/workflows/ci.yml:5"}, got)
}

// A second module of the project at the top leaves the pipeline's module
// unknown, and the rule silent, as before.
func TestCIToolchainImageSilentWithTwoModulesOfProject(t *testing.T) {
	got := ciToolchainFindings(t, NewCIToolchainImageOlderThanGoModRule(), map[string]string{
		"lib/go.mod": "module example.com/lib\n\ngo 1.20\n",
	})
	assert.Empty(t, got)
}

// A module in a directory git ignores is not the project's while .gitignore
// is respected; with settings.respect_gitignore off the run walks it, and
// two modules leave the pipeline's one unknown.
func TestCIToolchainImageIgnoredModuleCountsOnlyWithoutRespectGitignore(t *testing.T) {
	files := map[string]string{
		".gitignore":     "/scratch/\n",
		"scratch/go.mod": "module example.com/scratch\n\ngo 1.20\n",
	}
	assert.Equal(t, []string{".github/workflows/ci.yml:5"}, ciToolchainFindings(t, NewCIToolchainImageOlderThanGoModRule(), files))
	assert.Empty(t, ciToolchainFindings(t, rulestest.WithoutGitignore(t, NewCIToolchainImageOlderThanGoModRule()), files))
}
