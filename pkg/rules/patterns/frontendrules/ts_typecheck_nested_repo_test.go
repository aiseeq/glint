package frontendrules

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

const typecheckPackage = `{"scripts": {"typecheck": "tsc --noEmit"}}`

func checkedTSConfigPaths(t *testing.T, root string, files map[string]string) []string {
	t.Helper()
	for name, content := range files {
		path := filepath.Join(root, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
	}
	scopes, err := checkedTSConfigs(root, true)
	require.NoError(t, err)
	var paths []string
	for _, scope := range scopes {
		rel, err := filepath.Rel(root, scope.path)
		require.NoError(t, err)
		paths = append(paths, filepath.ToSlash(rel))
	}
	return paths
}

// A checkout of another repository below the project (a submodule, a cloned
// library) has a name without a dot; its package.json type-checks its own
// code, not the project's, and the run does not walk it.
func TestCheckedTSConfigsLeaveOutNestedRepository(t *testing.T) {
	t.Parallel()
	got := checkedTSConfigPaths(t, t.TempDir(), map[string]string{
		".git/HEAD":                       "ref: refs/heads/main\n",
		"web/package.json":                typecheckPackage,
		"web/tsconfig.json":               "{}",
		"third_party/lib/.git":            "gitdir: /elsewhere/.git/modules/lib\n",
		"third_party/lib/package.json":    typecheckPackage,
		"third_party/lib/tsconfig.json":   "{}",
		"third_party/plain/package.json":  typecheckPackage,
		"third_party/plain/tsconfig.json": "{}",
	})
	assert.Equal(t, []string{"third_party/plain/tsconfig.json", "web/tsconfig.json"}, got)
}

// A package.json in a directory git ignores is the project's only when the
// run walks that directory: with settings.respect_gitignore off.
func TestCheckedTSConfigsReadIgnoredDirectoryOnlyWithoutRespectGitignore(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	files := map[string]string{
		".git/HEAD":               "ref: refs/heads/main\n",
		".gitignore":              "/generated/\n",
		"web/package.json":        typecheckPackage,
		"web/tsconfig.json":       "{}",
		"generated/package.json":  typecheckPackage,
		"generated/tsconfig.json": "{}",
	}
	assert.Equal(t, []string{"web/tsconfig.json"}, checkedTSConfigPaths(t, root, files))
	scopes, err := checkedTSConfigs(root, false)
	require.NoError(t, err)
	require.Len(t, scopes, 2)
	assert.Equal(t, filepath.Join(root, "generated/tsconfig.json"), scopes[0].path)
}

// gen/package.json type-checks gen/ by tsconfig.gen.json; gen/ is ignored,
// and the root's tsconfig.json is the nearest one above its files.
var ignoredCheckProject = map[string]string{
	".git/HEAD":             "ref: refs/heads/main\n",
	".gitignore":            "/gen/\n",
	"tsconfig.json":         "{}",
	"gen/package.json":      `{"scripts": {"typecheck": "tsc -p tsconfig.gen.json"}}`,
	"gen/tsconfig.gen.json": "{}",
	"gen/a.ts":              "export const a = 1\n",
}

// The tsconfigs a run reads once per root are kept per
// settings.respect_gitignore, and a file of the ignored directory is
// type-checked by its package.json only when the run walks that directory.
func TestTSFileTypeCheckedFollowsRespectGitignore(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	checkedTSConfigPaths(t, root, ignoredCheckProject)
	file := filepath.Join(root, "gen/a.ts")
	checked, err := tsFileTypeChecked(root, file, true)
	require.NoError(t, err)
	assert.False(t, checked)
	checked, err = tsFileTypeChecked(root, file, false)
	require.NoError(t, err)
	assert.True(t, checked)
}

func TestTSFileTypeCheckedRespectsSkipDirs(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	files := map[string]string{
		".git/HEAD":               "ref: refs/heads/main\n",
		"generated/package.json":  typecheckPackage,
		"generated/tsconfig.json": "{}",
		"generated/src/probe.ts":  "export const probe = 1\n",
	}
	checkedTSConfigPaths(t, root, files)
	checked, err := tsFileTypeChecked(root, filepath.Join(root, "generated/src/probe.ts"), true, "generated")
	require.NoError(t, err)
	assert.False(t, checked)
}

// The tsc rule of a run without respect_gitignore checks the file of the
// ignored directory by the tsconfig its package.json names; respecting
// .gitignore, by the nearest tsconfig.json above it, as an editor does.
func TestTscPlanFollowsRespectGitignore(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	checkedTSConfigPaths(t, root, ignoredCheckProject)
	file := filepath.Join(root, "gen/a.ts")
	contexts := []*core.FileContext{core.NewFileContext(file, root, []byte(ignoredCheckProject["gen/a.ts"]), core.DefaultConfig())}
	configs := func(rule *TscRule) []string {
		_ = rule.CheckTools(contexts) // the plan is made before the tools are looked for
		require.NoError(t, rule.planErr)
		var names []string
		for _, program := range rule.plan.programs {
			names = append(names, program.config)
		}
		return names
	}
	assert.Equal(t, []string{filepath.Join(root, "tsconfig.json")}, configs(NewTscRule()))
	assert.Equal(t, []string{filepath.Join(root, "gen/tsconfig.gen.json")}, configs(rulestest.WithoutGitignore(t, NewTscRule())))
}

// Run in a linked worktree of the project, its own package.json counts.
func TestCheckedTSConfigsReadWorktreeRoot(t *testing.T) {
	t.Parallel()
	got := checkedTSConfigPaths(t, t.TempDir(), map[string]string{
		".git":              "gitdir: /elsewhere/.git/worktrees/wt\n",
		"web/package.json":  typecheckPackage,
		"web/tsconfig.json": "{}",
	})
	assert.Equal(t, []string{"web/tsconfig.json"}, got)
}
