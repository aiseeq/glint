package core

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
)

func sortedWalkPaths(t *testing.T, root string, cfg *Config) []string {
	t.Helper()
	paths := walkPaths(t, root, cfg)
	sort.Strings(paths)
	return paths
}

// Генерируемые файлы, перечисленные в .gitignore, не должны попадать в анализ:
// отчёт тест-раннера с minified-бандлами внутри игнорируемого каталога даёт
// десятки ложных находок на чужом коде.
func TestWalkerRespectsGitignore(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		".gitignore":          "generated/\n*.gen.go\n!keep.gen.go\n",
		"main.go":             "package main\n",
		"a.gen.go":            "package main\n",
		"keep.gen.go":         "package main\n",
		"generated/bundle.js": "var x = 1\n",
		"sub/.gitignore":      "local.ts\n",
		"sub/local.ts":        "export {}\n",
		"sub/ok.ts":           "export {}\n",
	})

	paths := sortedWalkPaths(t, root, &Config{})
	require.Equal(t, []string{"keep.gen.go", "main.go", "sub/ok.ts"}, paths)
}

// glint часто запускают на подкаталоге репозитория (glint check backend
// frontend), а .gitignore с паттерном вида /frontend/report/ лежит в корне
// репы. Git применяет ignore-файлы всех родителей до корня — walker обязан
// делать то же.
func TestWalkerRespectsAncestorGitignoreFromRepoRoot(t *testing.T) {
	repo := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(repo, ".git"), 0o755))
	writeTree(t, repo, map[string]string{
		".gitignore":          "/front/report/\n",
		"front/report/big.js": "var x = 1\n",
		"front/src/app.ts":    "export {}\n",
	})

	paths := sortedWalkPaths(t, filepath.Join(repo, "front"), &Config{})
	require.Equal(t, []string{"src/app.ts"}, paths)
}

// respect_gitignore: false возвращает старое поведение — анализировать всё.
func TestWalkerGitignoreCanBeDisabled(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		".gitignore": "skipped.go\n",
		"skipped.go": "package main\n",
		"main.go":    "package main\n",
	})

	disabled := false
	cfg := &Config{Settings: SettingsConfig{RespectGitignore: &disabled}}
	paths := sortedWalkPaths(t, root, cfg)
	require.Equal(t, []string{"main.go", "skipped.go"}, paths)
}

// Локальные исключения клона живут в .git/info/exclude, а не в .gitignore:
// так прячут, например, git worktree агентов внутри репозитория. Без учёта
// exclude glint анализирует каждую копию репы и находит тысячи дублей между
// ними. Исключённый каталог отрезается целиком, а не пофайлово; отрицание из
// .gitignore сильнее exclude, как в git.
func TestWalkerRespectsGitInfoExclude(t *testing.T) {
	repo := t.TempDir()
	writeTree(t, repo, map[string]string{
		".git/info/exclude":            "# local\n.agents/worktrees/\n*.log.go\n",
		".gitignore":                   "!keep.log.go\n",
		"main.go":                      "package main\n",
		"debug.log.go":                 "package main\n",
		"keep.log.go":                  "package main\n",
		".agents/worktrees/a/main.go":  "package main\n",
		".agents/worktrees/a/lib.ts":   "export {}\n",
		".agents/settings/settings.go": "package settings\n",
	})

	w := NewWalker(repo, &Config{})
	contexts, errs := w.WalkSync()
	require.Empty(t, errs)
	paths := make([]string, 0, len(contexts))
	for _, ctx := range contexts {
		paths = append(paths, filepath.ToSlash(ctx.RelPath))
	}
	sort.Strings(paths)
	require.Equal(t, []string{".agents/settings/settings.go", "keep.log.go", "main.go"}, paths)
	// Только debug.log.go отсеян пофайлово; каталог worktree отрезан целиком.
	require.Equal(t, 1, w.Stats().SkippedFiles)
}

// В самом worktree .git — файл со ссылкой на свой git-dir, а info/exclude
// общий для всех worktree и лежит в основном git-dir (commondir).
func TestWalkerRespectsGitInfoExcludeFromWorktree(t *testing.T) {
	base := t.TempDir()
	writeTree(t, base, map[string]string{
		"main/.git/info/exclude":           "generated/\n",
		"main/.git/worktrees/wt/commondir": "../..\n",
		"main/.git/worktrees/wt/HEAD":      "ref: refs/heads/wt\n",
		"wt/.git":                          "gitdir: " + filepath.Join(base, "main/.git/worktrees/wt") + "\n",
		"wt/app.go":                        "package app\n",
		"wt/generated/out.go":              "package generated\n",
		"rel/.git":                         "gitdir: ../main/.git/worktrees/wt\n",
		"rel/app.go":                       "package app\n",
		"rel/generated/out.go":             "package generated\n",
	})

	require.Equal(t, []string{"app.go"}, sortedWalkPaths(t, filepath.Join(base, "wt"), &Config{}))
	require.Equal(t, []string{"app.go"}, sortedWalkPaths(t, filepath.Join(base, "rel"), &Config{}))
}

// .git-файл без строки gitdir — повреждённый репозиторий: ошибка, а не
// молчаливый анализ того, что git, возможно, исключает.
func TestWalkerReportsMalformedGitFile(t *testing.T) {
	repo := t.TempDir()
	writeTree(t, repo, map[string]string{
		".git":    "garbage\n",
		"main.go": "package main\n",
	})

	_, errs := NewWalker(repo, &Config{}).WalkSync()
	require.Len(t, errs, 1)
	require.Contains(t, errs[0].Error(), "gitdir")
}
