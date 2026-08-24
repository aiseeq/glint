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
