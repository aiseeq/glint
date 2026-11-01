package buildmanifest

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEmbeddedResourceChangesOnlyItsRuleFingerprint(t *testing.T) {
	root := fixtureModule(t)
	write(t, root, "pkg/rules/check/rule.go", "package check\nimport (\n _ \"embed\"\n _ \"example.com/fixture/pkg/core\"\n)\n//go:embed names.txt\nvar names string\n")
	write(t, root, "pkg/rules/check/names.txt", "first\n")
	before := capture(t, root)
	write(t, root, "pkg/rules/check/names.txt", "first\nsecond\n")
	after := capture(t, root)
	require.NotEqual(t, before.Manifest.Packages["example.com/fixture/pkg/rules/check"], after.Manifest.Packages["example.com/fixture/pkg/rules/check"])
	require.Equal(t, before.Manifest.Core, after.Manifest.Core)
}

func TestLocalReplaceChangeUpdatesRuleFingerprint(t *testing.T) {
	root := fixtureModule(t)
	write(t, root, "go.mod", "module example.com/fixture\n\ngo 1.24\n\nrequire example.com/dep v0.0.0\nreplace example.com/dep => ./dep\n")
	write(t, root, "dep/go.mod", "module example.com/dep\n\ngo 1.24\n")
	write(t, root, "dep/dep.go", "package dep\nfunc Value() int { return 1 }\n")
	write(t, root, "pkg/rules/check/rule.go", "package check\nimport \"example.com/dep\"\nvar value = dep.Value()\n")
	before := capture(t, root)
	write(t, root, "dep/dep.go", "package dep\nfunc Value() int { return 2 }\n")
	after := capture(t, root)
	require.NotEqual(t, before.Manifest.Packages["example.com/fixture/pkg/rules/check"], after.Manifest.Packages["example.com/fixture/pkg/rules/check"])
	require.Equal(t, before.Manifest.Core, after.Manifest.Core)
}

func TestBuildTagsChangeRuleFingerprint(t *testing.T) {
	root := fixtureModule(t)
	write(t, root, "pkg/rules/check/blue.go", "//go:build blue\n\npackage check\nconst Value = 1\n")
	write(t, root, "pkg/rules/check/red.go", "//go:build red\n\npackage check\nconst Value = 2\n")
	t.Setenv("GOFLAGS", "-tags=blue")
	blue := capture(t, root)
	t.Setenv("GOFLAGS", "-tags=red")
	red := capture(t, root)
	require.NotEqual(t, blue.Manifest.Packages["example.com/fixture/pkg/rules/check"], red.Manifest.Packages["example.com/fixture/pkg/rules/check"])
}

func TestVerifyStableRejectsChangedBuildID(t *testing.T) {
	before := Snapshot{Packages: map[string]Package{"example.com/fixture/pkg/rules/check": {BuildID: "before"}}}
	after := Snapshot{Packages: map[string]Package{"example.com/fixture/pkg/rules/check": {BuildID: "after"}}}
	err := VerifyStable(before, after)
	require.ErrorContains(t, err, "BuildIDs changed during the graft build")
	require.ErrorContains(t, err, "example.com/fixture/pkg/rules/check")
}

func fixtureModule(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	write(t, root, "go.mod", "module example.com/fixture\n\ngo 1.24\n")
	write(t, root, "cmd/glint/main.go", "package main\nfunc main() {}\n")
	write(t, root, "pkg/core/core.go", "package core\nconst Value = 1\n")
	return root
}

func capture(t *testing.T, root string) Snapshot {
	t.Helper()
	snapshot, err := Capture(context.Background(), root)
	require.NoError(t, err)
	return snapshot
}

func write(t *testing.T, root, name, content string) {
	t.Helper()
	path := filepath.Join(root, name)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
}

func TestPackageOutsideTheBinaryLeavesTheCoreFingerprint(t *testing.T) {
	root := fixtureModule(t)
	write(t, root, "cmd/glint/main.go", "package main\nimport _ \"example.com/fixture/pkg/core\"\nfunc main() {}\n")
	write(t, root, "tools/perf/perf.go", "package perf\nconst Value = 1\n")
	before := capture(t, root)
	write(t, root, "tools/perf/perf.go", "package perf\nconst Value = 2\n")
	after := capture(t, root)
	require.Equal(t, before.Manifest.Core, after.Manifest.Core, "a package the binary does not link")
	write(t, root, "pkg/core/core.go", "package core\nconst Value = 2\n")
	changed := capture(t, root)
	require.NotEqual(t, after.Manifest.Core, changed.Manifest.Core, "a package the binary links")
}
