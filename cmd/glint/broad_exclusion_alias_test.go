package main

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
)

// The load of the configuration follows a YAML alias, so a list, a rule, a
// category or an entry named by an alias is in effect where the alias is
// used. broad-exclusion read the nodes as they are, an alias as nothing, so
// an alias switched a watch off or took sources out without a finding. Each
// entry of an alias is now judged as the one it names, on the line that
// uses the alias, and a marker there keeps it.
func TestBroadExclusionFollowsAliases(t *testing.T) {
	for name, tt := range map[string]struct {
		config string
		want   []string
	}{
		"exceptions":            {"version: 1\ncategories:\n  deadcode:\n    rules:\n      unused-internal-export:\n        exceptions: &wide\n          - pattern: \"Suppression\"\n            reason: legacy markers\n      suppression-without-reason:\n        exceptions: *wide\n", []string{".glint.yaml:10"}},
		"rule":                  {"version: 1\ncategories:\n  deadcode:\n    rules:\n      unused-internal-export: &rulecfg\n        exceptions:\n          - pattern: \"Suppression\"\n            reason: legacy markers\n      suppression-without-reason: *rulecfg\n", []string{".glint.yaml:9"}},
		"exception":             {"version: 1\ncategories:\n  deadcode:\n    rules:\n      unused-internal-export:\n        exceptions:\n          - &exc\n            pattern: \"Suppression\"\n            reason: legacy markers\n      suppression-without-reason:\n        exceptions:\n          - *exc\n", []string{".glint.yaml:12"}},
		"exclude entry":         {"version: 1\ncategories:\n  security:\n    rules:\n      hardcoded-secret:\n        exceptions:\n          - files: &tree \"internal/**\"\n            reason: fixtures\nsettings:\n  exclude:\n    - *tree\n", []string{".glint.yaml:11"}},
		"skip_dirs entry":       {"version: 1\ncategories:\n  security:\n    rules:\n      hardcoded-secret:\n        exceptions:\n          - files: \"tools/**\"\n            reason: &dir tools\nsettings:\n  skip_dirs:\n    - *dir\n", []string{".glint.yaml:11"}},
		"skip_dirs list":        {"version: 1\nsettings:\n  exclude: &dirs\n    - tools\n  skip_dirs: *dirs\n", []string{".glint.yaml:5"}},
		"category":              {"version: 1\ncategories:\n  security: &off\n    enabled: false\n  deadcode: *off\n", []string{".glint.yaml:5", ".glint.yaml:4"}},
		"oversight rule off":    {"version: 1\ncategories:\n  deadcode:\n    rules:\n      unused-internal-export: &off\n        enabled: false\n      stale-suppression: *off\n", []string{".glint.yaml:7"}},
		"marker at the use":     {"version: 1\ncategories:\n  deadcode:\n    rules:\n      unused-internal-export:\n        exceptions: &wide\n          - pattern: \"Suppression\"\n            reason: legacy markers\n      suppression-without-reason:\n        # broad-exclusion: safe — the legacy markers are tracked in one ticket\n        exceptions: *wide\n", nil},
		"marker at the anchor":  {"version: 1\ncategories:\n  deadcode:\n    rules:\n      unused-internal-export:\n        exceptions: &wide # broad-exclusion: safe — kept for unused-internal-export\n          - pattern: \"Suppression\"\n            reason: legacy markers\n      suppression-without-reason:\n        exceptions: *wide\n", []string{".glint.yaml:10"}},
		"no alias, as it was":   {"version: 1\ncategories:\n  deadcode:\n    rules:\n      unused-internal-export: &rulecfg\n        exceptions:\n          - pattern: \"Suppression\"\n            reason: legacy markers\n", nil},
		"alias of a narrow one": {"version: 1\ncategories:\n  deadcode:\n    rules:\n      unused-internal-export: &rulecfg\n        exceptions:\n          - files: internal/svc/svc.go\n            line: 1\n            reason: one marker\n      suppression-without-reason: *rulecfg\n", nil},
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			writeModuleFile(t, root, ".glint.yaml", tt.config)
			writeModuleFile(t, root, "cmd/app/main.go", "package main\n")
			writeModuleFile(t, root, "internal/svc/svc.go", "package svc\n")
			writeModuleFile(t, root, "tools/cli/main.go", "package main\n")
			assert.Equal(t, tt.want, broadPlaces(t, root))
		})
	}
}

// An alias in a base file outside the project is reported as all that file
// sets: on the extends line that leads out of the project, naming the line of
// the alias in the base.
func TestBroadExclusionFollowsAnAliasOfAnOutsideBase(t *testing.T) {
	shared := t.TempDir()
	writeModuleFile(t, shared, "base.yaml", "version: 1\ncategories:\n  deadcode:\n    rules:\n      unused-internal-export: &rulecfg\n        exceptions:\n          - pattern: \"Suppression\"\n            reason: legacy markers\n      suppression-without-reason: *rulecfg\n")
	root := t.TempDir()
	writeModuleFile(t, root, ".glint.yaml", "version: 1\nextends: "+filepath.Join(shared, "base.yaml")+"\n")
	writeModuleFile(t, root, "cmd/app/main.go", "package main\n")
	cfg, err := core.LoadConfigWithDefaults(root)
	require.NoError(t, err)
	found := broadFindingsForTest(t, cfg)
	require.Len(t, found, 1)
	assert.Equal(t, 2, found[0].Line)
	assert.Contains(t, found[0].Message, "base.yaml:9, outside the project, through extends: ")
}
