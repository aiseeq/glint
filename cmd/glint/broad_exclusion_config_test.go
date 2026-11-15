package main

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

// gitTrack makes root a git repository whose index holds the given files.
func gitTrack(t *testing.T, root string, files ...string) {
	t.Helper()
	for _, args := range [][]string{{"init", "-q"}, append([]string{"add", "--"}, files...)} {
		cmd := exec.Command("git", append([]string{"-C", root}, args...)...)
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "git %v: %s", args, output)
	}
}

// broadPlaces returns the findings of broad-exclusion as file:line.
func broadPlaces(t *testing.T, root string) []string {
	t.Helper()
	cfg, err := core.LoadConfigWithDefaults(root)
	require.NoError(t, err)
	var places []string
	for _, v := range broadFindingsForTest(t, cfg) {
		places = append(places, fmt.Sprintf("%s:%d", v.File, v.Line))
	}
	return places
}

// The walk leaves an untracked build, out, dist or bin directory out by
// default and walks a tracked one; an explicit settings.skip_dirs leaves it
// out either way. So skip_dirs naming a tracked directory of sources of that
// name takes them out of the analysis, as for any other name; so do gen and
// site, which the walk always reaches.
func TestBroadExclusionReportsSkipDirsOverTrackedArtifactDirectory(t *testing.T) {
	for _, name := range []string{"build", "out", "dist", "bin", "site", "gen"} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			writeModuleFile(t, root, ".glint.yaml", "settings:\n  skip_dirs:\n    - "+name+"\n")
			writeModuleFile(t, root, "go.mod", "module example.com/projecta\n\ngo 1.22\n")
			writeModuleFile(t, root, "cmd/app/main.go", "package main\n")
			writeModuleFile(t, root, "internal/"+name+"/version.go", "package "+name+"\n")
			gitTrack(t, root, ".")
			assert.Equal(t, []string{".glint.yaml:3"}, broadPlaces(t, root))
		})
	}
}

// An untracked build directory the walk never reaches by default, or one
// outside git, takes nothing out when skip_dirs names it.
func TestBroadExclusionSkipDirsOverUntrackedArtifactDirectory(t *testing.T) {
	inGit := t.TempDir()
	writeModuleFile(t, inGit, ".glint.yaml", "settings:\n  skip_dirs:\n    - build\n")
	writeModuleFile(t, inGit, "cmd/app/main.go", "package main\n")
	writeModuleFile(t, inGit, "build/version.go", "package build\n")
	gitTrack(t, inGit, ".glint.yaml", "cmd/app/main.go")
	assert.Empty(t, broadPlaces(t, inGit))

	outsideGit := t.TempDir()
	writeModuleFile(t, outsideGit, ".glint.yaml", "settings:\n  skip_dirs:\n    - build\n")
	writeModuleFile(t, outsideGit, "cmd/app/main.go", "package main\n")
	writeModuleFile(t, outsideGit, "internal/build/version.go", "package build\n")
	assert.Empty(t, broadPlaces(t, outsideGit))
}

// Switching off a rule that watches suppressions (a marker without a reason,
// a stale marker, a broad exclusion) takes that watch away from the whole
// project, so it is a broad exclusion on the line that switches it off.
// Another rule switched off is none, and a marker with a reason keeps it.
func TestBroadExclusionReportsOversightRuleSwitchedOff(t *testing.T) {
	for _, rule := range []string{"suppression-without-reason", "stale-suppression", "broad-exclusion"} {
		t.Run(rule, func(t *testing.T) {
			root := t.TempDir()
			writeModuleFile(t, root, ".glint.yaml", "categories:\n  deadcode:\n    rules:\n      "+rule+":\n        enabled: false\n")
			writeModuleFile(t, root, "cmd/app/main.go", "package main\n")
			cfg, err := core.LoadConfigWithDefaults(root)
			require.NoError(t, err)
			found := broadFindingsForTest(t, cfg)
			require.Len(t, found, 1)
			assert.Equal(t, 5, found[0].Line)
			assert.Contains(t, found[0].Message, rule)
		})
	}
	root := t.TempDir()
	writeModuleFile(t, root, ".glint.yaml", "categories:\n  deadcode:\n    rules:\n      unused-internal-export:\n        enabled: false\n      stale-suppression:\n        # broad-exclusion: safe — markers are checked by the gate of the monorepo\n        enabled: false\n      suppression-without-reason:\n        enabled: false # broad-exclusion: safe — <reason>\n  patterns:\n    rules:\n      error-wrap:\n        enabled: false\n")
	writeModuleFile(t, root, "cmd/app/main.go", "package main\n")
	assert.Equal(t, []string{".glint.yaml:10"}, broadPlaces(t, root))
}

// broad-exclusion switched off by name reports only that it is: the rest of
// its findings are switched off with it.
func TestBroadExclusionSwitchedOffReportsOnlyItself(t *testing.T) {
	root := t.TempDir()
	writeModuleFile(t, root, ".glint.yaml", "settings:\n  exclude:\n    - \"internal/**\"\ncategories:\n  security:\n    enabled: false\n  deadcode:\n    rules:\n      broad-exclusion:\n        enabled: false\n")
	writeModuleFile(t, root, "cmd/app/main.go", "package main\n")
	writeModuleFile(t, root, "internal/svc/svc.go", "package svc\n")
	assert.Equal(t, []string{".glint.yaml:10"}, broadPlaces(t, root))
}

// The rules that watch suppressions are in the deadcode category; switching
// the category off used to switch off broad-exclusion too, so the line that
// did it was never reported. broad-exclusion now runs with its category off
// and reports it, while the other rules of the category stay off; a marker
// with a reason keeps the switch.
func TestBroadExclusionRunsWithItsCategoryOff(t *testing.T) {
	withFlags(t, "")
	for config, want := range map[string][]string{
		"categories:\n  deadcode:\n    enabled: false\n":                                                                {".glint.yaml:3"},
		"categories:\n  deadcode:\n    # broad-exclusion: safe — the monorepo gate runs deadcode\n    enabled: false\n": nil,
		"categories:\n  deadcode:\n    enabled: false\n    rules:\n      broad-exclusion:\n        enabled: false\n":    {".glint.yaml:3", ".glint.yaml:6"},
	} {
		root := t.TempDir()
		writeModuleFile(t, root, ".glint.yaml", config)
		writeModuleFile(t, root, "cmd/app/main.go", "package main\n")
		cfg, enabled, err := loadConfig(root)
		require.NoError(t, err)
		var names []string
		for _, rule := range enabled {
			if rule.Category() == "deadcode" {
				names = append(names, rule.Name())
			}
		}
		assert.Equal(t, []string{"broad-exclusion"}, names, config)
		found, err := analyzeConfigurationRules(enabled, cfg, nil, analysisRoot{dir: root}, silencedSeverities{})
		require.NoError(t, err)
		var places []string
		for _, v := range found {
			places = append(places, fmt.Sprintf("%s:%d", v.File, v.Line))
		}
		assert.Equal(t, want, places, config)
	}
}

// broad-exclusion stays off with its category off when the run asks for
// other rules or another category: it was not asked for.
func TestBroadExclusionWithItsCategoryOffKeepsToTheRequestedRules(t *testing.T) {
	root := t.TempDir()
	writeModuleFile(t, root, ".glint.yaml", "categories:\n  deadcode:\n    enabled: false\n")
	for _, flags := range [][]string{{"security"}, {"", "error-wrap"}} {
		withFlags(t, flags[0], flags[1:]...)
		_, enabled, err := loadConfig(root)
		require.NoError(t, err)
		assert.False(t, slices.ContainsFunc(enabled, func(rule rules.Rule) bool { return rule.Name() == "broad-exclusion" }), flags)
	}
}

// broad-exclusion reads every file of the extends chain as the load merges
// them: what a base file excludes or switches off is reported on its own
// line, unless a file above it sets the same thing again.
func TestBroadExclusionReadsTheExtendsChain(t *testing.T) {
	base := "version: 1\nsettings:\n  exclude:\n    - \"internal/**\"\n  skip_dirs:\n    - tools\ncategories:\n  security:\n    enabled: false\n  patterns:\n    rules:\n      error-wrap:\n        exceptions:\n          - files: \"**\"\n            reason: everywhere\n  deadcode:\n    rules:\n      stale-suppression:\n        enabled: false\n"
	for _, tt := range []struct {
		name, config string
		want         []string
	}{
		{"base in the project", "version: 1\nextends: configs/base.yaml\n", []string{"configs/base.yaml:4", "configs/base.yaml:6", "configs/base.yaml:14", "configs/base.yaml:9", "configs/base.yaml:19"}},
		{"set again above", "version: 1\nextends: configs/base.yaml\nsettings:\n  exclude:\n    - \"*.md\"\n  skip_dirs:\n    - scratch\ncategories:\n  security:\n    severity_override: low\n  patterns:\n    rules:\n      error-wrap:\n        exceptions:\n          - files: internal/svc/**\n            reason: one package\n  deadcode:\n    rules:\n      stale-suppression:\n        severity: low\n", nil},
		{"empty lists above set nothing", "version: 1\nextends: configs/base.yaml\nsettings:\n  exclude: []\n  skip_dirs: []\ncategories:\n  patterns:\n    rules:\n      error-wrap:\n        exceptions:\n", []string{"configs/base.yaml:4", "configs/base.yaml:6", "configs/base.yaml:14", "configs/base.yaml:9", "configs/base.yaml:19"}},
		{"marker in the base", "version: 1\nextends: configs/marked.yaml\n", []string{"configs/marked.yaml:4", "configs/marked.yaml:6", "configs/marked.yaml:14", "configs/marked.yaml:19"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			writeModuleFile(t, root, ".glint.yaml", tt.config)
			writeModuleFile(t, root, "configs/base.yaml", base)
			writeModuleFile(t, root, "configs/marked.yaml", strings.Replace(base, "    enabled: false\n", "    enabled: false # broad-exclusion: safe — security runs in its own gate\n", 1))
			writeModuleFile(t, root, "cmd/app/main.go", "package main\n")
			writeModuleFile(t, root, "internal/svc/svc.go", "package svc\n")
			writeModuleFile(t, root, "tools/cli/main.go", "package main\n")
			assert.Equal(t, tt.want, broadPlaces(t, root))
		})
	}
}

// A base file outside the project is no file of it: what it excludes or
// switches off is reported on the extends line that leads out of the
// project, and a marker with a reason there keeps it.
func TestBroadExclusionReportsAnOutsideBaseOnItsExtendsLine(t *testing.T) {
	shared := t.TempDir()
	writeModuleFile(t, shared, "base.yaml", "version: 1\nsettings:\n  exclude:\n    - \"internal/**\"\ncategories:\n  security:\n    enabled: false\n")
	writeModuleFile(t, shared, "inner.yaml", "version: 1\nextends: base.yaml\n")
	for _, tt := range []struct {
		name, config, middle string
		want                 []string
	}{
		{"root extends it", "version: 1\nextends: " + filepath.Join(shared, "base.yaml") + "\n", "", []string{".glint.yaml:2", ".glint.yaml:2"}},
		{"through a file outside", "version: 1\n\nextends: " + filepath.Join(shared, "inner.yaml") + "\n", "", []string{".glint.yaml:3", ".glint.yaml:3"}},
		{"through a file inside", "version: 1\nextends: configs/mid.yaml\n", "version: 1\n\n\nextends: " + filepath.Join(shared, "base.yaml") + "\n", []string{"configs/mid.yaml:4", "configs/mid.yaml:4"}},
		{"marker with a reason", "version: 1\n# broad-exclusion: safe — the shared base is reviewed where it lives\nextends: " + filepath.Join(shared, "base.yaml") + "\n", "", nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			writeModuleFile(t, root, ".glint.yaml", tt.config)
			if tt.middle != "" {
				writeModuleFile(t, root, "configs/mid.yaml", tt.middle)
			}
			writeModuleFile(t, root, "cmd/app/main.go", "package main\n")
			writeModuleFile(t, root, "internal/svc/svc.go", "package svc\n")
			assert.Equal(t, tt.want, broadPlaces(t, root))
			cfg, err := core.LoadConfigWithDefaults(root)
			require.NoError(t, err)
			for _, v := range broadFindingsForTest(t, cfg) {
				assert.Regexp(t, `base\.yaml:[47], outside the project, through extends: `, v.Message)
			}
		})
	}
}

// A directory named in settings.skip_dirs that holds sources only below a
// foreign or test-data directory takes no source of the project's own out.
func TestBroadExclusionSkipDirsBelowForeignDirectory(t *testing.T) {
	for _, dir := range []string{"testdata", "third_party", ".tools", "pb_generated"} {
		root := t.TempDir()
		writeModuleFile(t, root, ".glint.yaml", "settings:\n  skip_dirs:\n    - fixtures\n")
		writeModuleFile(t, root, "cmd/app/main.go", "package main\n")
		writeModuleFile(t, root, "pkg/"+dir+"/fixtures/a.go", "package fixtures\n")
		assert.Empty(t, broadPlaces(t, root), dir)
	}
}

// A run of the configured rules runs broad-exclusion once, whether the
// configuration leaves it on or not.
func TestEnabledRulesHoldBroadExclusionOnce(t *testing.T) {
	withFlags(t, "")
	enabled, err := getEnabledRules(core.DefaultConfig())
	require.NoError(t, err)
	count := 0
	for _, rule := range enabled {
		if rule.Name() == "broad-exclusion" {
			count++
		}
	}
	assert.Equal(t, 1, count)
}

// A language is judged by the files the walk reads: an untracked build
// directory it leaves out does not keep an exclusion over every other Go file
// from covering the language, while a gen directory, which it reads, does.
func TestBroadExclusionLanguageCountsWalkedArtifactDirectories(t *testing.T) {
	for dir, message := range map[string]string{"build": "every .go file", "gen": "all source files in a project directory"} {
		root := t.TempDir()
		writeModuleFile(t, root, ".glint.yaml", "settings:\n  exclude:\n    - \"internal/**/*.go\"\n")
		writeModuleFile(t, root, "internal/svc/svc.go", "package svc\n")
		writeModuleFile(t, root, dir+"/api/api.go", "package api\n")
		gitTrack(t, root, ".glint.yaml", "internal/svc/svc.go")
		cfg, err := core.LoadConfigWithDefaults(root)
		require.NoError(t, err)
		found := broadFindingsForTest(t, cfg)
		require.Len(t, found, 1, dir)
		assert.Contains(t, found[0].Message, message, dir)
	}
}

// A category switched off says so; the one that holds the rules watching
// suppressions says it takes them away too.
func TestBroadExclusionCategoryMessageNamesTheOversight(t *testing.T) {
	root := t.TempDir()
	writeModuleFile(t, root, ".glint.yaml", "categories:\n  security:\n    enabled: false\n  deadcode:\n    enabled: false\n")
	writeModuleFile(t, root, "cmd/app/main.go", "package main\n")
	cfg, err := core.LoadConfigWithDefaults(root)
	require.NoError(t, err)
	messages := make(map[int]string)
	for _, v := range broadFindingsForTest(t, cfg) {
		messages[v.Line] = v.Message
	}
	require.Len(t, messages, 2)
	assert.NotContains(t, messages[3], "watch suppressions")
	assert.Contains(t, messages[5], "the rules that watch suppressions")
}

// A marker after the entry on its line covers that line only, as every YAML
// marker after code does: one at the end of the line that switches security
// off used to keep the line under it too, so deadcode, and with it the
// rules watching suppressions, went off without a finding. A marker on a line
// of its own still covers the line under it.
func TestBroadExclusionMarkerAtTheLineEndCoversItsLineOnly(t *testing.T) {
	for config, want := range map[string][]string{
		"categories:\n  security: {enabled: false} # broad-exclusion: safe — no secrets in this tool\n  deadcode: {enabled: false}\n":                                                     {".glint.yaml:3"},
		"categories:\n  security: {enabled: false} # broad-exclusion: safe — no secrets in this tool\n  # broad-exclusion: safe — the gate runs deadcode\n  deadcode: {enabled: false}\n": nil,
		"settings:\n  exclude:\n    - \"tools/**\" # broad-exclusion: safe — snapshots of retired bots\n    - \"internal/**\"\n":                                                          {".glint.yaml:4"},
	} {
		root := t.TempDir()
		writeModuleFile(t, root, ".glint.yaml", config)
		writeModuleFile(t, root, "cmd/app/main.go", "package main\n")
		writeModuleFile(t, root, "tools/cli/main.go", "package main\n")
		writeModuleFile(t, root, "internal/svc/svc.go", "package svc\n")
		assert.Equal(t, want, broadPlaces(t, root), config)
	}
}

// settings.exclude over a tracked directory named build, out, dist, bin, site
// or gen takes its sources out of the analysis as over any other name: the
// walk reads a tracked build, out, dist or bin directory and always reads site
// and gen. Each used to count as a default artifact directory, so the
// exclusion hid a package of the project without a finding.
func TestBroadExclusionReportsExcludeOverTrackedArtifactDirectory(t *testing.T) {
	for _, name := range []string{"build", "out", "dist", "bin", "site", "gen"} {
		for _, pattern := range []string{"internal/" + name + "/**", "**/" + name + "/**"} {
			t.Run(pattern, func(t *testing.T) {
				root := t.TempDir()
				writeModuleFile(t, root, ".glint.yaml", "settings:\n  exclude:\n    - \""+pattern+"\"\n")
				writeModuleFile(t, root, "go.mod", "module example.com/projecta\n\ngo 1.22\n")
				writeModuleFile(t, root, "cmd/app/main.go", "package main\n")
				writeModuleFile(t, root, "internal/"+name+"/version.go", "package "+name+"\n")
				gitTrack(t, root, ".")
				assert.Equal(t, []string{".glint.yaml:3"}, broadPlaces(t, root))
			})
		}
	}
}

// An untracked build, out, dist or bin directory, or one outside git, is not
// walked, so an exclusion over it takes nothing out; an exclusion by language
// is judged without its files.
func TestBroadExclusionExcludeOverUntrackedArtifactDirectory(t *testing.T) {
	for _, name := range []string{"build", "out", "dist", "bin"} {
		t.Run(name, func(t *testing.T) {
			inGit := t.TempDir()
			writeModuleFile(t, inGit, ".glint.yaml", "settings:\n  exclude:\n    - \""+name+"/**\"\n    - \"**/"+name+"/**\"\n")
			writeModuleFile(t, inGit, "cmd/app/main.go", "package main\n")
			writeModuleFile(t, inGit, name+"/x/version.go", "package x\n")
			gitTrack(t, inGit, ".glint.yaml", "cmd/app/main.go")
			assert.Empty(t, broadPlaces(t, inGit))

			outsideGit := t.TempDir()
			writeModuleFile(t, outsideGit, ".glint.yaml", "settings:\n  exclude:\n    - \"internal/"+name+"/**\"\n")
			writeModuleFile(t, outsideGit, "cmd/app/main.go", "package main\n")
			writeModuleFile(t, outsideGit, "internal/"+name+"/version.go", "package x\n")
			assert.Empty(t, broadPlaces(t, outsideGit))
		})
	}
}
