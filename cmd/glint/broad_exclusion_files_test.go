package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
)

// broadFilesTree is a project the files an exception covers are counted in.
type broadFilesTree struct {
	// sources are Go files whose line 3 holds the finding: a marker without
	// a reason (marked) or an empty var group (bare).
	sources []string
	// files are other files of the tree, by path.
	files map[string]string
	// head are lines of the configuration after its version and, marked,
	// its own marker without a reason on line 3; settings are the lines of
	// its settings section, "" for none.
	head     string
	settings string
	// tracked are the files git tracks, nil for a tree without git; nested
	// are directories that are repositories of their own.
	tracked []string
	nested  []string
	// scopes are the directories of the runs over the tree besides the whole
	// of it, each run from its directory; fileScopes are the files of the
	// runs from the root that name them.
	scopes     []string
	fileScopes []string
}

// broadBareMarker is a marker without a reason, on line 3 of a file that
// holds a finding of suppression-without-reason.
const broadBareMarker = "# nolint:empty-decl-group"

// write lays the tree out in root with the configuration that excepts rule
// with the exceptions, none when there are none, and returns the line of
// each exception in the configuration.
func (tree broadFilesTree) write(t *testing.T, root string, marked bool, rule string, exceptions ...string) []int {
	t.Helper()
	config := "version: 1\n"
	if marked {
		config += "\n" + broadBareMarker + "\n"
	}
	config += tree.head
	if tree.settings != "" {
		config += "settings:\n" + tree.settings
	}
	var lines []int
	if len(exceptions) > 0 {
		config += "categories:\n  deadcode:\n    rules:\n      " + rule + ":\n        exceptions:\n"
	}
	for _, exception := range exceptions {
		lines = append(lines, strings.Count(config, "\n")+1)
		config += "          - " + strings.ReplaceAll(exception, "\n", "\n            ") + "\n            reason: legacy\n"
	}
	writeModuleFile(t, root, ".glint.yaml", config)
	writeModuleFile(t, root, "go.mod", oversightModule)
	for _, source := range tree.sources {
		group := "var ()"
		if marked {
			group += " // nolint:empty-decl-group"
		}
		name := path.Base(path.Dir(source))
		if name == "." {
			name = "main"
		}
		writeModuleFile(t, root, source, fmt.Sprintf("package %s\n\n%s\n", name, group))
	}
	for name, contents := range tree.files {
		writeModuleFile(t, root, name, contents)
	}
	return lines
}

// track makes the tree's repositories, once its files are written.
func (tree broadFilesTree) track(t *testing.T, root string) {
	t.Helper()
	for _, dir := range tree.nested {
		gitTrack(t, root+"/"+dir)
	}
	if tree.tracked != nil {
		gitTrack(t, root, tree.tracked...)
	}
}

// runFindings returns the places (file:line, relative to root) of the
// findings of each rule in the runs over the tree: the whole of it, each of
// its scopes and each of its files.
func (tree broadFilesTree) runFindings(t *testing.T, root string) map[string][]string {
	t.Helper()
	places := map[string][]string{}
	runs := [][]string{{"-C", root, "check", "."}}
	for _, scope := range tree.scopes {
		runs = append(runs, []string{"-C", root + "/" + scope, "check", "."})
	}
	for _, file := range tree.fileScopes {
		runs = append(runs, []string{"-C", root, "check", file})
	}
	for _, run := range runs {
		for rule, found := range checkPlaces(t, run...) {
			// A run from a scope names files relative to it.
			for _, place := range found {
				places[rule] = append(places[rule], path.Join(strings.TrimPrefix(strings.TrimPrefix(run[1], root), "/"), place))
			}
		}
	}
	for rule := range places {
		slices.Sort(places[rule])
		places[rule] = slices.Compact(places[rule])
	}
	return places
}

// checkPlaces runs glint with the arguments of a check, adding --no-cache,
// -o json and -s low, and returns the places (file:line, as the report names
// them) of the findings of each rule.
func checkPlaces(t *testing.T, args ...string) map[string][]string {
	t.Helper()
	cmd := mainSubprocess(t, append(args, "--no-cache", "-o", "json", "-s", "low"))
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	// A finding at fail_on exits non-zero; the report on stdout is what counts.
	output, _ := cmd.Output()
	var report struct {
		Issues []shownFinding `json:"issues"`
	}
	require.NoError(t, json.NewDecoder(bytes.NewReader(output)).Decode(&report), "report:\n%s\n%s", output, stderr.String())
	places := map[string][]string{}
	for _, finding := range report.Issues {
		places[finding.Rule] = append(places[finding.Rule], fmt.Sprintf("%s:%d", finding.File, finding.Line))
	}
	return places
}

// silencedPlaces are the places of the findings of a rule in the runs
// without an exception that the runs with it do not report.
func silencedPlaces(unexcepted, excepted map[string][]string, rule string) []string {
	return slices.DeleteFunc(slices.Clone(unexcepted[rule]), func(place string) bool { return slices.Contains(excepted[rule], place) })
}

// coveredPlaces returns the files of the places broad-exclusion counts for
// the only exception of rule in the configuration of root, with the runs
// that name files.
func coveredPlaces(t *testing.T, root, category, rule string, fileScopes []string) []string {
	t.Helper()
	cfg, err := core.LoadConfigWithDefaults(root)
	require.NoError(t, err)
	exceptions := cfg.GetRuleExceptions(category, rule)
	require.Len(t, exceptions, 1)
	var scopes []string
	for _, file := range fileScopes {
		scopes = append(scopes, root+"/"+file)
	}
	places, err := readOversightPlaces(cfg, scopes, []oneLineException{{rule: rule, exception: exceptions[0]}})
	require.NoError(t, err)
	return places.covered(rule, exceptions[0])
}

// broadFilesTrees are the trees of the comparison: git with a tracked build
// directory and one with it untracked, no git, settings.exclude,
// settings.skip_dirs, .gitignore, a nested repository, one with its own
// configuration, a configuration that extends another in the project, a
// generated file, and a file .gitignore leaves out that a run names.
var broadFilesTrees = map[string]broadFilesTree{
	"tracked build":   {sources: []string{"internal/svc/a.go", "build/a.go"}, tracked: []string{"."}},
	"untracked build": {sources: []string{"internal/svc/a.go", "build/a.go"}, tracked: []string{".glint.yaml", "go.mod", "internal"}},
	"no git":          {sources: []string{"internal/svc/a.go", "build/a.go", "cmd/app/a.go"}},
	"exclude":         {sources: []string{"internal/svc/a.go", "cmd/app/a.go"}, settings: "  exclude: [\"internal/**\"]\n"},
	"skip_dirs":       {sources: []string{"internal/svc/a.go", "cmd/app/a.go", "tools/a.go"}, settings: "  skip_dirs: [svc]\n"},
	"gitignore":       {sources: []string{"internal/svc/a.go", "cmd/app/a.go"}, files: map[string]string{".gitignore": "internal/\n"}, tracked: []string{"."}},
	"nested repo":     {sources: []string{"internal/svc/a.go", "sub/a.go"}, nested: []string{"sub"}, tracked: []string{".glint.yaml", "go.mod", "internal"}, scopes: []string{"sub"}},
	"extends":         {sources: []string{"a.go"}, head: "extends: conf/base.yaml\n", files: map[string]string{"conf/base.yaml": "version: 1\n\n" + broadBareMarker + "\n"}},
	"nested repo with its own configuration": {
		sources: []string{"internal/svc/a.go", "sub/a.go"}, files: map[string]string{"sub/.glint.yaml": "version: 1\n"},
		nested: []string{"sub"}, tracked: []string{".glint.yaml", "go.mod", "internal"}, scopes: []string{"sub"},
	},
	"generated": {sources: []string{"internal/svc/a.go"}, files: map[string]string{"gen/a.go": "// Code generated by projecta-gen. DO NOT EDIT.\npackage gen\nvar () // nolint:empty-decl-group\n"}},
	"ignored file named": {
		sources: []string{"internal/svc/a.go", "local/a.go"}, files: map[string]string{".gitignore": "local/\n"},
		tracked: []string{"."}, fileScopes: []string{"local/a.go"},
	},
	"file named": {sources: []string{"internal/svc/a.go"}, fileScopes: []string{"internal/svc/a.go"}},
}

// An exception of a rule watching suppressions that keeps one line is a
// finding when it covers more than one file, counted as the run excepts:
// broad-exclusion counted the files of the configuration's directory less
// the default artifact directories, while the walk reads a build directory
// git tracks, so an exception of a.go kept a marker in build/a.go unseen. It
// now counts the files the run reads, matched as the run matches them; a
// nested repository counts, since a run scoped to it reads it under the same
// configuration, unless it has a configuration of its own, which a run of it
// reads instead. The configuration does not, nor one it extends: the run
// excepts no marker there. Nor does a generated file, where no rule reports,
// while a file .gitignore leaves out counts for a run that names it.
func TestBroadExclusionOneLineExceptionCountsWhatTheRunExcepts(t *testing.T) {
	const rule = "suppression-without-reason"
	forms := []string{"file: a.go", "files: a.go", "files: \"*.go\"", "files: \"internal/**\"", "files: \"*\"", "files: \"*.yaml\""}
	for name, tree := range broadFilesTrees {
		for _, form := range forms {
			exception := form + "\nline: 3"
			t.Run(name+"/"+form, func(t *testing.T) {
				// Each run is a subprocess in its own directory; in parallel
				// the race build of the package stays within its timeout.
				t.Parallel()
				root := t.TempDir()
				tree.write(t, root, true, rule)
				tree.track(t, root)
				unexcepted := tree.runFindings(t, root)
				line := tree.write(t, root, true, rule, exception)[0]
				excepted := tree.runFindings(t, root)
				silenced := silencedPlaces(unexcepted, excepted, rule)
				reported := slices.Contains(excepted[broadExclusionRule], fmt.Sprintf(".glint.yaml:%d", line))
				assert.Equal(t, len(silenced) > 1, reported, "the run excepts %v", silenced)
				covered := coveredPlaces(t, root, "deadcode", rule, tree.fileScopes)
				assert.Len(t, covered, len(silenced), "broad-exclusion counts %v, the run excepts %v", covered, silenced)
				t.Logf("the run excepts %v", silenced)
			})
		}
	}
}

// staleMarkerSource is a Go file of the package with a marker that silences
// nothing on the line, and a reason: a finding of stale-suppression alone.
func staleMarkerSource(pkg string, line int) string {
	lines := []string{"package " + pkg, ""}
	for len(lines) < line-1 {
		lines = append(lines, fmt.Sprintf("var v%d = %d", len(lines)+1, len(lines)+1))
	}
	lines = append(lines, fmt.Sprintf("var v%d = %d // nolint:interface-any — kept for the generator", line, line))
	return strings.Join(lines, "\n") + "\n"
}

// staleBase is a base configuration whose exception of empty-decl-group,
// which matches nothing, is declared on line 15.
const staleBase = "version: 1\n" + "# padding\n# padding\n# padding\n# padding\n# padding\n# padding\n# padding\n# padding\n" +
	"categories:\n  deadcode:\n    rules:\n      empty-decl-group:\n        exceptions:\n          - file: main.go\n            reason: projecta\n"

// staleExceptionConfig is a configuration of the project, after the extends line: an
// exception of stale-suppression of the form on the line, declared on line
// 8 of a configuration that extends another and on line 7 of one that does
// not, and an exception of hardcoded-secret, which matches nothing, on line
// 15 and 14.
func staleExceptionConfig(extends, form string, line int) string {
	config := "version: 1\n"
	if extends != "" {
		config += "extends: " + extends + "\n"
	}
	return config + "categories:\n  deadcode:\n    rules:\n      stale-suppression:\n        exceptions:\n" +
		"          - " + form + fmt.Sprintf("\n            line: %d\n", line) + "            reason: one legacy finding\n" +
		"  security:\n    rules:\n      hardcoded-secret:\n        exceptions:\n          - file: main.go\n            reason: projecta\n"
}

// An exception of stale-suppression of one line silences its findings in the
// configuration as well, on the line of an exception there, of the project's
// configuration and of a base it extends, in the project or outside it:
// those places count with the sources. The exception of a line no exception
// is declared on silences none of them.
func TestBroadExclusionOneLineStaleExceptionCountsTheConfiguration(t *testing.T) {
	const rule = "stale-suppression"
	type staleTree struct {
		// dir is the project's directory in the tree, extends its base; line
		// is the line of the exceptions that match nothing.
		dir, extends string
		line         int
		files        map[string]string
		forms        []string
	}
	trees := map[string]staleTree{
		"base in the project": {
			extends: "conf/base.yaml", line: 15, files: map[string]string{"conf/base.yaml": staleBase},
			forms: []string{"files: \"*.yaml\"", "files: \"*\"", "files: \"{conf/base.yaml,.glint.yaml}\"", "file: base.yaml", "files: \"*.go\""},
		},
		"base outside the project": {
			dir: "p", extends: "../shared/base.yaml", line: 15, files: map[string]string{"shared/base.yaml": staleBase},
			forms: []string{"files: \"*.yaml\"", "files: \"*\"", "file: base.yaml"},
		},
		"configuration and source": {
			line: 14, files: map[string]string{"cmd/x/b.go": staleMarkerSource("x", 14)},
			forms: []string{"files: \"{cmd/x/b.go,.glint.yaml}\"", "files: \"*\"", "files: \"*.go\"", "file: b.go", "files: \".glint.yaml\""},
		},
	}
	for name, tree := range trees {
		for _, form := range tree.forms {
			t.Run(name+"/"+form, func(t *testing.T) {
				t.Parallel()
				root := t.TempDir()
				for file, contents := range tree.files {
					writeModuleFile(t, root, file, contents)
				}
				project := path.Join(root, tree.dir)
				writeModuleFile(t, project, "go.mod", oversightModule)
				writeModuleFile(t, project, "main.go", staleMarkerSource("main", tree.line))
				run := broadFilesTree{}
				writeModuleFile(t, project, ".glint.yaml", staleExceptionConfig(tree.extends, form, 99))
				unexcepted := run.runFindings(t, project)
				// No exception is declared on line 99: the sources alone count.
				elsewhere := coveredPlaces(t, project, "deadcode", rule, nil)
				writeModuleFile(t, project, ".glint.yaml", staleExceptionConfig(tree.extends, form, tree.line))
				excepted := run.runFindings(t, project)
				silenced := silencedPlaces(unexcepted, excepted, rule)
				declared := 7
				if tree.extends != "" {
					declared = 8
				}
				reported := slices.Contains(excepted[broadExclusionRule], fmt.Sprintf(".glint.yaml:%d", declared))
				assert.Equal(t, len(silenced) > 1, reported, "the run excepts %v", silenced)
				covered := coveredPlaces(t, project, "deadcode", rule, nil)
				assert.Len(t, covered, len(silenced), "broad-exclusion counts %v, the run excepts %v", covered, silenced)
				sources := slices.DeleteFunc(slices.Clone(covered), func(file string) bool { return !strings.HasSuffix(file, ".go") })
				assert.ElementsMatch(t, sources, elsewhere, "of line 99")
				t.Logf("the run excepts %v", silenced)
			})
		}
	}
}

// The places in the configuration count for stale-suppression alone: an
// exception of one line of suppression-without-reason over the YAML files
// covers none, while the same one of stale-suppression beside it covers the
// two exceptions declared on its line.
func TestBroadExclusionOneLineExceptionOfAnotherRuleCountsNoConfiguration(t *testing.T) {
	root := t.TempDir()
	writeModuleFile(t, root, "conf/base.yaml", staleBase)
	writeModuleFile(t, root, "go.mod", oversightModule)
	writeModuleFile(t, root, "main.go", "package main\n\nfunc main() {}\n")
	writeModuleFile(t, root, ".glint.yaml", "version: 1\nextends: conf/base.yaml\ncategories:\n  deadcode:\n    rules:\n"+
		"      suppression-without-reason: {exceptions: [{files: \"*.yaml\", line: 15, reason: one legacy marker}]}\n"+
		"      stale-suppression: {exceptions: [{files: \"*.yaml\", line: 15, reason: one legacy finding}]}\n"+
		"  security:\n    rules:\n      hardcoded-secret:\n        exceptions:\n          # projecta\n          # projecta\n          # projecta\n"+
		"          - file: main.go\n            reason: projecta\n")
	places := broadPlaces(t, root)
	assert.NotContains(t, places, ".glint.yaml:6")
	assert.Contains(t, places, ".glint.yaml:7")
}

// Exceptions of one line are counted each on its own: two of one file each
// are none, though the run excepts two files with them.
func TestBroadExclusionOneLineExceptionsCountEachItsOwnFiles(t *testing.T) {
	root := t.TempDir()
	tree := broadFilesTree{sources: []string{"internal/svc/a.go", "cmd/app/b.go"}}
	lines := tree.write(t, root, true, "suppression-without-reason", "files: a.go\nline: 3", "files: b.go\nline: 3")
	places := broadPlaces(t, root)
	for _, line := range lines {
		assert.NotContains(t, places, fmt.Sprintf(".glint.yaml:%d", line))
	}
}

// An exception of another rule that names files covers the whole project
// when the run excepts every source with it: its files glob matched as the
// run matches it (a glob without a separator matches the base name), a
// file-only one keeping the rule off what its files or its file names, one of
// a name with no glob as well. A project with no source has none to cover.
func TestBroadExclusionFileExceptionCoversWhatTheRunExcepts(t *testing.T) {
	const rule = "empty-decl-group"
	trees := map[string]broadFilesTree{
		"mixed names": {sources: []string{"main.go", "cmd/app/a.go", "internal/svc/b.go"}},
		"one name":    {sources: []string{"cmd/app/a.go", "internal/svc/a.go"}},
		"no source":   {files: map[string]string{"README.md": "# projectA\n"}},
	}
	forms := []string{"files: \"*.go\"", "files: a.go", "file: a.go", "files: \"**\"\nfile: a.go", "line: -1", "files: \"**/*.go\"", "files: \"cmd/**\""}
	for name, tree := range trees {
		for _, exception := range forms {
			t.Run(name+"/"+strings.ReplaceAll(exception, "\n", " "), func(t *testing.T) {
				t.Parallel()
				root := t.TempDir()
				tree.write(t, root, false, rule)
				unexcepted := tree.runFindings(t, root)[rule]
				require.Len(t, unexcepted, len(tree.sources))
				line := tree.write(t, root, false, rule, exception)[0]
				excepted := tree.runFindings(t, root)[rule]
				reported := slices.Contains(broadPlaces(t, root), fmt.Sprintf(".glint.yaml:%d", line))
				assert.Equal(t, len(unexcepted) > 0 && len(excepted) == 0, reported, "the run keeps %v", excepted)
			})
		}
	}
}

// A check of a directory below the configuration's reads the configuration
// all the same: the files an exception of one line covers are counted from
// the configuration's directory, its exclude matched there.
func TestBroadExclusionOneLineExceptionCountsFromTheConfigurationDirectory(t *testing.T) {
	root := t.TempDir()
	tree := broadFilesTree{sources: []string{"internal/svc/a.go", "cmd/app/a.go"}, settings: "  exclude: [\"internal/**\"]\n"}
	line := tree.write(t, root, true, "suppression-without-reason", "file: a.go\nline: 3")[0]
	cfg, err := core.LoadConfigWithDefaults(root + "/cmd")
	require.NoError(t, err)
	exceptions := cfg.GetRuleExceptions("deadcode", "suppression-without-reason")
	require.Len(t, exceptions, 1)
	places, err := readOversightPlaces(cfg, nil, []oneLineException{{rule: "suppression-without-reason", exception: exceptions[0]}})
	require.NoError(t, err)
	assert.Equal(t, []string{"cmd/app/a.go"}, places.covered("suppression-without-reason", exceptions[0]))
	var found []string
	for _, v := range broadFindingsForTest(t, cfg) {
		found = append(found, fmt.Sprintf("%s:%d", v.File, v.Line))
	}
	assert.NotContains(t, found, fmt.Sprintf(".glint.yaml:%d", line))
}
