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
	// scopes are the paths of the runs over the tree besides the whole of it.
	scopes []string
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
// findings of rule in the runs over the tree: the whole of it and each of its
// scopes.
func (tree broadFilesTree) runFindings(t *testing.T, root, rule string) []string {
	t.Helper()
	var places []string
	for _, scope := range append([]string{"."}, tree.scopes...) {
		cmd := mainSubprocess(t, []string{"-C", root + "/" + scope, "check", ".", "--no-cache", "-o", "json", "-s", "low"})
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		// A finding at fail_on exits non-zero; the report on stdout is what counts.
		output, _ := cmd.Output()
		var report struct {
			Issues []shownFinding `json:"issues"`
		}
		require.NoError(t, json.NewDecoder(bytes.NewReader(output)).Decode(&report), "report:\n%s\n%s", output, stderr.String())
		for _, finding := range report.Issues {
			if finding.Rule == rule {
				places = append(places, fmt.Sprintf("%s:%d", path.Join(scope, finding.File), finding.Line))
			}
		}
	}
	slices.Sort(places)
	return slices.Compact(places)
}

// broadFilesTrees are the trees of the comparison: git with a tracked build
// directory and one with it untracked, no git, settings.exclude,
// settings.skip_dirs, .gitignore, a nested repository and a configuration
// that extends another in the project.
var broadFilesTrees = map[string]broadFilesTree{
	"tracked build":   {sources: []string{"internal/svc/a.go", "build/a.go"}, tracked: []string{"."}},
	"untracked build": {sources: []string{"internal/svc/a.go", "build/a.go"}, tracked: []string{".glint.yaml", "go.mod", "internal"}},
	"no git":          {sources: []string{"internal/svc/a.go", "build/a.go", "cmd/app/a.go"}},
	"exclude":         {sources: []string{"internal/svc/a.go", "cmd/app/a.go"}, settings: "  exclude: [\"internal/**\"]\n"},
	"skip_dirs":       {sources: []string{"internal/svc/a.go", "cmd/app/a.go", "tools/a.go"}, settings: "  skip_dirs: [svc]\n"},
	"gitignore":       {sources: []string{"internal/svc/a.go", "cmd/app/a.go"}, files: map[string]string{".gitignore": "internal/\n"}, tracked: []string{"."}},
	"nested repo":     {sources: []string{"internal/svc/a.go", "sub/a.go"}, nested: []string{"sub"}, tracked: []string{".glint.yaml", "go.mod", "internal"}, scopes: []string{"sub"}},
	"extends":         {sources: []string{"a.go"}, head: "extends: conf/base.yaml\n", files: map[string]string{"conf/base.yaml": "version: 1\n\n" + broadBareMarker + "\n"}},
}

// An exception of a rule watching suppressions that keeps one line is a
// finding when it covers more than one file, counted as the run excepts:
// broad-exclusion counted the files of the configuration's directory less
// the default artifact directories, while the walk reads a build directory
// git tracks, so an exception of a.go kept a marker in build/a.go unseen. It
// now counts the files the run reads, matched as the run matches them; a
// nested repository counts, since a run scoped to it reads it under the same
// configuration. The configuration does not, nor one it extends: the run
// excepts no marker there.
func TestBroadExclusionOneLineExceptionCountsWhatTheRunExcepts(t *testing.T) {
	const rule = "suppression-without-reason"
	forms := []string{"file: a.go", "files: a.go", "files: \"*.go\"", "files: \"internal/**\"", "files: \"*\"", "files: \"*.yaml\""}
	for name, tree := range broadFilesTrees {
		for _, form := range forms {
			exception := form + "\nline: 3"
			t.Run(name+"/"+form, func(t *testing.T) {
				root := t.TempDir()
				tree.write(t, root, true, rule)
				tree.track(t, root)
				unexcepted := tree.runFindings(t, root, rule)
				line := tree.write(t, root, true, rule, exception)[0]
				excepted := tree.runFindings(t, root, rule)
				silenced := slices.DeleteFunc(slices.Clone(unexcepted), func(place string) bool { return slices.Contains(excepted, place) })
				reported := slices.Contains(broadPlaces(t, root), fmt.Sprintf(".glint.yaml:%d", line))
				assert.Equal(t, len(silenced) > 1, reported, "the run excepts %v", silenced)
				cfg, err := core.LoadConfigWithDefaults(root)
				require.NoError(t, err)
				exceptions := cfg.GetRuleExceptions("deadcode", rule)
				require.Len(t, exceptions, 1)
				covered, err := broadRunFiles(cfg, exceptions[0].CoversFile)
				require.NoError(t, err)
				assert.Len(t, covered, len(silenced), "broad-exclusion counts %v, the run excepts %v", covered, silenced)
				t.Logf("the run excepts %v", silenced)
			})
		}
	}
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
				root := t.TempDir()
				tree.write(t, root, false, rule)
				unexcepted := tree.runFindings(t, root, rule)
				require.Len(t, unexcepted, len(tree.sources))
				line := tree.write(t, root, false, rule, exception)[0]
				excepted := tree.runFindings(t, root, rule)
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
	covered, err := broadRunFiles(cfg, exceptions[0].CoversFile)
	require.NoError(t, err)
	assert.Equal(t, []string{"cmd/app/a.go"}, covered)
	var places []string
	for _, v := range broadFindingsForTest(t, cfg) {
		places = append(places, fmt.Sprintf("%s:%d", v.File, v.Line))
	}
	assert.NotContains(t, places, fmt.Sprintf(".glint.yaml:%d", line))
}
