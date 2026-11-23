package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/deadcode"
)

const staleConfig = `version: 1
categories:
  patterns:
    rules:
      error-string:
        exceptions:
          - file: errs.go
            function: Wrapped
            reason: the finding it was written for
          - file: errs.go
            function: Clean
            reason: the finding is gone
          - file: moved.go
            function: Gone
            reason: dead-config-exception reports a missing file
`

const staleSource = `package check

import "errors"

func Wrapped() error { return errors.New("Failed to wrap") }

func Clean() error { return errors.New("clean failure") }

func Marked() error {
	//nolint:error-string
	return errors.New("Failed to mark")
}

func Listed() error {
	return errors.New("Failed to list") //nolint:magic-number, error-string
}

func Unused() error {
	//nolint:error-string
	return errors.New("fine")
}

//nolint
func Bare() {}

//nolint:errcheck
func Unknown() {}

//nolint:tombstone-comment
func NotRun() {}
`

// staleFindings analyzes a module with error-string, magic-number and
// stale-suppression enabled, through cache when it is set, and returns the
// stale-suppression findings by file and line.
func staleFindings(t *testing.T, root string, cache *resultCache) []string {
	t.Helper()
	_, stale := analyzeWithRules(t, root, cache, "error-string", "magic-number", "stale-suppression")
	return foundAt(stale)
}

// analyzeWithRules analyzes a module with the named rules enabled and returns
// their findings apart from the stale-suppression ones.
func analyzeWithRules(t *testing.T, root string, cache *resultCache, names ...string) (findings, stale core.ViolationList) {
	t.Helper()
	cfg, all, err := loadConfig(root)
	require.NoError(t, err)
	var enabled []rules.Rule
	for _, rule := range all {
		if slices.Contains(names, rule.Name()) {
			enabled = append(enabled, rule)
		}
	}
	require.Len(t, enabled, len(names))
	prepared, err := prepareAnalysis(core.NewGoProjectLoader(), root, cfg, enabled, false)
	require.NoError(t, err)
	rules.ResetState(enabled)
	violations, err := analyzeProject(prepared.contexts, enabled, cfg, prepared.project, cache)
	require.NoError(t, err)
	findings, suppressions := core.SplitSuppressions(violations)
	stale, err = staleSuppressions(enabled, deadcode.StaleSuppressionRun{
		Contexts: prepared.contexts, Suppressions: suppressions, Config: cfg, WholeRoot: true,
	})
	require.NoError(t, err)
	return findings, stale
}

func foundAt(violations core.ViolationList) []string {
	var found []string
	for _, v := range violations {
		found = append(found, v.Location())
	}
	return found
}

func writeStaleModule(t *testing.T, golangci bool) string {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{
		"go.mod":      "module example.com/check\n\ngo 1.24\n",
		".glint.yaml": staleConfig,
		"errs.go":     staleSource,
	}
	if golangci {
		files[".golangci.yml"] = "version: \"2\"\n"
	}
	for name, content := range files {
		require.NoError(t, os.WriteFile(filepath.Join(root, name), []byte(content), 0o644))
	}
	return root
}

// A marker or an exception that silenced a finding of the run is in use; one
// that silenced nothing is stale. Each name of a nolint list (with a space
// after the comma) is judged on its own; a bare nolint and a name that is no
// glint rule silence nothing; markers of rules the run did not execute and
// exceptions of missing files are left alone.
func TestStaleSuppressionReportsMarkersAndExceptionsThatSilenceNothing(t *testing.T) {
	root := writeStaleModule(t, false)
	assert.ElementsMatch(t, []string{
		".glint.yaml:10", // exception for Clean, whose error string is fine
		"errs.go:15",     // magic-number in the list
		"errs.go:19",     // marker over a lower-case error string
		"errs.go:23",     // bare //nolint directive
		"errs.go:26",     // errcheck without golangci-lint
	}, staleFindings(t, root, nil))
}

// With golangci-lint configured, a name glint does not know is its linter.
func TestStaleSuppressionLeavesGolangciNamesToGolangci(t *testing.T) {
	root := writeStaleModule(t, true)
	assert.NotContains(t, staleFindings(t, root, nil), "errs.go:26")
}

// An exception of a rule the run did not execute matched nothing because
// nothing ran to match it: it is left alone, as the markers of such a rule.
func TestStaleSuppressionLeavesExceptionsOfRulesThatDidNotRun(t *testing.T) {
	root := writeStaleModule(t, false)
	_, stale := analyzeWithRules(t, root, nil, "magic-number", "stale-suppression")
	assert.NotContains(t, foundAt(stale), ".glint.yaml:10")
}

// A stale marker after code is told to cover its line only, one on a line of
// its own the next line too.
func TestStaleSuppressionTellsTheLinesAMarkerCovers(t *testing.T) {
	_, stale := analyzeWithRules(t, writeStaleModule(t, false), nil, "error-string", "magic-number", "stale-suppression")
	messages := map[string]string{}
	for _, v := range stale {
		messages[v.Location()] = v.Message
	}
	// Go reads a marker after code as golangci-lint does: it covers the
	// line under it too.
	assert.True(t, strings.HasSuffix(messages["errs.go:15"], "reports nothing on this line or the next"), messages["errs.go:15"])
	assert.True(t, strings.HasSuffix(messages["errs.go:19"], "reports nothing on this line or the next"), messages["errs.go:19"])
}

// The markers in use are known from the result cache too: a second run that
// reuses every finding judges them the same.
func TestStaleSuppressionSeesMarkersThroughTheResultCache(t *testing.T) {
	root := writeStaleModule(t, false)
	dir := t.TempDir()
	first, err := openResultCache(dir, root, "", "build", "stamp")
	require.NoError(t, err)
	want := staleFindings(t, root, first)
	require.NoError(t, first.save())

	second, err := openResultCache(dir, root, "", "build", "stamp")
	require.NoError(t, err)
	assert.ElementsMatch(t, want, staleFindings(t, root, second))
	assert.Positive(t, second.reused)
}

// Flow-list exceptions share a YAML line but must keep independent keys in
// suppression entries, including findings reused from the result cache.
func TestStaleSuppressionFlowListThroughResultCache(t *testing.T) {
	root := t.TempDir()
	t.Setenv("GLINT_CACHE_DIR", t.TempDir())
	writeModuleFile(t, root, "go.mod", "module example.com/flow\n\ngo 1.24\n")
	writeModuleFile(t, root, "errs.go", `package flow

import "errors"

func Used() error { return errors.New("Failed to report") }
func Stale() error { return nil }
`)
	config := `version: 1
categories:
  patterns:
    rules:
      error-string:
        exceptions: [{file: errs.go, function: Used, reason: known}, {file: errs.go, function: Stale, reason: no finding}]
`
	writeModuleFile(t, root, ".glint.yaml", config)
	cfg, err := core.LoadConfigWithDefaults(root)
	require.NoError(t, err)
	cache, err := newRootCache(root, "", cfg, false)
	require.NoError(t, err)
	_, uncached := analyzeWithRules(t, root, nil, "error-string", "stale-suppression")
	require.Equal(t, []string{".glint.yaml:6"}, foundAt(uncached))
	require.Len(t, uncached, 1)
	assert.Contains(t, uncached[0].Message, `file "errs.go"`)
	assert.Contains(t, uncached[0].Message, `function "Stale"`)
	assert.NotContains(t, uncached[0].Message, `function "Used"`)
	_, first := analyzeWithRules(t, root, cache, "error-string", "stale-suppression")
	assert.Equal(t, foundAt(uncached), foundAt(first))
	require.NoError(t, cache.save())
	warm, err := newRootCache(root, "", cfg, false)
	require.NoError(t, err)
	_, cached := analyzeWithRules(t, root, warm, "error-string", "stale-suppression")
	assert.Equal(t, foundAt(uncached), foundAt(cached))
	assert.Positive(t, warm.reused)

	blockConfig := `version: 1
categories:
  patterns:
    rules:
      error-string:
        exceptions:
          - file: errs.go
            function: Used
            reason: known
          - file: errs.go
            function: Stale
            reason: no finding
`
	writeModuleFile(t, root, ".glint.yaml", blockConfig)
	_, blockStale := analyzeWithRules(t, root, nil, "error-string", "stale-suppression")
	assert.Equal(t, []string{".glint.yaml:10"}, foundAt(blockStale))
	assert.Contains(t, blockStale[0].Message, `function "Stale"`)
}

// Moving configuration changes exception locations even when its analysis
// settings remain equivalent. Cached suppression entries must identify the
// current exception, while an exception that silences nothing stays stale.
func TestStaleSuppressionAfterConfigMovesWithResultCache(t *testing.T) {
	root := t.TempDir()
	t.Setenv("GLINT_CACHE_DIR", t.TempDir())
	writeModuleFile(t, root, "go.mod", "module example.com/projectA\n\ngo 1.24\n")
	writeModuleFile(t, root, "logic.go", "package projectA\nfunc Complex(x int) int { if x > 0 { return 1 }; return 0 }\nfunc Simple() int { return 0 }\n")
	config := `version: 1
categories:
  architecture:
    rules:
      cyclomatic-complexity:
        settings:
          max_complexity: 1
        exceptions:
          - file: logic.go
            function: Complex
            reason: known finding
          - file: logic.go
            function: Simple
            reason: no finding remains
`
	settings := "settings:\n  fail_on: low\n\n"
	for _, tc := range []struct{ name, config, stale string }{
		{"initial", config, ".glint.yaml:12"},
		{"settings first", settings + config, ".glint.yaml:15"},
		{"settings last", config + "\n" + settings, ".glint.yaml:12"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			writeModuleFile(t, root, ".glint.yaml", tc.config)
			cfg, _, err := loadConfig(root)
			require.NoError(t, err)
			cache, err := newRootCache(root, "", cfg, false)
			require.NoError(t, err)
			_, uncached := analyzeWithRules(t, root, nil, "cyclomatic-complexity", "stale-suppression")
			_, cached := analyzeWithRules(t, root, cache, "cyclomatic-complexity", "stale-suppression")
			assert.Equal(t, []string{tc.stale}, foundAt(uncached))
			assert.Equal(t, foundAt(uncached), foundAt(cached))
			require.NoError(t, cache.save())
			warm, err := newRootCache(root, "", cfg, false)
			require.NoError(t, err)
			_, cachedAgain := analyzeWithRules(t, root, warm, "cyclomatic-complexity", "stale-suppression")
			assert.Equal(t, foundAt(uncached), foundAt(cachedAgain))
			assert.Positive(t, warm.reused)
		})
	}
}

func TestStaleSuppressionAfterProjectExceptionMovesWithResultCache(t *testing.T) {
	root := t.TempDir()
	t.Setenv("GLINT_CACHE_DIR", t.TempDir())
	writeModuleFile(t, root, "go.mod", "module example.com/projectA\n\ngo 1.24\n")
	writeModuleFile(t, root, "logic.go", `package projectA

func projectAFirst(x int) int {
	a := x + 1
	b := a * 2
	c := b + 3
	d := c * 4
	return d + 5
}

func projectACopy(x int) int {
	a := x + 2
	b := a * 2
	c := b + 3
	d := c * 4
	return d + 5
}

func projectASolo(x int) int {
	return x
}
`)
	config := `version: 1
categories:
  duplication:
    rules:
      near-duplicate-func:
        exceptions:
          - file: logic.go
            function: projectACopy
            reason: known project finding
          - file: logic.go
            function: projectASolo
            reason: no finding remains
`
	run := func() (findings, stale core.ViolationList, cache *resultCache) {
		t.Helper()
		cfg, all, err := loadConfig(root)
		require.NoError(t, err)
		var enabled []rules.Rule
		for _, rule := range all {
			if slices.Contains([]string{"near-duplicate-func", "stale-suppression"}, rule.Name()) {
				enabled = append(enabled, rule)
			}
		}
		require.Len(t, enabled, 2)
		prepared, err := prepareAnalysis(core.NewGoProjectLoader(), root, cfg, enabled, true)
		require.NoError(t, err)
		rules.ResetState(enabled)
		violations, err := analyzeProject(prepared.contexts, enabled, cfg, prepared.project, prepared.cache)
		require.NoError(t, err)
		findings, suppressions := core.SplitSuppressions(violations)
		stale, err = staleSuppressions(enabled, deadcode.StaleSuppressionRun{
			Contexts: prepared.contexts, Suppressions: suppressions, Config: cfg, WholeRoot: true,
		})
		require.NoError(t, err)
		require.NoError(t, prepared.cache.save())
		return findings, stale, prepared.cache
	}
	writeModuleFile(t, root, ".glint.yaml", config)
	initialFindings, initialStale, _ := run()
	assert.Empty(t, foundAt(initialFindings), "the project exception silences the near-duplicate finding")
	assert.Equal(t, []string{".glint.yaml:10"}, foundAt(initialStale), "only the exception without a finding is stale")

	shiftedConfig := "settings:\n  fail_on: low\n\n" + config
	writeModuleFile(t, root, ".glint.yaml", shiftedConfig)
	uncachedFindings, uncachedStale := analyzeWithRules(t, root, nil, "near-duplicate-func", "stale-suppression")
	cachedFindings, cachedStale, cached := run()
	assert.Empty(t, foundAt(uncachedFindings), "the moved project exception still silences the finding")
	assert.Equal(t, []string{".glint.yaml:13"}, foundAt(uncachedStale), "the moved dead exception is stale")
	assert.Equal(t, foundAt(uncachedFindings), foundAt(cachedFindings))
	assert.Equal(t, foundAt(uncachedStale), foundAt(cachedStale))
	assert.NotNil(t, cached.projectHit, "the project cache is selected by unchanged inputs")
}

const atoiSource = `package check

import "strconv"

func Width(wl string) int {
	w, _ := strconv.Atoi(wl) MARKER
	return w
}
`

// Only a marker naming the rule silences it: a nolint for another linter
// leaves the finding in place and is itself reported as silencing nothing.
func TestOnlyTheRulesOwnMarkerSilencesIgnoredError(t *testing.T) {
	for _, tc := range []struct {
		marker        string
		ignored, dead int
	}{
		{marker: "//nolint:errcheck // not a number is zero", ignored: 1, dead: 1},
		{marker: "//nolint:ignored-error // not a number is zero", ignored: 0, dead: 0},
	} {
		t.Run(tc.marker, func(t *testing.T) {
			root := t.TempDir()
			for name, content := range map[string]string{
				"go.mod":  "module example.com/check\n\ngo 1.24\n",
				"atoi.go": strings.Replace(atoiSource, "MARKER", tc.marker, 1),
			} {
				require.NoError(t, os.WriteFile(filepath.Join(root, name), []byte(content), 0o644))
			}
			findings, stale := analyzeWithRules(t, root, nil, "ignored-error", "stale-suppression")
			assert.Len(t, findings, tc.ignored)
			require.Len(t, stale, tc.dead)
			if tc.dead > 0 {
				assert.Equal(t, "atoi.go:6", stale[0].Location())
				assert.Contains(t, stale[0].Message, "errcheck")
			}
		})
	}
}

const fileExceptionConfig = `version: 1
categories:
  patterns:
    rules:
      error-string:
        exceptions:
          - files: "loud*.go"
            reason: the finding it was written for
          - files: "**/quiet.go"
            reason: the file has no such finding
          - file: missing.go
            reason: dead-config-exception reports a missing file
      ignored-error:
        exceptions:
          - files: "drop.go"
            reason: a project rule's finding in the file
          - files: "quiet.go"
            reason: the file drops no error
  duplication:
    rules:
      cross-file-duplicate:
        exceptions:
          - files: "quiet.go"
            reason: the file copies nothing
`

var fileExceptionModule = map[string]string{
	"go.mod":        "module example.com/check\n\ngo 1.24\n",
	".golangci.yml": "version: \"2\"\n",
	".glint.yaml":   fileExceptionConfig,
	"loud.go": `package check

import "errors"

func Loud() error { return errors.New("Failed loudly") }
`,
	"quiet.go": `package check

import "errors"

func Quiet() error { return errors.New("quiet failure") }

//nolint:glint
func Tool() {}

//nolint:somelinter
func Other() {}
`,
	"drop.go": `package check

func produce() error { return nil }

func Drop() { _ = produce() }
`,
}

// A file-only exception is judged like any other: the rule runs on the files
// it names, and an exception none of whose files has a finding of the rule is
// stale. Missing files stay dead-config-exception's; a rule comparing files
// learns the root before it runs, so it runs on an excepted file without
// changing what it finds elsewhere. A marker naming glint itself names no rule
// — golangci-lint knows no such linter either — so it is stale even where
// golangci-lint is configured.
func TestStaleSuppressionJudgesFileExceptionsAndTheToolName(t *testing.T) {
	root := writeFileExceptionModule(t)
	findings, stale := analyzeWithRules(t, root, nil, fileExceptionRules...)
	assert.Empty(t, foundAt(findings))
	assert.ElementsMatch(t, []string{
		".glint.yaml:9",  // error-string over quiet.go
		".glint.yaml:17", // ignored-error over quiet.go
		".glint.yaml:23", // cross-file-duplicate over quiet.go
		"quiet.go:7",     // the marker naming the tool
	}, foundAt(stale))
}

var fileExceptionRules = []string{"error-string", "ignored-error", "cross-file-duplicate", "stale-suppression"}

func writeFileExceptionModule(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for name, content := range fileExceptionModule {
		require.NoError(t, os.WriteFile(filepath.Join(root, name), []byte(content), 0o644))
	}
	return root
}

// The findings in excepted files reach the verdict through the result cache
// too: a second run that reuses them judges the file exceptions the same.
func TestStaleSuppressionSeesFileExceptionsThroughTheResultCache(t *testing.T) {
	root := writeFileExceptionModule(t)
	dir := t.TempDir()
	first, err := openResultCache(dir, root, "", "build", "stamp")
	require.NoError(t, err)
	_, want := analyzeWithRules(t, root, first, fileExceptionRules...)
	require.NoError(t, first.save())

	second, err := openResultCache(dir, root, "", "build", "stamp")
	require.NoError(t, err)
	_, got := analyzeWithRules(t, root, second, fileExceptionRules...)
	assert.ElementsMatch(t, foundAt(want), foundAt(got))
	assert.Len(t, foundAt(got), 4)
	assert.Positive(t, second.reused)
}

var hashCommentModule = map[string]string{
	"go.mod": "module example.com/check\n\ngo 1.24\n",
	"deploy.sh": `#!/usr/bin/env bash
set -euo pipefail
# secret-exposure: safe - nothing below prints a secret
echo "start"
echo "$API_TOKEN" # secret-exposure: safe - the operator asked for it
echo "# secret-exposure: safe"
echo "${#API_TOKEN}"
#nolint
echo done
`,
	".github/workflows/ci.yml": `steps:
  # nolint:secret-exposure - nothing here prints a secret
  - run: make test
`,
}

// Scripts, YAML and the other files that comment with '#' have their markers
// judged like Go's: a marker that silences nothing is stale, one that
// silences a finding is not, and a '#' inside quotes or ${#var} is no marker.
func TestStaleSuppressionJudgesHashCommentMarkers(t *testing.T) {
	root := t.TempDir()
	for name, content := range hashCommentModule {
		require.NoError(t, os.MkdirAll(filepath.Dir(filepath.Join(root, name)), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(root, name), []byte(content), 0o644))
	}
	findings, stale := analyzeWithRules(t, root, nil, "secret-exposure", "stale-suppression")
	assert.Empty(t, foundAt(findings))
	assert.ElementsMatch(t, []string{"deploy.sh:3", "deploy.sh:8", ".github/workflows/ci.yml:2"}, foundAt(stale))
}

// A marker in embedded script (a multi-line quote, a heredoc body, a block
// scalar) covers the next line only while it is still in that script: the
// line after the closing quote or the terminator is the outer file's, and a
// stale marker at the end of the script is told to cover its own line.
func TestStaleSuppressionKeepsEmbeddedMarkersInTheirScript(t *testing.T) {
	root := t.TempDir()
	for name, content := range map[string]string{
		"go.mod": "module example.com/check\n\ngo 1.24\n",
		"deploy.sh": `#!/usr/bin/env bash
ssh host.example "
  # secret-exposure: safe - the remote end prints nothing
"
echo "$API_TOKEN"
bash <<EOF
# secret-exposure: safe - the operator asked for it
echo "$API_TOKEN"
EOF
`,
		".github/workflows/ci.yml": `steps:
  - run: |
      make test
      # nolint:secret-exposure - nothing below prints a secret
  - run: make lint
`,
	} {
		require.NoError(t, os.MkdirAll(filepath.Dir(filepath.Join(root, name)), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(root, name), []byte(content), 0o644))
	}
	findings, stale := analyzeWithRules(t, root, nil, "secret-exposure", "stale-suppression")
	assert.ElementsMatch(t, []string{"deploy.sh:5"}, foundAt(findings))
	messages := map[string]string{}
	for _, v := range stale {
		messages[v.Location()] = v.Message
	}
	assert.Len(t, messages, 2, foundAt(stale))
	assert.True(t, strings.HasSuffix(messages["deploy.sh:3"], "reports nothing on this line"), messages["deploy.sh:3"])
	assert.True(t, strings.HasSuffix(messages[".github/workflows/ci.yml:4"], "reports nothing on this line"), messages[".github/workflows/ci.yml:4"])
}

// A fresh worktree starts from the cache of the main worktree, whose entries
// name the exceptions they used: the same exception of the worktree's own
// configuration file is in use there too, though that file has another path.
func TestStaleSuppressionSeesExceptionsThroughASeededCache(t *testing.T) {
	module := func() string {
		root := t.TempDir()
		for name, content := range map[string]string{
			"go.mod":  "module example.com/check\n\ngo 1.24\n",
			"stub.go": "package check\n\n// MockClient answers fixed values.\ntype MockClient struct{}\n",
			".glint.yaml": `version: 1
categories:
  patterns:
    rules:
      mock-identifier:
        exceptions:
          - files: "stub.go"
            reason: the rule's own subject
`,
		} {
			require.NoError(t, os.WriteFile(filepath.Join(root, name), []byte(content), 0o644))
		}
		return root
	}
	main, worktree := module(), module()
	dir := t.TempDir()
	first, err := openResultCache(dir, main, "", "build", "stamp")
	require.NoError(t, err)
	_, want := analyzeWithRules(t, main, first, "mock-identifier", "stale-suppression")
	require.NoError(t, first.save())
	require.Empty(t, foundAt(want))

	seeded, err := openResultCache(dir, worktree, main, "build", "stamp")
	require.NoError(t, err)
	_, got := analyzeWithRules(t, worktree, seeded, "mock-identifier", "stale-suppression")
	assert.Empty(t, foundAt(got))
	assert.Positive(t, seeded.reused)
}
