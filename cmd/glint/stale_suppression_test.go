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

// The markers in use are known from the result cache too: a second run that
// reuses every finding judges them the same.
func TestStaleSuppressionSeesMarkersThroughTheResultCache(t *testing.T) {
	root := writeStaleModule(t, false)
	dir := t.TempDir()
	first, err := openResultCache(dir, root, "build", "stamp")
	require.NoError(t, err)
	want := staleFindings(t, root, first)
	require.NoError(t, first.save())

	second, err := openResultCache(dir, root, "build", "stamp")
	require.NoError(t, err)
	assert.ElementsMatch(t, want, staleFindings(t, root, second))
	assert.Positive(t, second.reused)
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
            reason: a rule whose files feed each other is not run on excepted ones
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
// stale. Missing files stay dead-config-exception's; rules whose analysis of
// one file feeds their findings on others are not run on excepted files, so
// their exceptions are not judged. A marker naming glint itself names no rule
// — golangci-lint knows no such linter either — so it is stale even where
// golangci-lint is configured.
func TestStaleSuppressionJudgesFileExceptionsAndTheToolName(t *testing.T) {
	root := writeFileExceptionModule(t)
	findings, stale := analyzeWithRules(t, root, nil, fileExceptionRules...)
	assert.Empty(t, foundAt(findings))
	assert.ElementsMatch(t, []string{
		".glint.yaml:9",  // error-string over quiet.go
		".glint.yaml:17", // ignored-error over quiet.go
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
	first, err := openResultCache(dir, root, "build", "stamp")
	require.NoError(t, err)
	_, want := analyzeWithRules(t, root, first, fileExceptionRules...)
	require.NoError(t, first.save())

	second, err := openResultCache(dir, root, "build", "stamp")
	require.NoError(t, err)
	_, got := analyzeWithRules(t, root, second, fileExceptionRules...)
	assert.ElementsMatch(t, foundAt(want), foundAt(got))
	assert.Len(t, foundAt(got), 3)
	assert.Positive(t, second.reused)
}
