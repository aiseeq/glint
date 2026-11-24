// The checks below run `glint check` in a child of the test binary and read
// only the report the child prints on stdout: checkShownIn discards the exit
// status and stderr of the child, where a race build reports a data race
// (WARNING: DATA RACE, exit status 66). The race build of these tests would
// find nothing, while each of them starts the race-built analysis of every
// rule several times. They run in the plain test task; the race build leaves
// them out. The concurrent analysis they start stays under -race in
// TestAnalyzeFilesIsDeterministicAndRaceFree and
// TestProjectRulesAreDeterministicAndRaceFree, and in children whose exit
// status fails the test: TestProjectCacheExcludedConfiguredMigrationMatchesNoCache,
// TestScopedGoRunKeepsDeadConfigExceptionFinding, the TestSQLChild tests.

//go:build !race

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
)

// checkShown runs `glint check . --no-cache -o json -s <severity>` in a
// project made of files and returns the findings of the named rules.
func checkShown(t *testing.T, files map[string]string, severity string, ruleNames ...string) []shownFinding {
	t.Helper()
	return checkShownIn(t, oversightProject(t, files), "", severity, ruleNames...)
}

func oversightProject(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for path, contents := range files {
		require.NoError(t, os.MkdirAll(filepath.Dir(filepath.Join(root, path)), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(root, path), []byte(contents), 0o644))
	}
	return root
}

// checkShownIn runs the check in root, with the result cache in cacheDir;
// without one when cacheDir is "".
func checkShownIn(t *testing.T, root, cacheDir, severity string, ruleNames ...string) []shownFinding {
	t.Helper()
	args := []string{"-C", root, "check", ".", "-o", "json", "-s", severity}
	if cacheDir == "" {
		args = append(args, "--no-cache")
	}
	cmd := mainSubprocess(t, args)
	if cacheDir != "" {
		cmd.Env = append(cmd.Env, "GLINT_CACHE_DIR="+cacheDir)
	}
	// A finding at fail_on exits non-zero; the report on stdout is what counts.
	output, _ := cmd.Output()
	var report struct {
		Issues []shownFinding `json:"issues"`
	}
	// The test binary prints its own verdict after the report.
	require.NoError(t, json.NewDecoder(bytes.NewReader(output)).Decode(&report), "report:\n%s", output)
	var kept []shownFinding
	for _, finding := range report.Issues {
		if slices.Contains(ruleNames, finding.Rule) {
			kept = append(kept, finding)
		}
	}
	return kept
}

// hotMarkerSource silences a finding of format-before-branch, medium in a
// function marked hot (line 10) and low in an ordinary one (line 19).
const hotMarkerSource = "package main\n\nimport (\n\t\"errors\"\n\t\"fmt\"\n)\n\n" +
	"//glint:hot\nfunc Charge(a, t int, dmg int) error {\n\t// nolint:format-before-branch\n\tmsg := fmt.Sprintf(\"charge %d on %d\", a, t)\n\tif dmg < 0 {\n\t\treturn errors.New(msg)\n\t}\n\treturn nil\n}\n\n" +
	"func Refund(a, t int, dmg int) error {\n\t// nolint:format-before-branch\n\tmsg := fmt.Sprintf(\"refund %d on %d\", a, t)\n\tif dmg < 0 {\n\t\treturn errors.New(msg)\n\t}\n\treturn nil\n}\n\n" +
	"func main() { println(Charge(1, 2, 3), Refund(1, 2, 3)) }\n"

// A marker without a reason is as severe as the findings it silences: one
// over a medium finding is seen at min_severity medium, and hidden at high,
// where the finding itself would be. At low it is where it always was.
func TestBareMarkerTakesTheSeverityOfWhatItSilences(t *testing.T) {
	files := map[string]string{
		"go.mod":      oversightModule,
		".glint.yaml": "version: 1\n",
		"main.go":     "package main\n\n//nolint:interface-any\nvar holder interface{}\n\nfunc main() { println(holder) }\n",
	}
	want := []shownFinding{{Rule: core.SuppressionReasonRule, File: "main.go", Line: 3, Severity: "medium"}}
	assert.Equal(t, want, checkShown(t, files, "medium", core.SuppressionReasonRule), "min_severity medium")
	assert.Equal(t, want, checkShown(t, files, "low", core.SuppressionReasonRule), "min_severity low")
	assert.Empty(t, checkShown(t, files, "high", core.SuppressionReasonRule), "min_severity high")
}

// A marker with a reason has no oversight finding at any severity.
func TestReasonedMarkerOverAMediumFindingIsNoFinding(t *testing.T) {
	files := map[string]string{
		"go.mod":      oversightModule,
		".glint.yaml": "version: 1\n",
		"main.go":     "package main\n\n//nolint:interface-any the decoder fills it with any value\nvar holder interface{}\n\nfunc main() { println(holder) }\n",
	}
	assert.Empty(t, checkShown(t, files, "low", core.SuppressionReasonRule))
}

// A marker over a low finding stays low: min_severity medium hides it.
func TestBareMarkerOverALowFindingStaysLow(t *testing.T) {
	files := map[string]string{
		"go.mod":      oversightModule,
		".glint.yaml": "version: 1\n",
		"main.go":     "package main\n\nvar () // nolint:empty-decl-group\n\nfunc main() {}\n",
	}
	assert.Empty(t, checkShown(t, files, "medium", core.SuppressionReasonRule), "min_severity medium")
	assert.Equal(t, []shownFinding{{Rule: core.SuppressionReasonRule, File: "main.go", Line: 3, Severity: "low"}},
		checkShown(t, files, "low", core.SuppressionReasonRule), "min_severity low")
}

// A marker that silences findings of two rules is as severe as the higher.
func TestBareMarkerOverTwoFindingsTakesTheHigher(t *testing.T) {
	files := map[string]string{
		"go.mod":      oversightModule,
		".glint.yaml": "version: 1\n",
		"main.go":     "package main\n\n//nolint:interface-any,hardcoded-secret\nvar Password = \"hunter2hunter2\"; var Holder interface{}\n\nfunc main() { println(Password, Holder) }\n",
	}
	assert.Equal(t, []shownFinding{{Rule: core.SuppressionReasonRule, File: "main.go", Line: 3, Severity: "critical"}},
		checkShown(t, files, "high", core.SuppressionReasonRule))
}

// A marker over a finding a hot function raises to medium is medium: seen at
// min_severity medium, where the finding itself would be; the same marker in
// an ordinary function stays low. A severity configured for the rule replaces
// both, as it does for the findings.
func TestBareMarkerInAHotFunctionTakesTheRaisedSeverity(t *testing.T) {
	files := map[string]string{"go.mod": oversightModule, ".glint.yaml": "version: 1\n", "main.go": hotMarkerSource}
	assert.Equal(t, []shownFinding{{Rule: core.SuppressionReasonRule, File: "main.go", Line: 10, Severity: "medium"}},
		checkShown(t, files, "medium", core.SuppressionReasonRule), "min_severity medium")
	assert.Equal(t, []shownFinding{
		{Rule: core.SuppressionReasonRule, File: "main.go", Line: 10, Severity: "medium"},
		{Rule: core.SuppressionReasonRule, File: "main.go", Line: 19, Severity: "low"},
	}, checkShown(t, files, "low", core.SuppressionReasonRule), "min_severity low")

	configured := func(severity string) map[string]string {
		return map[string]string{"go.mod": oversightModule, "main.go": hotMarkerSource,
			".glint.yaml": "version: 1\ncategories:\n  patterns:\n    rules:\n      format-before-branch:\n        enabled: true\n        severity: " + severity + "\n"}
	}
	assert.Equal(t, []shownFinding{
		{Rule: core.SuppressionReasonRule, File: "main.go", Line: 10, Severity: "low"},
		{Rule: core.SuppressionReasonRule, File: "main.go", Line: 19, Severity: "low"},
	}, checkShown(t, configured("low"), "low", core.SuppressionReasonRule), "the rule configured low")
	assert.Equal(t, []shownFinding{
		{Rule: core.SuppressionReasonRule, File: "main.go", Line: 10, Severity: "high"},
		{Rule: core.SuppressionReasonRule, File: "main.go", Line: 19, Severity: "high"},
	}, checkShown(t, configured("high"), "high", core.SuppressionReasonRule), "the rule configured high")
}

// The finding about a marker without a reason is as severe as what that
// marker silenced, not every marker of its line: a reasoned marker over a
// secret and a bare one over a low finding on one line leave a low finding.
// Two bare markers on one line are one finding, as severe as the higher; a
// marker on the line above and one at the end of the line are each their own.
func TestMarkerFindingTakesTheSeverityOfItsOwnMarker(t *testing.T) {
	for name, tt := range map[string]struct {
		source string
		want   []shownFinding
	}{
		"reasoned secret, bare low": {
			source: "var (); var Password = \"hunter2hunter2\" /* hardcoded-secret: safe — fixture value, not a real credential */ // nolint:empty-decl-group\n",
			want:   []shownFinding{{Rule: core.SuppressionReasonRule, File: "main.go", Line: 3, Severity: "low"}},
		},
		"reasoned low, bare secret": {
			source: "var (); var Password = \"hunter2hunter2\" /* empty-decl-group: safe — kept for the generator */ // nolint:hardcoded-secret\n",
			want:   []shownFinding{{Rule: core.SuppressionReasonRule, File: "main.go", Line: 3, Severity: "critical"}},
		},
		"bare secret, bare low": {
			source: "var (); var Password = \"hunter2hunter2\" /* nolint:hardcoded-secret */ // nolint:empty-decl-group\n",
			want:   []shownFinding{{Rule: core.SuppressionReasonRule, File: "main.go", Line: 3, Severity: "critical"}},
		},
		"bare low, bare secret": {
			source: "var (); var Password = \"hunter2hunter2\" /* nolint:empty-decl-group */ // nolint:hardcoded-secret\n",
			want:   []shownFinding{{Rule: core.SuppressionReasonRule, File: "main.go", Line: 3, Severity: "critical"}},
		},
		"secret above, low at the end": {
			source: "// nolint:hardcoded-secret\nvar (); var Password = \"hunter2hunter2\" // nolint:empty-decl-group\n",
			want: []shownFinding{
				{Rule: core.SuppressionReasonRule, File: "main.go", Line: 3, Severity: "critical"},
				{Rule: core.SuppressionReasonRule, File: "main.go", Line: 4, Severity: "low"},
			},
		},
		"low above, secret at the end": {
			source: "// nolint:empty-decl-group\nvar (); var Password = \"hunter2hunter2\" // nolint:hardcoded-secret\n",
			want: []shownFinding{
				{Rule: core.SuppressionReasonRule, File: "main.go", Line: 3, Severity: "low"},
				{Rule: core.SuppressionReasonRule, File: "main.go", Line: 4, Severity: "critical"},
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			files := map[string]string{
				"go.mod":      oversightModule,
				".glint.yaml": "version: 1\n",
				"main.go":     "package main\n\n" + tt.source + "\nfunc main() { println(Password) }\n",
			}
			assert.Equal(t, tt.want, checkShown(t, files, "low", core.SuppressionReasonRule, "hardcoded-secret", "empty-decl-group"))
		})
	}
}

// A marker of stale-suppression that silences its finding — a medium one,
// reported after the file rules ran — is medium; the stale marker it covers
// silences nothing and stays low.
func TestBareMarkerOverAStaleFindingIsMedium(t *testing.T) {
	files := map[string]string{
		"go.mod":      oversightModule,
		".glint.yaml": "version: 1\n",
		"main.go":     "package main\n\n//nolint:stale-suppression\n//nolint:interface-any\nvar holder = 1\n\nfunc main() { println(holder) }\n",
	}
	assert.Equal(t, []shownFinding{{Rule: core.SuppressionReasonRule, File: "main.go", Line: 3, Severity: "medium"}},
		checkShown(t, files, "medium", core.SuppressionReasonRule, "stale-suppression"))
	assert.Equal(t, []shownFinding{
		{Rule: core.SuppressionReasonRule, File: "main.go", Line: 3, Severity: "medium"},
		{Rule: core.SuppressionReasonRule, File: "main.go", Line: 4, Severity: "low"},
	}, checkShown(t, files, "low", core.SuppressionReasonRule, "stale-suppression"))

	files[".glint.yaml"] = "version: 1\ncategories:\n  deadcode:\n    rules:\n      stale-suppression:\n        enabled: true\n        severity: high\n"
	assert.Equal(t, []shownFinding{{Rule: core.SuppressionReasonRule, File: "main.go", Line: 3, Severity: "high"}},
		checkShown(t, files, "high", core.SuppressionReasonRule, "stale-suppression"), "stale-suppression configured high")
}

// A broad exception of the configuration that silences a critical finding is
// reported as critical; one that silences nothing stays low.
func TestBroadExceptionTakesTheSeverityOfWhatItSilences(t *testing.T) {
	config := "version: 1\ncategories:\n  security:\n    rules:\n      hardcoded-secret:\n        exceptions:\n          - files: \"**/*.go\"\n            reason: fixtures of the vendored client\n"
	secret := map[string]string{
		"go.mod":      oversightModule,
		".glint.yaml": config,
		"main.go":     "package main\n\nvar Password = \"hunter2hunter2\"\n\nfunc main() { println(Password) }\n",
	}
	assert.Equal(t, []shownFinding{{Rule: broadExclusionRule, File: ".glint.yaml", Line: 7, Severity: "critical"}},
		checkShown(t, secret, "high", broadExclusionRule))

	clean := map[string]string{
		"go.mod":      oversightModule,
		".glint.yaml": config,
		"main.go":     "package main\n\nfunc main() {}\n",
	}
	assert.Empty(t, checkShown(t, clean, "medium", broadExclusionRule), "min_severity medium")
	assert.Equal(t, []shownFinding{{Rule: broadExclusionRule, File: ".glint.yaml", Line: 7, Severity: "low"}},
		checkShown(t, clean, "low", broadExclusionRule), "min_severity low")
}

// An exception of suppression-without-reason that silences the finding about
// a bare marker over a critical finding is as severe as that finding,
// whether it keeps the rule off the file or matches the finding by a
// pattern.
func TestExceptionOfTheReasonRuleTakesTheSeverityOfTheMarker(t *testing.T) {
	for name, exception := range map[string]string{
		"files":   "          - files: \"*.go\"\n            reason: generated markers\n",
		"pattern": "          - files: \"*.go\"\n            pattern: has no reason\n            reason: generated markers\n",
	} {
		t.Run(name, func(t *testing.T) {
			files := map[string]string{
				"go.mod":      oversightModule,
				".glint.yaml": "version: 1\ncategories:\n  deadcode:\n    rules:\n      suppression-without-reason:\n        exceptions:\n" + exception,
				"main.go":     "package main\n\n//nolint:hardcoded-secret\nvar Password = \"hunter2hunter2\"\n\nfunc main() { println(Password) }\n",
			}
			assert.Equal(t, []shownFinding{{Rule: broadExclusionRule, File: ".glint.yaml", Line: 7, Severity: "critical"}},
				checkShown(t, files, "high", broadExclusionRule, core.SuppressionReasonRule))
		})
	}
}

// An exception of suppression-without-reason over the finding about a bare
// marker of a low rule is low, though a reasoned marker on the same line
// silences a secret — whether the exception keeps the rule off the file or
// matches the finding by a pattern.
func TestExceptionOfTheReasonRuleTakesTheSeverityOfItsOwnMarker(t *testing.T) {
	for name, exception := range map[string]string{
		"files":   "          - files: \"*.go\"\n            reason: generated markers\n",
		"pattern": "          - files: \"*.go\"\n            pattern: has no reason\n            reason: generated markers\n",
	} {
		t.Run(name, func(t *testing.T) {
			files := map[string]string{
				"go.mod":      oversightModule,
				".glint.yaml": "version: 1\ncategories:\n  deadcode:\n    rules:\n      suppression-without-reason:\n        exceptions:\n" + exception,
				"main.go":     "package main\n\nvar (); var Password = \"hunter2hunter2\" /* hardcoded-secret: safe — fixture value, not a real credential */ // nolint:empty-decl-group\n\nfunc main() { println(Password) }\n",
			}
			assert.Empty(t, checkShown(t, files, "medium", broadExclusionRule, core.SuppressionReasonRule), "min_severity medium")
			assert.Equal(t, []shownFinding{{Rule: broadExclusionRule, File: ".glint.yaml", Line: 7, Severity: "low"}},
				checkShown(t, files, "low", broadExclusionRule, core.SuppressionReasonRule), "min_severity low")
		})
	}
}

// The silenced finding is rated as the configuration reports it: a severity
// set for the rule rates the marker too.
func TestBareMarkerTakesTheConfiguredSeverity(t *testing.T) {
	files := map[string]string{
		"go.mod":      oversightModule,
		".glint.yaml": "version: 1\ncategories:\n  typesafety:\n    rules:\n      interface-any:\n        enabled: true\n        severity: high\n",
		"main.go":     "package main\n\n//nolint:interface-any\nvar holder interface{}\n\nfunc main() { println(holder) }\n",
	}
	assert.Equal(t, []shownFinding{{Rule: core.SuppressionReasonRule, File: "main.go", Line: 3, Severity: "high"}},
		checkShown(t, files, "high", core.SuppressionReasonRule))
}

// A run that takes the findings of an unchanged file from the result cache
// rates the marker as the run that stored them.
func TestBareMarkerSeverityThroughTheResultCache(t *testing.T) {
	root := oversightProject(t, map[string]string{
		"go.mod":      oversightModule,
		".glint.yaml": "version: 1\n",
		"main.go":     "package main\n\n//nolint:interface-any\nvar holder interface{}\n\nfunc main() { println(holder) }\n",
	})
	cacheDir := t.TempDir()
	want := []shownFinding{{Rule: core.SuppressionReasonRule, File: "main.go", Line: 3, Severity: "medium"}}
	assert.Equal(t, want, checkShownIn(t, root, cacheDir, "medium", core.SuppressionReasonRule), "the run that stores")
	assert.Equal(t, want, checkShownIn(t, root, cacheDir, "medium", core.SuppressionReasonRule), "the run that reuses")
	assert.Equal(t, want, checkShownIn(t, root, cacheDir, "low", core.SuppressionReasonRule), "a run at low")
}

// An exception of stale-suppression that silences its finding — medium — is
// reported medium by broad-exclusion, whether it keeps the rule off the
// files or matches the finding by a pattern.
func TestStaleExceptionTakesTheSeverityOfWhatItSilences(t *testing.T) {
	for name, exception := range map[string]string{
		"files":   "          - files: \"*.go\"\n            reason: generated markers\n",
		"pattern": "          - files: \"*.go\"\n            pattern: silences nothing\n            reason: generated markers\n",
	} {
		t.Run(name, func(t *testing.T) {
			files := map[string]string{
				"go.mod":      oversightModule,
				".glint.yaml": "version: 1\ncategories:\n  deadcode:\n    rules:\n      stale-suppression:\n        exceptions:\n" + exception,
				"main.go":     "package main\n\n//nolint:interface-any the decoder fills it\nvar holder = 1\n\nfunc main() { println(holder) }\n",
			}
			assert.Equal(t, []shownFinding{{Rule: broadExclusionRule, File: ".glint.yaml", Line: 7, Severity: "medium"}},
				checkShown(t, files, "medium", broadExclusionRule, "stale-suppression"))
		})
	}
}

// An exception is found by the line of its entry, which need not be the line
// of its files, and in the base file outside the project that sets it.
func TestBroadExceptionFoundByItsEntry(t *testing.T) {
	secret := "package main\n\nvar Password = \"hunter2hunter2\"\n\nfunc main() { println(Password) }\n"
	exception := "categories:\n  security:\n    rules:\n      hardcoded-secret:\n        exceptions:\n          - reason: fixtures of the vendored client\n            files: \"**/*.go\"\n"
	files := map[string]string{"go.mod": oversightModule, ".glint.yaml": "version: 1\n" + exception, "main.go": secret}
	assert.Equal(t, []shownFinding{{Rule: broadExclusionRule, File: ".glint.yaml", Line: 8, Severity: "critical"}},
		checkShown(t, files, "high", broadExclusionRule), "files below the first line of the entry")

	base := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(base, "base.yaml"), []byte(exception), 0o644))
	root := oversightProject(t, map[string]string{"go.mod": oversightModule, ".glint.yaml": "version: 1\nextends: " + filepath.Join(base, "base.yaml") + "\n", "main.go": secret})
	assert.Equal(t, []shownFinding{{Rule: broadExclusionRule, File: ".glint.yaml", Line: 2, Severity: "critical"}},
		checkShownIn(t, root, "", "high", broadExclusionRule), "set in a base file through extends")
}
