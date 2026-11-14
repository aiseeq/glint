package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

// shownFinding is a finding of `glint check -o json` as the oversight tests
// compare it.
type shownFinding struct {
	Rule     string `json:"rule"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	Severity string `json:"severity"`
}

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

const oversightModule = "module projectA\n\ngo 1.22\n"

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

// hotMarkerSource silences a finding of format-before-branch, medium in a
// function marked hot (line 10) and low in an ordinary one (line 19).
const hotMarkerSource = "package main\n\nimport (\n\t\"errors\"\n\t\"fmt\"\n)\n\n" +
	"//glint:hot\nfunc Charge(a, t int, dmg int) error {\n\t// nolint:format-before-branch\n\tmsg := fmt.Sprintf(\"charge %d on %d\", a, t)\n\tif dmg < 0 {\n\t\treturn errors.New(msg)\n\t}\n\treturn nil\n}\n\n" +
	"func Refund(a, t int, dmg int) error {\n\t// nolint:format-before-branch\n\tmsg := fmt.Sprintf(\"refund %d on %d\", a, t)\n\tif dmg < 0 {\n\t\treturn errors.New(msg)\n\t}\n\treturn nil\n}\n\n" +
	"func main() { println(Charge(1, 2, 3), Refund(1, 2, 3)) }\n"

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

// A marker over a finding of a Go project rule is rated by the finding's
// severity, not by the rule's default.
func TestProjectRuleMarkerIsRatedByTheFinding(t *testing.T) {
	root := writeAnalysisModule(t, "package check\n\n//nolint:project-stub\nfunc Value() int { return 1 }\n")
	rule := newProjectStubRule()
	finding := rule.CreateViolation("check.go", 4, "finding")
	finding.Severity = core.SeverityCritical
	rule.findings = []*core.Violation{finding}
	cfg := core.DefaultConfig()
	prepared, err := prepareAnalysis(core.NewGoProjectLoader(), root, cfg, []rules.Rule{rule}, false)
	require.NoError(t, err)

	violations, err := analyzeProject(prepared.contexts, []rules.Rule{rule}, cfg, prepared.project, nil)
	require.NoError(t, err)
	findings, suppressions := core.SplitSuppressions(violations)
	assert.Empty(t, findings)
	require.Len(t, suppressions, 1)
	assert.Equal(t, [2]any{3, core.SeverityCritical}, [2]any{suppressions[0].Line, suppressions[0].Severity})
}

// The severity an exception silenced is found by the line that declares it;
// an exception of suppression-without-reason takes the severity of the
// marker its finding is about, any other only its own findings', and the
// highest of several findings counts.
func TestSilencedExceptionSeverities(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, ".glint.yaml")
	require.NoError(t, os.WriteFile(path, []byte("version: 1\ncategories:\n  patterns:\n    rules:\n      magic-number:\n        exceptions:\n          - files: \"*.go\"\n            reason: tables\n  deadcode:\n    rules:\n      suppression-without-reason:\n        exceptions:\n          - files: \"*.go\"\n            reason: generated markers\n"), 0o644))
	cfg, err := core.LoadConfig(path)
	require.NoError(t, err)
	keys := map[string]string{}
	for _, ruleException := range cfg.Exceptions() {
		keys[ruleException.Rule] = core.SuppressionExceptionPrefix + cfg.ExceptionKey(ruleException.Exception)
	}
	entry := func(rule, suppression string, line int, severity core.Severity, markerRules ...string) *core.Violation {
		entry := core.NewSuppressionEntry(rule, "", "a.go", line, severity, suppression)
		entry.MarkerRules = markerRules
		return entry
	}

	silenced := newSilencedSeverities(cfg, core.ViolationList{
		entry("hardcoded-secret", core.SuppressionInline, 3, core.SeverityCritical),
		entry("interface-any", core.SuppressionInline, 9, core.SeverityLow),
		entry("magic-number", keys["magic-number"], 3, core.SeverityMedium),
		entry("magic-number", keys["magic-number"], 5, core.SeverityLow),
		entry(core.SuppressionReasonRule, keys[core.SuppressionReasonRule], 9, core.SeverityHigh, "interface-any"),
		entry(core.SuppressionReasonRule, keys[core.SuppressionReasonRule], 3, core.SeverityLow, "hardcoded-secret"),
		entry(core.SuppressionReasonRule, keys[core.SuppressionReasonRule], 9, core.SeverityLow, "interface-any"),
	})

	assert.Equal(t, core.SeverityMedium, silenced.exception(path, 7), "magic-number: its findings, not the marker at line 3")
	assert.Equal(t, core.SeverityCritical, silenced.exception(path, 13), "suppression-without-reason: the marker at line 3")
	assert.Equal(t, core.SeverityLow, silenced.exception(path, 8), "no exception is declared at line 8")

	silenced = newSilencedSeverities(cfg, core.ViolationList{
		entry(core.SuppressionReasonRule, keys[core.SuppressionReasonRule], 9, core.SeverityHigh, "interface-any"),
		entry("interface-any", core.SuppressionInline, 9, core.SeverityLow),
	})
	assert.Equal(t, core.SeverityHigh, silenced.exception(path, 13), "a finding of a configured severity above its marker's")

	silenced = newSilencedSeverities(cfg, core.ViolationList{
		entry("hardcoded-secret", core.SuppressionInline, 3, core.SeverityCritical),
		entry(core.SuppressionReasonRule, keys[core.SuppressionReasonRule], 3, core.SeverityLow, "empty-decl-group"),
	})
	assert.Equal(t, core.SeverityLow, silenced.exception(path, 13), "the marker of another rule on the line silenced the secret")
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

// The highest severity a marker or an exception silenced is kept whatever
// order the entries come in; only findings of suppression-without-reason at
// a marker take it, of the rules they name, on copies, and nothing moves.
func TestSilencedSeveritiesKeepTheHighest(t *testing.T) {
	inline := func(rule string, line int, severity core.Severity) *core.Violation {
		return core.NewSuppressionEntry(rule, "", "a.go", line, severity, core.SuppressionInline)
	}
	for name, entries := range map[string]core.ViolationList{
		"higher first": {inline("hardcoded-secret", 3, core.SeverityCritical), inline("interface-any", 3, core.SeverityMedium), inline("magic-number", 3, core.SeverityLow)},
		"higher last":  {inline("magic-number", 3, core.SeverityLow), inline("interface-any", 3, core.SeverityMedium), inline("hardcoded-secret", 3, core.SeverityCritical)},
		"higher mid":   {inline("interface-any", 3, core.SeverityMedium), inline("hardcoded-secret", 3, core.SeverityCritical), inline("magic-number", 3, core.SeverityLow)},
	} {
		t.Run(name, func(t *testing.T) {
			silenced := newSilencedSeverities(core.DefaultConfig(), append(entries, inline("interface-any", 9, core.SeverityMedium)))
			marker := func(file string, line int, severity core.Severity, names ...string) *core.Violation {
				v := core.NewViolation(core.SuppressionReasonRule, "deadcode", file, line, severity, "bare")
				v.MarkerRules = names
				return v
			}
			atMarker := marker("a.go", 3, core.SeverityLow, "magic-number", "hardcoded-secret", "interface-any")
			otherRule := core.NewViolation("magic-number", "style", "a.go", 3, core.SeverityLow, "number")
			elsewhere := marker("a.go", 5, core.SeverityLow, "hardcoded-secret")
			otherFile := marker("b.go", 3, core.SeverityLow, "hardcoded-secret")
			overridden := marker("a.go", 9, core.SeverityHigh, "interface-any")
			otherMarker := marker("a.go", 3, core.SeverityLow, "interface-any")
			lowMarker := marker("a.go", 3, core.SeverityLow, "magic-number")
			unsilenced := marker("a.go", 3, core.SeverityLow, "empty-decl-group")
			list := core.ViolationList{atMarker, otherRule, elsewhere, otherFile, overridden, otherMarker, lowMarker, unsilenced}

			raised := silenced.raiseMarkerFindings(list)

			var severities []core.Severity
			for i, v := range raised {
				assert.Equal(t, [3]any{list[i].Rule, list[i].File, list[i].Line}, [3]any{v.Rule, v.File, v.Line}, "finding %d keeps its place", i)
				severities = append(severities, v.Severity)
			}
			assert.Equal(t, []core.Severity{core.SeverityCritical, core.SeverityLow, core.SeverityLow, core.SeverityLow, core.SeverityHigh, core.SeverityMedium, core.SeverityLow, core.SeverityLow}, severities)
			assert.Equal(t, core.SeverityLow, atMarker.Severity, "the finding of the rule, cached too, keeps its own severity")
		})
	}
}

// A marker a rule consulted unrated silenced a finding of the rule's
// severity, a rated one the finding's; either as the configuration reports
// it.
func TestInlineSuppressionsRateAnUnratedMarkerByTheRule(t *testing.T) {
	rule, ok := rules.Get("hardcoded-secret")
	require.True(t, ok)
	ctx := &core.FileContext{Path: "a.go", RelPath: "a.go", Lines: []string{"//nolint:hardcoded-secret", "x"}}

	require.True(t, ctx.IsSuppressed(2, rule.Name()))
	entries := inlineSuppressions(ctx, rule, nil)
	require.Len(t, entries, 1)
	assert.Equal(t, rule.DefaultSeverity(), entries[0].Severity)

	require.True(t, ctx.IsSuppressed(2, rule.Name()))
	entries = inlineSuppressions(ctx, rule, severityOverrides{rule.Name(): core.SeverityLow})
	require.Len(t, entries, 1)
	assert.Equal(t, core.SeverityLow, entries[0].Severity)

	require.True(t, ctx.SuppressesFinding(2, rule.Name(), core.SeverityMedium))
	entries = inlineSuppressions(ctx, rule, nil)
	require.Len(t, entries, 1)
	assert.Equal(t, core.SeverityMedium, entries[0].Severity, "a rated marker keeps the severity of the finding")

	require.True(t, ctx.SuppressesFinding(2, rule.Name(), core.SeverityMedium))
	entries = inlineSuppressions(ctx, rule, severityOverrides{rule.Name(): core.SeverityLow})
	require.Len(t, entries, 1)
	assert.Equal(t, core.SeverityLow, entries[0].Severity, "a severity configured for the rule replaces the one it rated")
}

// A file-only exception has an entry per line with a finding, each with the
// highest severity on it as the configuration reports it.
func TestFileExceptionSuppressionRatesEachLine(t *testing.T) {
	rule, ok := rules.Get("hardcoded-secret")
	require.True(t, ok)
	finding := func(line int, severity core.Severity) *core.Violation {
		return core.NewViolation(rule.Name(), rule.Category(), "a.go", line, severity, "secret")
	}
	found := []*core.Violation{finding(4, core.SeverityLow), finding(2, core.SeverityMedium), finding(4, core.SeverityHigh), finding(4, core.SeverityMedium)}
	rated := func(entries core.ViolationList) [][2]any {
		var got [][2]any
		for _, entry := range entries {
			got = append(got, [2]any{entry.Line, entry.Severity})
		}
		return got
	}
	cfg := core.DefaultConfig()
	assert.Equal(t, [][2]any{{4, core.SeverityHigh}, {2, core.SeverityMedium}}, rated(fileExceptionSuppression(cfg, "a.go", rule, core.Exception{}, found, nil)))
	assert.Equal(t, [][2]any{{4, core.SeverityCritical}, {2, core.SeverityCritical}},
		rated(fileExceptionSuppression(cfg, "a.go", rule, core.Exception{}, found, severityOverrides{rule.Name(): core.SeverityCritical})))
	assert.Empty(t, fileExceptionSuppression(cfg, "a.go", rule, core.Exception{}, nil, nil))

	marker := func(markerRules ...string) *core.Violation {
		v := core.NewViolation(core.SuppressionReasonRule, "deadcode", "a.go", 3, core.SeverityLow, "bare")
		v.MarkerRules = markerRules
		return v
	}
	entries := fileExceptionSuppression(cfg, "a.go", rule, core.Exception{}, []*core.Violation{marker("empty-decl-group"), marker("hardcoded-secret")}, nil)
	require.Len(t, entries, 1)
	assert.Equal(t, []string{"empty-decl-group", "hardcoded-secret"}, entries[0].MarkerRules, "the rules of every marker finding of the line")
}

// ratedFindingRule reports one finding on line 2 of a severity other than
// its default, under the name of a real rule so that the configuration
// takes its exceptions.
type ratedFindingRule struct{ *rules.BaseRule }

func newRatedFindingRule() *ratedFindingRule {
	return &ratedFindingRule{rules.NewBaseRule("magic-number", "patterns", "reports a high finding", core.SeverityLow)}
}

func (r *ratedFindingRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	v := r.CreateViolation(ctx.RelPath, 2, "rated")
	v.Severity = core.SeverityHigh
	return []*core.Violation{v}
}

// A marker and an exception are rated by the severity of the finding they
// silenced, not by the rule's default.
func TestSilencedFindingIsRatedByItsOwnSeverity(t *testing.T) {
	root := t.TempDir()
	rule := newRatedFindingRule()
	source := []byte("package p\n//nolint:magic-number\nvar x = 1\n")

	ctx := core.NewFileContext(filepath.Join(root, "a.go"), root, source, core.DefaultConfig())
	kept, err := runRule(ctx, rule, core.DefaultConfig(), nil)
	require.NoError(t, err)
	require.Len(t, kept, 1)
	assert.Equal(t, [3]any{core.SuppressionInline, 2, core.SeverityHigh}, [3]any{kept[0].Suppression, kept[0].Line, kept[0].Severity}, "marker")

	ctx = core.NewFileContext(filepath.Join(root, "a.go"), root, source, core.DefaultConfig())
	kept, err = runRule(ctx, rule, core.DefaultConfig(), severityOverrides{rule.Name(): core.SeverityCritical})
	require.NoError(t, err)
	require.Len(t, kept, 1)
	assert.Equal(t, core.SeverityCritical, kept[0].Severity, "marker over a finding of a configured severity")

	path := filepath.Join(root, ".glint.yaml")
	require.NoError(t, os.WriteFile(path, []byte("version: 1\ncategories:\n  patterns:\n    rules:\n      magic-number:\n        exceptions:\n          - file: a.go\n            line: 2\n            reason: the table of the protocol\n"), 0o644))
	cfg, err := core.LoadConfig(path)
	require.NoError(t, err)
	ctx = core.NewFileContext(filepath.Join(root, "a.go"), root, source, cfg)
	kept, err = runRule(ctx, rule, cfg, nil)
	require.NoError(t, err)
	require.Len(t, kept, 1)
	assert.True(t, strings.HasPrefix(kept[0].Suppression, core.SuppressionExceptionPrefix), "exception entry: %q", kept[0].Suppression)
	assert.Equal(t, core.SeverityHigh, kept[0].Severity, "exception")
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
