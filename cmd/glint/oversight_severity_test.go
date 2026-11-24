package main

import (
	"os"
	"path/filepath"
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

const oversightModule = "module projectA\n\ngo 1.22\n"

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
