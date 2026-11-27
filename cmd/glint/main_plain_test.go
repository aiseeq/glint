//go:build !race

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/fix"
	"github.com/aiseeq/glint/pkg/rules"
)

// These path, flag, configuration, threshold and finding-set tests operate
// on values and fixtures; their processes do not start glint analysis workers.

func dedupeViolations(root string, violations core.ViolationList) core.ViolationList {
	findings := newFindingSet()
	findings.add(root, violations)
	return findings.list
}

func TestGetProjectRootsExpandsRecursiveCurrentDirectory(t *testing.T) {
	want, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}

	got, err := getProjectRoots([]string{"./..."})
	if err != nil {
		t.Fatalf("get project roots: %v", err)
	}
	if len(got) != 1 || got[0] != want {
		t.Fatalf("got project roots %v, want [%s]", got, want)
	}
}

func TestGetProjectRootsRejectsMissingPath(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")

	_, err := getProjectRoots([]string{missing})
	if err == nil {
		t.Fatal("expected missing project root to return an error")
	}
}

func TestGetProjectRootsReturnsAbsoluteCleanPath(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "project")
	if err := os.Mkdir(root, 0755); err != nil {
		t.Fatalf("create project root: %v", err)
	}
	t.Chdir(parent)

	got, err := getProjectRoots([]string{"project/./"})
	if err != nil {
		t.Fatalf("get project roots: %v", err)
	}
	if len(got) != 1 || got[0] != root {
		t.Fatalf("got project roots %v, want [%s]", got, root)
	}
}

func TestGetProjectRootsKeepsEveryPath(t *testing.T) {
	parent := t.TempDir()
	first := filepath.Join(parent, "backend")
	second := filepath.Join(parent, "tools")
	for _, dir := range []string{first, second} {
		if err := os.Mkdir(dir, 0755); err != nil {
			t.Fatalf("create %s: %v", dir, err)
		}
	}

	got, err := getProjectRoots([]string{first, second})
	if err != nil {
		t.Fatalf("get project roots: %v", err)
	}
	if len(got) != 2 || got[0] != first || got[1] != second {
		t.Fatalf("got project roots %v, want [%s %s]", got, first, second)
	}
}

func TestGetProjectRootsDeduplicatesRepeatedPath(t *testing.T) {
	root := t.TempDir()

	got, err := getProjectRoots([]string{root, root + "/."})
	if err != nil {
		t.Fatalf("get project roots: %v", err)
	}
	if len(got) != 1 || got[0] != root {
		t.Fatalf("got project roots %v, want [%s]", got, root)
	}
}

func TestShouldFailAnalysisAtThreshold(t *testing.T) {
	low := core.ViolationList{core.NewViolation("low", "test", "test.go", 1, core.SeverityLow, "low")}
	medium := core.ViolationList{core.NewViolation("medium", "test", "test.go", 1, core.SeverityMedium, "medium")}
	high := core.ViolationList{core.NewViolation("high", "test", "test.go", 1, core.SeverityHigh, "high")}
	critical := core.ViolationList{core.NewViolation("critical", "test", "test.go", 1, core.SeverityCritical, "critical")}

	if medium.AnyAtLeast(core.SeverityHigh) {
		t.Fatal("medium findings must not fail analysis at the default high threshold")
	}
	if !high.AnyAtLeast(core.SeverityHigh) {
		t.Fatal("high findings must fail analysis at the high threshold")
	}
	if !critical.AnyAtLeast(core.SeverityHigh) {
		t.Fatal("critical findings must fail analysis at the high threshold")
	}
	if !medium.AnyAtLeast(core.SeverityMedium) {
		t.Fatal("medium findings must fail analysis at the medium threshold")
	}
	if low.AnyAtLeast(core.SeverityMedium) {
		t.Fatal("low findings must not fail analysis at the medium threshold")
	}
	if high.AnyAtLeast(core.SeverityCritical) {
		t.Fatal("high findings must not fail analysis at the critical threshold")
	}
}

func TestFindingSetDropsRepeatedFinding(t *testing.T) {
	violations := core.ViolationList{
		{Rule: "error-wrap", File: "a.go", Line: 10, Message: "wrap it"},
		{Rule: "error-wrap", File: "a.go", Line: 10, Message: "wrap it"},
		{Rule: "error-wrap", File: "a.go", Line: 20, Message: "wrap it"},
		{Rule: "magic-number", File: "a.go", Line: 10, Message: "42"},
	}

	got := dedupeViolations("/project", violations)
	if len(got) != 3 {
		t.Fatalf("got %d violations, want 3", len(got))
	}
}

// One rule can report several distinct problems on the same line — for
// example two magic numbers in one expression. Those are not duplicates.
func TestFindingSetKeepsDistinctFindingsOnOneLine(t *testing.T) {
	violations := core.ViolationList{
		{Rule: "magic-number", File: "a.go", Line: 10, Column: 12, Message: "Magic number 86400"},
		{Rule: "magic-number", File: "a.go", Line: 10, Column: 30, Message: "Magic number 3600"},
	}

	if got := dedupeViolations("/project", violations); len(got) != 2 {
		t.Fatalf("got %d violations, want both distinct findings kept", len(got))
	}
}

// Overlapping roots name the same file differently: "sub/a.go" from the
// parent, "a.go" from sub itself. It is still one finding.
func TestFindingSetDropsFindingOfOverlappingRoot(t *testing.T) {
	findings := newFindingSet()
	findings.add("/project", core.ViolationList{{Rule: "magic-number", File: "sub/a.go", Line: 5, Message: "777"}})
	findings.add("/project/sub", core.ViolationList{{Rule: "magic-number", File: "a.go", Line: 5, Message: "777"}})

	if len(findings.list) != 1 || findings.list[0].File != "sub/a.go" {
		t.Fatalf("got %v, want the single finding of the first root", findings.list)
	}
}

// An unknown --rule used to leave the full rule set in place, so glint reported
// everything instead of the one rule the caller asked about.
func TestGetEnabledRulesRejectsUnknownRule(t *testing.T) {
	withFlags(t, "", "no-such-rule")

	_, err := getEnabledRules(core.DefaultConfig())
	if err == nil {
		t.Fatal("unknown rule must be an error, not a silent fallback to all rules")
	}
	if !strings.Contains(err.Error(), "no-such-rule") {
		t.Fatalf("error must name the unknown rule, got: %v", err)
	}
}

func TestRootDirectoryFlagAcceptsRepeatedValues(t *testing.T) {
	flags := rootCmd.PersistentFlags()
	prev := flagChdir
	t.Cleanup(func() {
		flagChdir = prev
		if err := flags.Lookup("directory").Value.(interface{ Replace([]string) error }).Replace(prev); err != nil {
			t.Error(err)
		}
	})
	flagChdir = nil
	if err := flags.Lookup("directory").Value.(interface{ Replace([]string) error }).Replace(nil); err != nil {
		t.Fatal(err)
	}
	if err := flags.Parse([]string{"-C", "first", "-C", "second"}); err != nil {
		t.Fatal(err)
	}
	if strings.Join(flagChdir, ",") != "first,second" {
		t.Fatalf("got -C values %q, want [first second]", flagChdir)
	}
}

func TestGetEnabledRulesRejectsUnknownCategory(t *testing.T) {
	withFlags(t, "no-such-category")

	_, err := getEnabledRules(core.DefaultConfig())
	if err == nil {
		t.Fatal("unknown category must be an error")
	}
	if !strings.Contains(err.Error(), "no-such-category") {
		t.Fatalf("error must name the unknown category, got: %v", err)
	}
}

// settings.output from the YAML config must win unless -o is passed explicitly;
// a non-empty flag default used to override the config on every run.
func TestLoadConfigHonorsOutputFromYAML(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".glint.yaml"), []byte("settings:\n  output: json\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// The -o default must stay empty: a non-empty default is indistinguishable
	// from an explicit -o and silently overrides the config on every run.
	if def := checkCmd.Flags().Lookup("output").DefValue; def != "" {
		t.Fatalf("-o default must be empty so the config can win, got %q", def)
	}

	prev := flagOutput
	t.Cleanup(func() { flagOutput = prev })

	flagOutput = "" // -o not passed
	cfg, _, err := loadConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Settings.Output != "json" {
		t.Fatalf("config output must survive when -o is not passed, got %q", cfg.Settings.Output)
	}

	flagOutput = "summary" // -o passed explicitly
	cfg, _, err = loadConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Settings.Output != "summary" {
		t.Fatalf("explicit -o must override config, got %q", cfg.Settings.Output)
	}
}

func TestGetEnabledRulesAcceptsKnownRule(t *testing.T) {
	withFlags(t, "", "interface-any")

	enabled, err := getEnabledRules(core.DefaultConfig())
	if err != nil {
		t.Fatalf("known rule must resolve: %v", err)
	}
	if len(enabled) != 1 || enabled[0].Name() != "interface-any" {
		t.Fatalf("got %d rules, want only interface-any", len(enabled))
	}
}

// An unknown name among several --rule values is an error too.
func TestGetEnabledRulesRejectsUnknownRuleAmongSeveral(t *testing.T) {
	withFlags(t, "", "interface-any", "no-such-rule")

	if _, err := getEnabledRules(core.DefaultConfig()); err == nil || !strings.Contains(err.Error(), "no-such-rule") {
		t.Fatalf("unknown rule among several must be an error naming it, got: %v", err)
	}
}

// Every registered fixer must belong to a registered rule, otherwise the
// "(auto-fix)" label in `glint rules` and `glint fix` itself point nowhere.
func TestFixersCoverRegisteredRules(t *testing.T) {
	for name := range fix.DefaultRegistry.All() {
		if _, ok := rules.Get(name); !ok {
			t.Errorf("fixer %q has no registered rule", name)
		}
	}
	if len(fix.DefaultRegistry.All()) == 0 {
		t.Fatal("no fixers registered")
	}
}

func TestBuildSeverityOverridesReportsInvalidSeverity(t *testing.T) {
	cfg := core.DefaultConfig()
	cat := cfg.Categories["patterns"]
	cat.SeverityOverride = "catastrophic"
	cfg.Categories["patterns"] = cat

	if _, err := buildSeverityOverrides(cfg, []rules.Rule{newExemptStubRule()}); err == nil {
		t.Fatal("an unparseable severity must be reported, not ignored")
	}
}

// Several --rule values used to keep only the last one: a pflag string flag
// silently overwrites on repeat. Every rule asked for must run.
func TestGetEnabledRulesRunsEveryRequestedRule(t *testing.T) {
	flags := checkCmd.Flags()
	prev := flagRules
	t.Cleanup(func() { flagRules = prev })
	for _, args := range [][]string{
		{"--rule=interface-any", "--rule=magic-number"},
		{"--rule=interface-any,magic-number"},
	} {
		flagRules = nil
		if err := flags.Lookup("rule").Value.(interface{ Replace([]string) error }).Replace(nil); err != nil {
			t.Fatal(err)
		}
		if err := flags.Parse(args); err != nil {
			t.Fatal(err)
		}
		enabled, err := getEnabledRules(core.DefaultConfig())
		if err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		var names []string
		for _, rule := range enabled {
			names = append(names, rule.Name())
		}
		if strings.Join(names, ",") != "interface-any,magic-number" {
			t.Fatalf("%v: got %v, want both rules", args, names)
		}
	}
}

// A rule the configuration disabled by name stays off under --category; the
// category switch itself is what the flag overrides.
func TestGetEnabledRulesCategoryKeepsRuleDisabledByName(t *testing.T) {
	withFlags(t, "architecture")
	cfg := core.DefaultConfig()
	cfg.Categories["architecture"] = core.CategoryConfig{
		Enabled: false,
		Rules:   map[string]core.RuleConfig{"solid-srp": {Enabled: false}},
	}

	got, err := getEnabledRules(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 {
		t.Fatal("an explicitly requested category must run although the config switched it off")
	}
	for _, rule := range got {
		if rule.Name() == "solid-srp" {
			t.Fatal("solid-srp is disabled by name and must stay off")
		}
		if rule.Category() != "architecture" {
			t.Fatalf("rule %s of category %s leaked into --category architecture", rule.Name(), rule.Category())
		}
	}
}

func TestResolveProjectRootAcceptsPackagePattern(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "internal"), 0o755); err != nil {
		t.Fatal(err)
	}

	got, err := resolvePath(filepath.Join(dir, "internal")+"/...", false)
	if err != nil {
		t.Fatal(err)
	}
	if got != filepath.Join(dir, "internal") {
		t.Fatalf("got %s, want the directory the pattern starts from", got)
	}
}

// An unknown -o used to fall through to the console report.
func TestLoadConfigRejectsUnknownOutputFormat(t *testing.T) {
	prev := flagOutput
	flagOutput = "jsn"
	t.Cleanup(func() { flagOutput = prev })

	_, _, err := loadConfig(t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "jsn") {
		t.Fatalf("got %v, want an error naming the unknown format", err)
	}
}

// A misspelled key, an unknown rule and a rule filed under the wrong category
// used to be ignored: the exception or setting silently never applied.
func TestLoadConfigRejectsUnknownNames(t *testing.T) {
	tests := map[string]string{
		"misspelled key":  "categories:\n  patterns:\n    rules:\n      error-wrap:\n        exeptions:\n          - file: a.go\n",
		"unknown rule":    "categories:\n  patterns:\n    rules:\n      error-wrapp:\n        enabled: false\n",
		"wrong category":  "categories:\n  architecture:\n    rules:\n      error-wrap:\n        enabled: false\n",
		"unknown section": "settings:\n  min_severty: high\n",
		"empty exception": "categories:\n  patterns:\n    rules:\n      error-wrap:\n        exceptions:\n          - reason: forgot the file\n",
	}
	for name, config := range tests {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, ".glint.yaml"), []byte(config), 0o644); err != nil {
				t.Fatal(err)
			}
			if _, _, err := loadConfig(dir); err == nil {
				t.Fatal("the configuration must be rejected")
			}
		})
	}
}
