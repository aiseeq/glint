package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/fix"
	"github.com/aiseeq/glint/pkg/rules"
)

func withFlags(t *testing.T, category string, ruleNames ...string) {
	t.Helper()
	prevCategory, prevRules := flagCategory, flagRules
	flagCategory, flagRules = category, ruleNames
	t.Cleanup(func() { flagCategory, flagRules = prevCategory, prevRules })
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

// severity / severity_override configured for a rule must reach the finding.
func TestAnalyzeFilesAppliesSeverityOverride(t *testing.T) {
	cfg := core.DefaultConfig()
	cat := cfg.Categories["patterns"]
	cat.Rules = map[string]core.RuleConfig{
		"exempt-stub": {Enabled: true, Severity: "low"},
	}
	cfg.Categories["patterns"] = cat

	rule := newExemptStubRule()
	overrides, err := buildSeverityOverrides(cfg, []rules.Rule{rule})
	if err != nil {
		t.Fatalf("build severity overrides: %v", err)
	}

	ctx := core.NewFileContext("service.go", ".", []byte("package svc\n"), nil)
	violations := mustAnalyzeFiles(t, []*core.FileContext{ctx}, []rules.Rule{rule}, cfg, overrides)

	if len(violations) != 1 {
		t.Fatalf("got %d violations, want 1", len(violations))
	}
	if violations[0].Severity != core.SeverityLow {
		t.Fatalf("got severity %s, want low — configured severity was ignored", violations[0].Severity)
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

// A dangling symlink in the tree (common in historical checkouts) used to abort
// the whole run; under --tolerate-broken-packages it must only be skipped.
func TestWalkWithWalkerSkipsUnreadableFilesWhenTolerant(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "value.go"), []byte("package project\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "gone.md"), filepath.Join(root, "AGENTS.md")); err != nil {
		t.Fatal(err)
	}

	prev := flagTolerant
	t.Cleanup(func() { flagTolerant = prev })

	flagTolerant = false
	if _, _, err := walkWithWalker(core.NewWalker(root, core.DefaultConfig())); err == nil {
		t.Fatal("strict mode must report an unreadable file")
	}

	flagTolerant = true
	contexts, _, err := walkWithWalker(core.NewWalker(root, core.DefaultConfig()))
	if err != nil {
		t.Fatalf("tolerant mode must skip the unreadable file, got: %v", err)
	}
	if len(contexts) == 0 {
		t.Fatal("readable files must still be analyzed")
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

	got, err := resolveProjectRoot(filepath.Join(dir, "internal") + "/...")
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

// A run takes four threads unless told otherwise: the machine is shared with
// other jobs, and every CPU at once slows them down for little gain.
func TestJobsDefaultsToFourAndRejectsZero(t *testing.T) {
	for _, cmd := range []*cobra.Command{checkCmd, fixCmd} {
		if def := cmd.Flags().Lookup("jobs").DefValue; def != "4" {
			t.Fatalf("%s --jobs default = %s, want 4", cmd.Name(), def)
		}
	}
	prev := flagJobs
	t.Cleanup(func() { flagJobs = prev; runtime.GOMAXPROCS(runtime.NumCPU()) })
	flagJobs = 0
	if err := applyJobs(); err == nil {
		t.Fatal("--jobs 0 must be an error")
	}
	flagJobs = 3
	if err := applyJobs(); err != nil || runtime.GOMAXPROCS(0) != 3 {
		t.Fatalf("--jobs 3 must set GOMAXPROCS to 3, got %d, %v", runtime.GOMAXPROCS(0), err)
	}
}
