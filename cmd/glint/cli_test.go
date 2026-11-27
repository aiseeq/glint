package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func withFlags(t *testing.T, category string, ruleNames ...string) {
	t.Helper()
	prevCategory, prevRules := flagCategory, flagRules
	flagCategory, flagRules = category, ruleNames
	t.Cleanup(func() { flagCategory, flagRules = prevCategory, prevRules })
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
