package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aiseeq/glint/pkg/core"
)

func captureRuleOutput(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	file, err := os.CreateTemp(os.TempDir(), "glint-rule-output-*")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(file.Name()) }()
	old := os.Stdout
	os.Stdout = file
	callErr := fn()
	os.Stdout = old
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	_, copyErr := io.Copy(&output, file)
	_ = file.Close()
	if copyErr != nil {
		t.Fatal(copyErr)
	}
	return output.String(), callErr
}

func TestRulesCommandShowsSettings(t *testing.T) {
	list, err := captureRuleOutput(t, func() error { return runRules(nil, nil) })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(list, "settings:") || !strings.Contains(list, "period_modules (string list)") {
		t.Fatalf("settings absent from list:\n%s", list)
	}
	for _, name := range []string{"ts-period-boundary-by-hand", "sql-concept-table-outside-owner"} {
		card, err := captureRuleOutput(t, func() error { return showRule(name) })
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(card, "YAML (.glint.yaml):") || !strings.Contains(card, "settings:") {
			t.Errorf("%s card lacks settings YAML:\n%s", name, card)
		}
		if name == "ts-period-boundary-by-hand" {
			block := card[strings.Index(card, "categories:"):]
			path := filepath.Join(t.TempDir(), ".glint.yaml")
			if err := os.WriteFile(path, []byte(block), 0600); err != nil {
				t.Fatal(err)
			}
			cfg, err := core.LoadConfig(path)
			if err != nil {
				t.Fatalf("card YAML does not load: %v\n%s", err, block)
			}
			if _, ok := cfg.Categories["patterns"].Rules[name].Settings["period_modules"]; !ok {
				t.Fatalf("card YAML lost period_modules: %+v", cfg.Categories["patterns"].Rules[name])
			}
		}
	}
}

func TestRulesCommandUnknownRule(t *testing.T) {
	err := showRule("clock-bypas")
	if err == nil || !strings.Contains(err.Error(), "clock-bypass") {
		t.Fatalf("expected unknown rule suggestion, got %v", err)
	}
}
