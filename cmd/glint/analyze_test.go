package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

// sampleContexts builds a handful of parsed Go files that trip a broad set of
// rules, so that the whole registry actually runs over them.
func sampleContexts(t *testing.T, count int) []*core.FileContext {
	t.Helper()
	contexts := make([]*core.FileContext, 0, count)
	for i := 0; i < count; i++ {
		code := fmt.Sprintf(`package svc

import "fmt"

type Config%d struct {
	Name    string
	Timeout int
	Retries int
}

// Handler%d does work.
type Handler%d struct{ cfg Config%d }

func Build%d(name string) (interface{}, error) {
	cfg := Config%d{Name: name, Timeout: 30, Retries: 3}
	if cfg.Name == "" {
		return nil, nil
	}
	other := Config%d{Name: "other", Timeout: 60, Retries: 5}
	fmt.Println(other)
	// TODO: revisit this fallback
	value, err := lookup(name)
	if err != nil {
		return "", nil
	}
	return value, nil
}

func lookup(name string) (string, error) {
	if len(name) > 42 {
		return "", fmt.Errorf("too long")
	}
	return name, nil
}
`, i, i, i, i, i, i, i)
		contexts = append(contexts, goContext(t, fmt.Sprintf("pkg/svc/file%d.go", i), code))
	}
	return contexts
}

func fingerprint(violations core.ViolationList) string {
	var b strings.Builder
	for _, v := range violations {
		fmt.Fprintf(&b, "%s|%s|%d|%s\n", v.Rule, v.File, v.Line, v.Message)
	}
	return b.String()
}

// Analysis runs rules concurrently; the reported findings and their order must
// not depend on scheduling. Run with -race to also catch shared rule state.
func TestAnalyzeFilesIsDeterministicAndRaceFree(t *testing.T) {
	cfg := core.DefaultConfig()
	allRules := rules.All()
	contexts := sampleContexts(t, 12)

	rules.ResetState(allRules)
	want := fingerprint(analyzeFiles(contexts, allRules, cfg, nil))
	if want == "" {
		t.Fatal("sample files produced no findings — the test would not prove anything")
	}

	for run := 0; run < 8; run++ {
		rules.ResetState(allRules)
		got := fingerprint(analyzeFiles(contexts, allRules, cfg, nil))
		if got != want {
			t.Fatalf("run %d produced different findings:\nwant:\n%s\ngot:\n%s", run, want, got)
		}
	}
}

// Stateful rules see files in a fixed order, so their cross-file findings stay
// reproducible even though the rest of the analysis is parallel.
func TestStatefulRulesSeeFilesInOrder(t *testing.T) {
	cfg := core.DefaultConfig()
	scattered, ok := rules.Get("scattered-construction")
	if !ok {
		t.Fatal("scattered-construction rule must be registered")
	}
	if _, ok := scattered.(rules.StatefulRule); !ok {
		t.Fatal("scattered-construction accumulates state across files and must implement StatefulRule")
	}

	contexts := sampleContexts(t, 6)
	rules.ResetState([]rules.Rule{scattered})
	want := fingerprint(analyzeFiles(contexts, []rules.Rule{scattered}, cfg, nil))

	for run := 0; run < 5; run++ {
		rules.ResetState([]rules.Rule{scattered})
		if got := fingerprint(analyzeFiles(contexts, []rules.Rule{scattered}, cfg, nil)); got != want {
			t.Fatalf("cross-file findings changed between runs:\nwant:\n%s\ngot:\n%s", want, got)
		}
	}
}
