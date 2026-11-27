//go:build !race

package main

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

// Stateful analysis tests use one analysis worker and do not start a Walker.

// Stateful rules see files in a fixed order, so their cross-file findings stay
// reproducible even though the rest of the analysis is parallel.
func TestStatefulRulesSeeFilesInOrder(t *testing.T) {
	cfg := core.DefaultConfig()
	crossFile, ok := rules.Get("cross-file-duplicate")
	if !ok {
		t.Fatal("cross-file-duplicate rule must be registered")
	}
	if _, ok := crossFile.(rules.StatefulRule); !ok {
		t.Fatal("cross-file-duplicate accumulates state across files and must implement StatefulRule")
	}

	contexts := sampleContexts(t, 6)
	rules.ResetState([]rules.Rule{crossFile})
	want := fingerprint(mustAnalyzeFiles(t, contexts, []rules.Rule{crossFile}, cfg, nil))
	if want == "" {
		t.Fatal("the sample files are near-copies; cross-file-duplicate must report them")
	}

	for range 5 {
		rules.ResetState([]rules.Rule{crossFile})
		if got := fingerprint(mustAnalyzeFiles(t, contexts, []rules.Rule{crossFile}, cfg, nil)); got != want {
			t.Fatalf("cross-file findings changed between runs:\nwant:\n%s\ngot:\n%s", want, got)
		}
	}
}
