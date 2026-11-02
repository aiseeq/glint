package main

import (
	"fmt"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

// sampleContexts builds a handful of parsed Go files that trip a broad set of
// rules, so that the whole registry actually runs over them.
func sampleContexts(t *testing.T, count int) []*core.FileContext {
	t.Helper()
	contexts := make([]*core.FileContext, 0, count)
	for i := range count {
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

type sharedIndexKey struct{}

type concurrentProjectFilesRule struct {
	*rules.BaseRule
	ready   *atomic.Int32
	started chan struct{}
	once    *sync.Once
	// serial is set when an index waited in vain for the others: they ran
	// one after another
	serial *atomic.Bool
}

func (r *concurrentProjectFilesRule) AnalyzeFile(*core.FileContext) []*core.Violation { return nil }
func (r *concurrentProjectFilesRule) ResetState()                                     {}
func (r *concurrentProjectFilesRule) UseProjectFiles(files []*core.FileContext) {
	if r.ready.Add(1) == 4 {
		r.once.Do(func() { close(r.started) })
	}
	select {
	case <-r.started:
	case <-time.After(10 * time.Second):
		r.serial.Store(true)
	}
	for _, file := range files {
		core.FileShared(file, sharedIndexKey{}, func() int { return len(file.Lines) })
	}
}

// Indexing rules in parallel must safely share the same FileContexts and the
// per-file derived-value cache.
func TestProjectFileIndexesAreConcurrentAndRaceFree(t *testing.T) {
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(4))
	var ready atomic.Int32
	var once sync.Once
	var serial atomic.Bool
	started := make(chan struct{})
	ruleList := make([]rules.Rule, 4)
	for i := range ruleList {
		ruleList[i] = &concurrentProjectFilesRule{
			BaseRule: rules.NewBaseRule(fmt.Sprintf("shared-index-%d", i), "patterns", "test", core.SeverityLow),
			ready:    &ready,
			started:  started,
			once:     &once,
			serial:   &serial,
		}
	}
	files := sampleContexts(t, 8)
	indexed, panics, err := indexProjectRules(ruleList, files, nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(panics) != 0 {
		t.Fatalf("unexpected index panics: %v", panics)
	}
	if serial.Load() {
		t.Fatal("project-file indexes ran one after another, not concurrently")
	}
	if len(indexed) != len(ruleList) || ready.Load() != int32(len(ruleList)) {
		t.Fatalf("indexes=%d, concurrent index calls=%d; want %d", len(indexed), ready.Load(), len(ruleList))
	}
}

// Analysis runs rules concurrently; the reported findings and their order must
// not depend on scheduling. Run with -race to also catch shared rule state.
func TestAnalyzeFilesIsDeterministicAndRaceFree(t *testing.T) {
	cfg := core.DefaultConfig()
	allRules := rules.All()
	contexts := sampleContexts(t, 12)

	rules.ResetState(allRules)
	want := fingerprint(mustAnalyzeFiles(t, contexts, allRules, cfg, nil))
	if want == "" {
		t.Fatal("sample files produced no findings — the test would not prove anything")
	}

	for run := range 8 {
		rules.ResetState(allRules)
		got := fingerprint(mustAnalyzeFiles(t, contexts, allRules, cfg, nil))
		if got != want {
			t.Fatalf("run %d produced different findings:\nwant:\n%s\ngot:\n%s", run, want, got)
		}
	}
}

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

// The Go project rules run concurrently too; their findings and order must
// not depend on scheduling. Run with -race to also catch state two project
// rules share.
func TestProjectRulesAreDeterministicAndRaceFree(t *testing.T) {
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(4))
	module := t.TempDir()
	writeModuleFile(t, module, "go.mod", "module example.com/check\n\ngo 1.24\n")
	writeModuleFile(t, module, "svc/shared.go", "package svc\n\n// Shared is built everywhere.\ntype Shared struct {\n\tName    string\n\tTimeout int\n\tRetries int\n}\n")
	for i := range 4 {
		writeModuleFile(t, module, fmt.Sprintf("svc/file%d.go", i), fmt.Sprintf(`package svc

import (
	"errors"
	"fmt"
)

// Build%d builds a value from a name.
func Build%d(name string, unused int) (Shared, error) {
	if name == "" {
		return Shared{}, errors.New("empty")
	}
	fmt.Println(Shared{Name: name, Timeout: 60, Retries: %d})
	if err := run%d(); err != nil && err.Error() == "boom" {
		return Shared{}, nil
	}
	return Shared{Name: name, Timeout: 30, Retries: 3}, nil
}

func run%d() error { return nil }
`, i, i, i, i, i))
	}
	cfg := core.DefaultConfig()
	allRules := rules.All()
	prepared, err := prepareAnalysis(core.NewGoProjectLoader(), module, cfg, allRules, false)
	if err != nil {
		t.Fatal(err)
	}
	projectFindings := func() string {
		t.Helper()
		rules.ResetState(allRules)
		violations, panics, err := analyzeProjectContained(prepared.contexts, prepared.contexts, allRules, cfg, prepared.project, nil)
		if err != nil || len(panics) > 0 {
			t.Fatalf("analyze: %v %v", err, panics)
		}
		return fingerprint(violations)
	}

	want := projectFindings()
	for _, rule := range []string{"unused-param", "error-string-compare"} {
		if !strings.Contains(want, rule+"|") {
			t.Fatalf("the sample module must trip the project rule %s — the test would not prove anything:\n%s", rule, want)
		}
	}
	for run := range 4 {
		if got := projectFindings(); got != want {
			t.Fatalf("run %d produced different findings:\nwant:\n%s\ngot:\n%s", run, want, got)
		}
	}
}
