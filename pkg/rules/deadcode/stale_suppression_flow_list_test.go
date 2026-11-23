package deadcode

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/stretchr/testify/require"
)

type flowListTestRule struct{ *rules.BaseRule }

func (*flowListTestRule) AnalyzeFile(*core.FileContext) []*core.Violation { return nil }

// registerFlowListTestRule registers the stand-in error-string rule once per
// test binary: the registry refuses a second rule of one name.
func registerFlowListTestRule() {
	if _, ok := rules.Get("error-string"); !ok {
		rules.Register(&flowListTestRule{rules.NewBaseRule("error-string", "patterns", "test rule", core.SeverityLow)})
	}
}

func TestStaleSuppressionFlowList(t *testing.T) {
	root := t.TempDir()
	config := `version: 1
categories:
  patterns:
    rules:
      error-string:
        exceptions: [{file: a.go, function: F, reason: silences a finding}, {file: b.go, function: G, reason: stale}]
`
	require.NoError(t, os.WriteFile(filepath.Join(root, ".glint.yaml"), []byte(config), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "a.go"), []byte("package p\nfunc F() {}\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "b.go"), []byte("package p\nfunc G() {}\n"), 0o644))
	cfg, err := core.LoadConfigWithDefaults(root)
	require.NoError(t, err)
	exceptions := cfg.GetRuleExceptions("patterns", "error-string")
	require.Len(t, exceptions, 2)
	registerFlowListTestRule()
	errorString, ok := rules.Get("error-string")
	require.True(t, ok)
	run := StaleSuppressionRun{
		Contexts: []*core.FileContext{core.NewFileContext(filepath.Join(root, "a.go"), root, nil, cfg)},
		Suppressions: core.ViolationList{core.NewSuppressionEntry("error-string", "patterns", "a.go", 1, core.SeverityLow,
			core.SuppressionExceptionPrefix+cfg.ExceptionKey(exceptions[0]))},
		Executed: map[string]rules.Rule{"error-string": errorString},
		Config:   cfg, WholeRoot: true,
	}
	found, err := NewStaleSuppressionRule().Check(run)
	require.NoError(t, err)
	require.Len(t, found, 1)
	require.Equal(t, ".glint.yaml", found[0].File)
	require.Equal(t, 6, found[0].Line)
}

// The finding of a dead exception names what the exception names, its line
// too, so of two exceptions on one line that differ in nothing else the
// reader still sees which one is dead.
func TestStaleSuppressionFlowListNamesTheDeadException(t *testing.T) {
	for _, tc := range []struct{ name, exceptions, want, not string }{
		{"line", `[{file: a.go, line: 1, reason: silences a finding}, {file: a.go, line: 2, reason: stale}]`, `file "a.go", line 2 `, "line 1"},
		{"pattern", `[{file: a.go, line: 1, reason: silences a finding}, {pattern: "never here", reason: stale}]`, `for pattern "never here" `, "line 1"},
		{"negative line", `[{file: a.go, line: 1, reason: silences a finding}, {line: -1, reason: stale}]`, "for every finding ", "line 1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			config := "version: 1\ncategories:\n  patterns:\n    rules:\n      error-string:\n        exceptions: " + tc.exceptions + "\n"
			require.NoError(t, os.WriteFile(filepath.Join(root, ".glint.yaml"), []byte(config), 0o644))
			require.NoError(t, os.WriteFile(filepath.Join(root, "a.go"), []byte("package p\nfunc F() {}\n"), 0o644))
			cfg, err := core.LoadConfigWithDefaults(root)
			require.NoError(t, err)
			exceptions := cfg.GetRuleExceptions("patterns", "error-string")
			require.Len(t, exceptions, 2)
			registerFlowListTestRule()
			errorString, ok := rules.Get("error-string")
			require.True(t, ok)
			run := StaleSuppressionRun{
				Contexts: []*core.FileContext{core.NewFileContext(filepath.Join(root, "a.go"), root, nil, cfg)},
				Suppressions: core.ViolationList{core.NewSuppressionEntry("error-string", "patterns", "a.go", 1, core.SeverityLow,
					core.SuppressionExceptionPrefix+cfg.ExceptionKey(exceptions[0]))},
				Executed: map[string]rules.Rule{"error-string": errorString},
				Config:   cfg, WholeRoot: true,
			}
			found, err := NewStaleSuppressionRule().Check(run)
			require.NoError(t, err)
			require.Len(t, found, 1)
			require.Contains(t, found[0].Message, tc.want)
			require.NotContains(t, found[0].Message, tc.not)
		})
	}
}
