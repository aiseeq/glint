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
	rules.Register(&flowListTestRule{rules.NewBaseRule("error-string", "patterns", "test rule", core.SeverityLow)})
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
