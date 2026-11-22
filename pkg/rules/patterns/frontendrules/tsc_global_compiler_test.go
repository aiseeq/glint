package frontendrules

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTscGlobalCompilerUsesOnlyGlobalTsc(t *testing.T) {
	rulestest.IsolateUserCache(t, t.TempDir())
	root := t.TempDir()
	config := filepath.Join(root, "tsconfig.json")
	require.NoError(t, os.WriteFile(config, []byte(`{"compilerOptions":{"strict":true},"files":["main.ts"]}`), 0o644))
	local, localLog := secondRunTsc(t, "5.9.3", "local-tsc", "")
	global, globalLog := secondRunTsc(t, "7.0.2", "global-tsc", "")
	answer, err := runTscProgram(&tscProgram{config: config, tsc: local, compiler: "global"}, globalTscInfo{path: global})
	require.NoError(t, err)
	assert.Empty(t, answer.Errors)
	assert.Empty(t, answer.TSC7)
	assert.Zero(t, secondRunCount(t, localLog))
	assert.Equal(t, 1, secondRunCount(t, globalLog))
}

func TestTscGlobalCompilerErrorsAreHighFindings(t *testing.T) {
	rulestest.IsolateUserCache(t, t.TempDir())
	root := t.TempDir()
	config := filepath.Join(root, "tsconfig.json")
	source := filepath.Join(root, "main.ts")
	require.NoError(t, os.WriteFile(config, []byte(`{"compilerOptions":{"strict":true},"files":["main.ts"]}`), 0o644))
	require.NoError(t, os.WriteFile(source, []byte("export const value: number = 'bad'\n"), 0o644))
	global := filepath.Join(root, "node_modules", "typescript", "bin", "tsc")
	globalLog := filepath.Join(root, "global-runs")
	require.NoError(t, os.MkdirAll(filepath.Dir(global), 0o755))
	script := fmt.Sprintf("#!/bin/sh\nif [ \"$1\" = --version ]; then printf 'Version 7.0.2\\n'; exit 0; fi\ncase \"$*\" in *--showConfig*) printf '%%s\\n' '{\"compilerOptions\":{\"strict\":true}}'; exit 0 ;; esac\nprintf 'run\\n' >> %q\nprevious=\nfor arg in \"$@\"; do if [ \"$previous\" = --tsBuildInfoFile ]; then printf '{}\\n' > \"$arg\"; fi; previous=\"$arg\"; done\nprintf '%%s\\n' %q\nexit 2\n", globalLog, source+"(1,29): error TS2322: Type 'string' is not assignable to type 'number'.")
	require.NoError(t, os.WriteFile(global, []byte(script), 0o755))
	contexts := tscContexts(t, root)
	rule := NewTscRule()
	rule.global = global
	require.NoError(t, rule.Configure(map[string]any{"compiler": "global"}))
	require.NoError(t, rule.CheckTools(contexts))
	var findings []*core.Violation
	for _, ctx := range contexts {
		findings = append(findings, rule.AnalyzeFile(ctx)...)
	}
	require.Len(t, findings, 1)
	assert.Equal(t, core.SeverityHigh, findings[0].Severity)
	assert.Contains(t, findings[0].Message, "TS2322")
	assert.Equal(t, 1, secondRunCount(t, globalLog))
}

func TestTscGlobalCompilerDefaultStillComparesBothCompilers(t *testing.T) {
	rulestest.IsolateUserCache(t, t.TempDir())
	root := t.TempDir()
	config := filepath.Join(root, "tsconfig.json")
	source := filepath.Join(root, "main.ts")
	require.NoError(t, os.WriteFile(config, []byte(`{"compilerOptions":{"strict":true}}`), 0o644))
	local, localLog := secondRunTsc(t, "5.9.3", "local-tsc", "")
	extra := source + "(1,1): error TS9999: only tsc 7 reports this"
	global, globalLog := secondRunTsc(t, "7.0.2", "global-tsc", extra)
	answer, err := runTscProgram(&tscProgram{config: config, tsc: local}, globalTscInfo{path: global})
	require.NoError(t, err)
	assert.Empty(t, answer.Errors)
	require.Len(t, answer.TSC7, 1)
	assert.Equal(t, "TS9999", answer.TSC7[0].Code)
	assert.Equal(t, 1, secondRunCount(t, localLog))
	assert.Equal(t, 1, secondRunCount(t, globalLog))
}

func TestTscGlobalCompilerRejectsUnknownSetting(t *testing.T) {
	err := NewTscRule().Configure(map[string]any{"compiler": "nonsense"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "project\" or \"global")
}

func TestTscGlobalCompilerCacheSeparatesModes(t *testing.T) {
	rulestest.IsolateUserCache(t, t.TempDir())
	root := t.TempDir()
	config := filepath.Join(root, "tsconfig.json")
	require.NoError(t, os.WriteFile(config, []byte(`{"compilerOptions":{"strict":true}}`), 0o644))
	local, localLog := secondRunTsc(t, "5.9.3", "local-tsc", "")
	global, globalLog := secondRunTsc(t, "7.0.2", "global-tsc", "")
	old := time.Now().Add(-5 * time.Second)
	for _, path := range []string{root, config, local, global} {
		require.NoError(t, os.Chtimes(path, old, old))
	}
	projectAnswer, err := runTscProgram(&tscProgram{config: config, tsc: local}, globalTscInfo{path: global})
	require.NoError(t, err)
	globalAnswer, err := runTscProgram(&tscProgram{config: config, tsc: local, compiler: "global"}, globalTscInfo{path: global})
	require.NoError(t, err)
	assert.Equal(t, projectAnswer, globalAnswer)
	assert.Equal(t, 1, secondRunCount(t, localLog))
	assert.Equal(t, 2, secondRunCount(t, globalLog), "the global mode must execute even when the project-mode answer is cached")
}
