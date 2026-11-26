package frontendrules

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTscGlobalCompilerUsesOnlyGlobalTsc(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
	root := t.TempDir()
	config := filepath.Join(root, "tsconfig.json")
	source := filepath.Join(root, "main.ts")
	require.NoError(t, os.WriteFile(config, []byte(`{"compilerOptions":{"strict":true},"files":["main.ts"]}`), 0o644))
	require.NoError(t, os.WriteFile(source, []byte("export const value: number = 'bad'\n"), 0o644))
	global := filepath.Join(root, "node_modules", "typescript", "bin", "tsc")
	globalLog := filepath.Join(root, "global-runs")
	require.NoError(t, os.MkdirAll(filepath.Dir(global), 0o755))
	script := fmt.Sprintf("#!/bin/sh\nif [ \"$1\" = --version ]; then printf 'Version 7.0.2\\n'; exit 0; fi\ncase \"$*\" in *--showConfig*) printf '%%s\\n' '{\"compilerOptions\":{\"strict\":true}}'; exit 0 ;; esac\nprintf 'run\\n' >> %q\nprevious=\nfor arg in \"$@\"; do if [ \"$previous\" = --tsBuildInfoFile ]; then printf '{}\\n' > \"$arg\"; fi; previous=\"$arg\"; done\nprintf '%%s\\n' %q\nexit 2\n", globalLog, source+"(1,29): error TS2322: Type 'string' is not assignable to type 'number'.")
	require.NoError(t, writeTestExecutable(global, []byte(script)))
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

func TestTscGlobalCompilerDoesNotCallProjectTsc(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	config := filepath.Join(root, "tsconfig.json")
	source := filepath.Join(root, "main.ts")
	local := filepath.Join(root, "node_modules", ".bin", "tsc")
	localLog := filepath.Join(root, "local-runs")
	global := filepath.Join(root, "node_modules", "typescript", "bin", "tsc")
	globalLog := filepath.Join(root, "global-runs")
	require.NoError(t, os.MkdirAll(filepath.Dir(local), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Dir(global), 0o755))
	require.NoError(t, os.WriteFile(config, []byte(`{"compilerOptions":{"strict":true},"files":["main.ts"]}`), 0o644))
	require.NoError(t, os.WriteFile(source, []byte("export const value: number = 'bad'\n"), 0o644))
	localScript := fmt.Sprintf("#!/bin/sh\nprintf '%%s\\n' \"$*\" >> %q\nif [ \"$1\" = --version ]; then printf 'Version 5.9.3\\n'; exit 0; fi\nprintf '%%s\\n' '{\"compilerOptions\":{\"strict\":true}}'\n", localLog)
	require.NoError(t, writeTestExecutable(local, []byte(localScript)))
	globalScript := fmt.Sprintf("#!/bin/sh\nprintf '%%s\\n' \"$*\" >> %q\nif [ \"$1\" = --version ]; then printf 'Version 7.0.2\\n'; exit 0; fi\ncase \"$*\" in *--showConfig*) printf '%%s\\n' '{\"compilerOptions\":{\"strict\":true}}'; exit 0 ;; esac\nprevious=\nfor arg in \"$@\"; do if [ \"$previous\" = --tsBuildInfoFile ]; then printf '{}\\n' > \"$arg\"; fi; previous=\"$arg\"; done\nprintf '%%s\\n' %q\nexit 2\n", globalLog, source+"(1,29): error TS2322: Type 'string' is not assignable to type 'number'.")
	require.NoError(t, writeTestExecutable(global, []byte(globalScript)))

	rule := NewTscRule()
	rule.global = global
	require.NoError(t, rule.Configure(map[string]any{"compiler": "global"}))
	contexts := tscContexts(t, root)
	require.NoError(t, rule.CheckTools(contexts))
	var findings []*core.Violation
	for _, ctx := range contexts {
		findings = append(findings, rule.AnalyzeFile(ctx)...)
	}
	require.Len(t, findings, 1)
	assert.Equal(t, core.SeverityHigh, findings[0].Severity)
	assert.Contains(t, findings[0].Message, "TS2322")
	localCalls, err := os.ReadFile(localLog)
	if !os.IsNotExist(err) {
		require.NoError(t, err)
	}
	assert.Empty(t, localCalls, "compiler: global must not invoke project tsc, including for --version or --showConfig")
	globalCalls, err := os.ReadFile(globalLog)
	require.NoError(t, err)
	assert.Contains(t, string(globalCalls), "--version")
	assert.Contains(t, string(globalCalls), "--showConfig")
	assert.Contains(t, string(globalCalls), "--listFiles")
}

func TestTscGlobalCompilerDefaultStillComparesBothCompilers(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
	err := NewTscRule().Configure(map[string]any{"compiler": "nonsense"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "project\" or \"global")
}

func TestTscGlobalCompilerRejectsNonStringSetting(t *testing.T) {
	t.Parallel()
	for _, value := range []any{7, true, []string{"global"}} {
		t.Run(fmt.Sprintf("%T", value), func(t *testing.T) {
			err := NewTscRule().Configure(map[string]any{"compiler": value})
			require.Error(t, err)
			assert.Contains(t, err.Error(), "must be a string")
		})
	}
}

func TestTscGlobalCompilerCacheSeparatesModes(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	config := filepath.Join(root, "tsconfig.json")
	require.NoError(t, os.WriteFile(config, []byte(`{"compilerOptions":{"strict":true}}`), 0o644))
	source := filepath.Join(root, "main.ts")
	require.NoError(t, os.WriteFile(source, []byte("export const value = 1\n"), 0o644))
	local, localLog := secondRunTsc(t, "5.9.3", "local-tsc", source)
	extra := source + "\n" + source + "(1,1): error TS9999: only global mode reports this"
	global, globalLog := secondRunTsc(t, "7.0.2", "global-tsc", extra)
	old := time.Now().Add(-5 * time.Second)
	for _, path := range []string{root, config, source, local, global} {
		require.NoError(t, os.Chtimes(path, old, old))
	}
	projectAnswer, err := runTscProgram(&tscProgram{config: config, tsc: local}, globalTscInfo{path: global})
	require.NoError(t, err)
	projectIdentity := []string{config, local, global, "-p", config, "--showConfig", "-p", config, "--noEmit", "--incremental", "--pretty", "false", "--listFiles"}
	poison := tscAnswer{Errors: []tscDiagnostic{{Code: "TS0000", Message: "project cache entry"}}}
	require.NoError(t, tscCache.Store(statFingerprintKey(projectIdentity), tscStatFingerprint{Answer: &poison}))
	globalAnswer, err := runTscProgram(&tscProgram{config: config, tsc: local, compiler: "global"}, globalTscInfo{path: global})
	require.NoError(t, err)
	assert.Empty(t, projectAnswer.Errors)
	require.Len(t, projectAnswer.TSC7, 1)
	assert.Equal(t, "TS9999", projectAnswer.TSC7[0].Code)
	require.Len(t, globalAnswer.Errors, 1)
	assert.Equal(t, "TS9999", globalAnswer.Errors[0].Code)
	assert.Empty(t, globalAnswer.TSC7)
	assert.Equal(t, 1, secondRunCount(t, localLog))
	assert.Equal(t, 2, secondRunCount(t, globalLog), "the global mode must execute even when the project-mode answer is cached")
}
