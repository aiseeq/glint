package frontendrules

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patterntest"
	"github.com/aiseeq/glint/pkg/toolcache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTscStaleJSXRuntimeAppears(t *testing.T) {
	root, local, log := countedTscProject(t, map[string]string{
		"tsconfig.json":                   `{"compilerOptions":{"strict":true,"jsx":"react-jsx","module":"esnext","moduleResolution":"bundler","noEmit":true},"include":["src"]}`,
		"src/main.tsx":                    "export const element = <div />\n",
		"node_modules/react/package.json": `{"name":"react","version":"1.0.0"}`,
	})
	ageTscInputs(t, root, local)
	require.Contains(t, strings.Join(runCountedTsc(t, root), "\n"), "TS2875")
	patterntest.WriteProjectFile(t, root, "node_modules/@types/react/package.json", `{"name":"@types/react","version":"1.0.0","types":"index.d.ts"}`)
	patterntest.WriteProjectFile(t, root, "node_modules/@types/react/index.d.ts", "export {}\n")
	patterntest.WriteProjectFile(t, root, "node_modules/@types/react/jsx-runtime.d.ts", "export namespace JSX { interface IntrinsicElements { div: {} } }\n")
	require.Empty(t, fullTscAnswer(t, root))
	assert.Empty(t, runCountedTsc(t, root))
	ageTscInputs(t, root, local)
	assert.Empty(t, runCountedTsc(t, root))
	before := tscRunCount(t, log)
	assert.Empty(t, runCountedTsc(t, root))
	assert.Equal(t, before, tscRunCount(t, log))
}

func TestTscNoCacheIgnoresBuildInfo(t *testing.T) {
	root, _, _ := countedTscProject(t, map[string]string{
		"tsconfig.json":                   `{"compilerOptions":{"strict":true,"jsx":"react-jsx","module":"esnext","moduleResolution":"bundler","noEmit":true},"include":["src"]}`,
		"src/main.tsx":                    "export const element = <div />\n",
		"node_modules/react/package.json": `{"name":"react","version":"1.0.0"}`,
	})
	require.Contains(t, strings.Join(runCountedTsc(t, root), "\n"), "TS2875")
	patterntest.WriteProjectFile(t, root, "node_modules/@types/react/index.d.ts", "export {}\n")
	patterntest.WriteProjectFile(t, root, "node_modules/@types/react/jsx-runtime.d.ts", "export namespace JSX { interface IntrinsicElements { div: {} } }\n")
	toolcache.Disabled = true
	t.Cleanup(func() { toolcache.Disabled = false })
	assert.Empty(t, runCountedTsc(t, root))
}

func TestTscReusesBuildInfoForSourceEdits(t *testing.T) {
	real := globalTsc7(t)
	log := filepath.Join(t.TempDir(), "buildinfo-used")
	wrapper := filepath.Join(t.TempDir(), "tsc")
	script := fmt.Sprintf(`#!/bin/sh
previous=
for arg in "$@"; do
  if [ "$previous" = "--tsBuildInfoFile" ] && [ -f "$arg" ]; then printf 'used\n' >> %q; fi
  previous="$arg"
done
exec %q "$@"
`, log, real)
	require.NoError(t, os.WriteFile(wrapper, []byte(script), 0o755))
	root := tscProject(t, wrapper, map[string]string{
		"tsconfig.json": strictTSConfig,
		"src/main.ts":   "export const n: number = 1\n",
	})
	ageTscInputs(t, root, wrapper)
	require.Empty(t, runCountedTsc(t, root))
	patterntest.WriteProjectFile(t, root, "src/main.ts", "export const n: number = 2\n")
	require.Empty(t, runCountedTsc(t, root))
	data, err := os.ReadFile(log)
	require.NoError(t, err)
	assert.Contains(t, string(data), "used")
}

func TestTscDependencyResolutionChanges(t *testing.T) {
	for _, tc := range []struct {
		name    string
		initial map[string]string
		change  func(*testing.T, string)
	}{
		{name: "missing declaration appears", initial: map[string]string{}, change: func(t *testing.T, root string) {
			patterntest.WriteProjectFile(t, root, "node_modules/pkg/index.d.ts", "export const value: number\n")
		}},
		{name: "package metadata changes", initial: map[string]string{"node_modules/pkg/index.d.ts": "export const value: number\n", "node_modules/pkg/other.d.ts": "export const value: string\n"}, change: func(t *testing.T, root string) {
			patterntest.WriteProjectFile(t, root, "node_modules/pkg/package.json", `{"name":"pkg","types":"other.d.ts"}`)
		}},
		{name: "declaration removed", initial: map[string]string{"node_modules/pkg/index.d.ts": "export const value: number\n"}, change: func(t *testing.T, root string) {
			require.NoError(t, os.Remove(filepath.Join(root, "node_modules/pkg/index.d.ts")))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files := map[string]string{"tsconfig.json": strictTSConfig, "src/main.ts": "import { value } from 'pkg'; export const n: number = value\n", "node_modules/pkg/package.json": `{"name":"pkg","types":"index.d.ts"}`}
			maps.Copy(files, tc.initial)
			root, local, _ := countedTscProject(t, files)
			ageTscInputs(t, root, local)
			assert.Equal(t, fullTscAnswer(t, root), incrementalTscAnswer(t, root))
			tc.change(t, root)
			assert.Equal(t, fullTscAnswer(t, root), incrementalTscAnswer(t, root))
		})
	}
}

func TestTscJSXRuntimeResolutionChanges(t *testing.T) {
	const runtime = "export namespace JSX { interface IntrinsicElements { div: {} } }\n"
	for _, tc := range []struct {
		name     string
		metadata string
		runtime  bool
		change   func(*testing.T, string)
	}{
		{name: "runtime appears", metadata: `{"name":"react"}`, change: func(t *testing.T, root string) {
			patterntest.WriteProjectFile(t, root, "node_modules/react/jsx-runtime.d.ts", runtime)
		}},
		{name: "exports changes", metadata: `{"name":"react","exports":{"./jsx-runtime":"./missing.d.ts"}}`, runtime: true, change: func(t *testing.T, root string) {
			patterntest.WriteProjectFile(t, root, "node_modules/react/package.json", `{"name":"react","exports":{"./jsx-runtime":"./jsx-runtime.d.ts"}}`)
		}},
		{name: "runtime removed", metadata: `{"name":"react"}`, runtime: true, change: func(t *testing.T, root string) {
			require.NoError(t, os.Remove(filepath.Join(root, "node_modules/react/jsx-runtime.d.ts")))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files := map[string]string{"tsconfig.json": `{"compilerOptions":{"strict":true,"jsx":"react-jsx","module":"esnext","moduleResolution":"bundler","noEmit":true},"include":["src"]}`, "src/main.tsx": "export const element = <div />\n", "node_modules/react/package.json": tc.metadata}
			if tc.runtime {
				files["node_modules/react/jsx-runtime.d.ts"] = runtime
			}
			root, local, _ := countedTscProject(t, files)
			ageTscInputs(t, root, local)
			assert.Equal(t, fullTscAnswer(t, root), incrementalTscAnswer(t, root))
			tc.change(t, root)
			assert.Equal(t, fullTscAnswer(t, root), incrementalTscAnswer(t, root))
		})
	}
}

func TestTscUnresolvedReferenceInvalidatesOldFingerprint(t *testing.T) {
	root, local, _ := countedTscProject(t, map[string]string{
		"tsconfig.json":                   `{"compilerOptions":{"strict":true,"jsx":"react-jsx","module":"esnext","moduleResolution":"bundler","noEmit":true},"include":["src"]}`,
		"src/main.tsx":                    "export const element = 1\n",
		"node_modules/react/package.json": `{"name":"react"}`,
	})
	ageTscInputs(t, root, local)
	require.Empty(t, runCountedTsc(t, root))
	patterntest.WriteProjectFile(t, root, "src/main.tsx", "export const element = <div />\n")
	require.Contains(t, strings.Join(runCountedTsc(t, root), "\n"), "TS2875")
	patterntest.WriteProjectFile(t, root, "node_modules/react/jsx-runtime.d.ts", "export namespace JSX { interface IntrinsicElements { div: {} } }\n")
	require.Empty(t, fullTscAnswer(t, root))
	assert.Empty(t, runCountedTsc(t, root))
}
