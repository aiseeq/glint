package frontendrules

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patterntest"
	"github.com/aiseeq/glint/pkg/toolcache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func buildInfoCountingTsc(t *testing.T, real string) (string, string) {
	t.Helper()
	log := filepath.Join(t.TempDir(), "reused")
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
	return wrapper, log
}

func requireBuildInfoReused(t *testing.T, log string) {
	t.Helper()
	data, err := os.ReadFile(log)
	require.NoError(t, err, "tsc must receive its previous buildinfo")
	require.Contains(t, string(data), "used")
}

func TestTscAtomicSourceEditReusesBuildInfo(t *testing.T) {
	wrapper, log := buildInfoCountingTsc(t, globalTsc7(t))
	root := tscProject(t, wrapper, map[string]string{"tsconfig.json": strictTSConfig, "src/main.ts": "export const n: number = 1\n"})
	ageTscInputs(t, root, wrapper)
	require.Empty(t, incrementalTscAnswer(t, root))
	target := filepath.Join(root, "src", "main.ts")
	temp := filepath.Join(root, "src", "replacement.tmp")
	require.NoError(t, os.WriteFile(temp, []byte("export const n: number = 2\n"), 0o644))
	require.NoError(t, os.Rename(temp, target))
	assert.Equal(t, fullTscAnswer(t, root), incrementalTscAnswer(t, root))
	requireBuildInfoReused(t, log)
}

func TestTscJSONEditReusesBuildInfo(t *testing.T) {
	wrapper, log := buildInfoCountingTsc(t, globalTsc7(t))
	root := tscProject(t, wrapper, map[string]string{
		"tsconfig.json":   `{"compilerOptions":{"strict":true,"module":"esnext","moduleResolution":"bundler","resolveJsonModule":true,"noEmit":true},"include":["src"]}`,
		"src/main.ts":     "import config from './config.json'; export const n: number = config.value\n",
		"src/config.json": `{"value":1}`,
	})
	ageTscInputs(t, root, wrapper)
	require.Empty(t, incrementalTscAnswer(t, root))
	patterntest.WriteProjectFile(t, root, "src/config.json", `{"value":"one"}`)
	full := fullTscAnswer(t, root)
	require.NotEmpty(t, full)
	assert.Equal(t, full, incrementalTscAnswer(t, root))
	requireBuildInfoReused(t, log)
}

func TestTscDependencyFileChangeStartsFresh(t *testing.T) {
	wrapper, log := buildInfoCountingTsc(t, globalTsc7(t))
	root := tscProject(t, wrapper, map[string]string{
		"tsconfig.json":                 strictTSConfig,
		"src/main.ts":                   "import {value} from 'pkg'; export const n: number = value\n",
		"node_modules/pkg/package.json": `{"name":"pkg","types":"index.d.ts"}`,
		"node_modules/pkg/index.d.ts":   "export const value: number\n",
	})
	ageTscInputs(t, root, wrapper)
	require.Empty(t, incrementalTscAnswer(t, root))
	patterntest.WriteProjectFile(t, root, "node_modules/pkg/index.d.ts", "export const value: string\n")
	assert.Equal(t, fullTscAnswer(t, root), incrementalTscAnswer(t, root))
	_, err := os.Stat(log)
	assert.True(t, os.IsNotExist(err), "tsc 7 must not reuse buildinfo after a dependency changes")
}

func TestTscAddedGlobalDeclarationMatchesFull(t *testing.T) {
	root, local, _ := countedTscProject(t, map[string]string{"tsconfig.json": strictTSConfig, "src/main.ts": "export const n: number = probeGlobal;\n"})
	ageTscInputs(t, root, local)
	initial := incrementalTscAnswer(t, root)
	require.NotEmpty(t, initial)
	assert.Equal(t, "TS2304", initial[0].Code)
	patterntest.WriteProjectFile(t, root, "src/globals.d.ts", "declare const probeGlobal: number;\n")
	full := fullTscAnswer(t, root)
	require.Empty(t, full)
	assert.Equal(t, full, incrementalTscAnswer(t, root))
}

func TestTscUnresolvedReferenceReusesBuildInfo(t *testing.T) {
	wrapper, log := buildInfoCountingTsc(t, globalTsc7(t))
	root := tscProject(t, wrapper, map[string]string{"tsconfig.json": strictTSConfig, "src/main.ts": "import {value} from 'pkg'; export const n: number = value\n"})
	ageTscInputs(t, root, wrapper)
	first := incrementalTscAnswer(t, root)
	require.NotEmpty(t, first)
	require.Equal(t, "TS2307", first[0].Code)
	assert.Equal(t, fullTscAnswer(t, root), incrementalTscAnswer(t, root))
	requireBuildInfoReused(t, log)
	before, err := os.ReadFile(log)
	require.NoError(t, err)
	patterntest.WriteProjectFile(t, root, "src/main.ts", "import {value} from 'pkg'; export const n: number = value; export const x = 1\n")
	edited := incrementalTscAnswer(t, root)
	assert.Equal(t, fullTscAnswer(t, root), edited)
	after, err := os.ReadFile(log)
	require.NoError(t, err)
	assert.Greater(t, len(after), len(before), "a source edit also reuses buildinfo")
	patterntest.WriteProjectFile(t, root, "src/main.ts", "import {value} from 'pkg'; export const n: number = value; export const x = 2\n")
	againAnswer := incrementalTscAnswer(t, root)
	assert.Equal(t, fullTscAnswer(t, root), againAnswer)
	again, err := os.ReadFile(log)
	require.NoError(t, err)
	assert.Greater(t, len(again), len(after), "consecutive source edits reuse buildinfo")
	patterntest.WriteProjectFile(t, root, "node_modules/pkg/package.json", `{"name":"pkg","types":"index.d.ts"}`)
	patterntest.WriteProjectFile(t, root, "node_modules/pkg/index.d.ts", "export const value: number\n")
	assert.Empty(t, fullTscAnswer(t, root))
	assert.Equal(t, fullTscAnswer(t, root), incrementalTscAnswer(t, root))
}

func TestTscReusesProjectCompilerVersion(t *testing.T) {
	real := globalTsc7(t)
	log := filepath.Join(t.TempDir(), "versions")
	wrapper := filepath.Join(t.TempDir(), "tsc")
	script := fmt.Sprintf("#!/bin/sh\nif [ \"$1\" = --version ]; then printf 'version\\n' >> %q; fi\nexec %q \"$@\"\n", log, real)
	require.NoError(t, os.WriteFile(wrapper, []byte(script), 0o755))
	root := tscProject(t, wrapper, map[string]string{
		"tsconfig.json": strictTSConfig,
		"src/main.ts":   "import {value} from 'pkg'; export const n = value\n",
	})
	ageTscInputs(t, root, wrapper)
	require.NotEmpty(t, incrementalTscAnswer(t, root))
	before, err := os.ReadFile(log)
	require.NoError(t, err)
	forgetToolVersion(filepath.Join(root, "node_modules", ".bin", "tsc"))
	require.NotEmpty(t, incrementalTscAnswer(t, root))
	after, err := os.ReadFile(log)
	require.NoError(t, err)
	assert.Equal(t, string(before), string(after), "the saved compiler version avoids another --version launch")
	now := time.Now()
	require.NoError(t, os.Chtimes(wrapper, now, now))
	require.NotEmpty(t, incrementalTscAnswer(t, root))
	changed, err := os.ReadFile(log)
	require.NoError(t, err)
	assert.Greater(t, len(changed), len(after), "a changed compiler must be queried again")
}

func TestTscSourceEditReusesShownConfig(t *testing.T) {
	root, local, log := countedTscProject(t, map[string]string{
		"tsconfig.json": strictTSConfig,
		"src/main.ts":   "import {value} from 'pkg'; export const n = value\n",
	})
	ageTscInputs(t, root, local)
	require.Contains(t, strings.Join(runCountedTsc(t, root), "\n"), "TS2307")
	before, err := os.ReadFile(log)
	require.NoError(t, err)
	require.Equal(t, 1, strings.Count(string(before), "--showConfig"))
	patterntest.WriteProjectFile(t, root, "src/main.ts", "import {value} from 'pkg'; export const n = value; export const x = 1\n")
	require.Contains(t, strings.Join(runCountedTsc(t, root), "\n"), "TS2307")
	after, err := os.ReadFile(log)
	require.NoError(t, err)
	assert.Equal(t, 1, strings.Count(string(after), "--showConfig"), "source edits reuse the unchanged effective configuration")
	patterntest.WriteProjectFile(t, root, "tsconfig.json", strings.Replace(strictTSConfig, `"strict": true`, `"strict": false`, 1))
	findings := runCountedTsc(t, root)
	assert.Contains(t, strings.Join(findings, "\n"), "does not make tsc strict")
	changed, err := os.ReadFile(log)
	require.NoError(t, err)
	assert.Equal(t, 2, strings.Count(string(changed), "--showConfig"), "a changed configuration must be read again")
}

func TestTscCompilerVersionsInvalidatedByExecutableChange(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	compiler := filepath.Join(t.TempDir(), "tsc")
	require.NoError(t, os.WriteFile(compiler, []byte("compiler"), 0o755))
	old := time.Now().Add(-time.Minute)
	require.NoError(t, os.Chtimes(compiler, old, old))
	stamp, err := statPath(compiler)
	require.NoError(t, err)
	fingerprint := tscStatFingerprint{
		Files:         []tscFileStat{stamp},
		Answer:        &tscAnswer{Errors: []tscDiagnostic{{Code: "TS2307"}}},
		LocalMajor:    5,
		GlobalVersion: "Version 7.0.2\n",
	}
	identity := []string{"compiler-versions"}
	require.NoError(t, tscCache.Store(statFingerprintKey(identity), fingerprint))
	lookup, err := statCachedAnswer(identity, []string{compiler})
	require.NoError(t, err)
	assert.Equal(t, 5, lookup.localMajor)
	assert.Equal(t, "Version 7.0.2\n", lookup.globalVersion)
	now := time.Now()
	require.NoError(t, os.Chtimes(compiler, now, now))
	lookup, err = statCachedAnswer(identity, []string{compiler})
	require.NoError(t, err)
	assert.Zero(t, lookup.localMajor)
	assert.Empty(t, lookup.globalVersion)
}

func TestTscNoCacheDoesNotOverwriteFingerprint(t *testing.T) {
	root, local, _ := countedTscProject(t, map[string]string{"tsconfig.json": strictTSConfig, "src/main.ts": "import {value} from 'pkg'; export const n = value\n"})
	ageTscInputs(t, root, local)
	require.Contains(t, strings.Join(runCountedTsc(t, root), "\n"), "TS2307")
	cache := filepath.Join(os.Getenv("XDG_CACHE_HOME"), "glint", "tools", "tsc")
	before, err := os.ReadDir(cache)
	require.NoError(t, err)
	contents := map[string]string{}
	stamps := map[string]time.Time{}
	for _, entry := range before {
		path := filepath.Join(cache, entry.Name())
		old := time.Now().Add(-time.Minute)
		require.NoError(t, os.Chtimes(path, old, old))
		info, err := os.Stat(path)
		require.NoError(t, err)
		stamps[entry.Name()] = info.ModTime()
		b, err := os.ReadFile(path)
		require.NoError(t, err)
		contents[entry.Name()] = string(b)
	}
	toolcache.Disabled = true
	t.Cleanup(func() { toolcache.Disabled = false })
	require.Contains(t, strings.Join(runCountedTsc(t, root), "\n"), "TS2307")
	after, err := os.ReadDir(cache)
	require.NoError(t, err)
	require.Len(t, after, len(contents))
	for _, entry := range after {
		path := filepath.Join(cache, entry.Name())
		b, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Equal(t, contents[entry.Name()], string(b), entry.Name())
		info, err := os.Stat(path)
		require.NoError(t, err)
		assert.Equal(t, stamps[entry.Name()], info.ModTime(), entry.Name())
	}
}

func TestTscStandaloneNoCacheDoesNotStore(t *testing.T) {
	globalTsc7(t)
	root := tscProject(t, "", map[string]string{
		"run.ts":                   "export const n: number = 1\n",
		"typing/node/package.json": `{"name":"@types/node","types":"index.d.ts"}`,
		"typing/node/index.d.ts":   "export {}\n",
	})
	ageTscInputs(t, root)
	global, err := NewTscRule().globalTscBase()
	require.NoError(t, err)
	global.typeRoots = filepath.Join(root, "typing")
	toolcache.Disabled = true
	t.Cleanup(func() { toolcache.Disabled = false })
	answer, err := runStandalone(filepath.Join(root, "run.ts"), global)
	require.NoError(t, err)
	assert.Empty(t, answer.Errors)
	entries, err := os.ReadDir(filepath.Join(os.Getenv("XDG_CACHE_HOME"), "glint", "tools", "tsc"))
	if os.IsNotExist(err) {
		return
	}
	require.NoError(t, err)
	assert.Empty(t, entries, "--no-cache must not store standalone answers or fingerprints")
}

func TestTscUnstableUnresolvedRunInvalidatesOldFingerprint(t *testing.T) {
	real := globalTsc7(t)
	root := tscProject(t, "", map[string]string{
		"tsconfig.json": strictTSConfig,
		"src/main.ts":   "export const n = 1\n",
	})
	target := filepath.Join(root, "src", "main.ts")
	marker := filepath.Join(t.TempDir(), "edit")
	wrapper := filepath.Join(t.TempDir(), "tsc")
	script := fmt.Sprintf(`#!/bin/sh
%q "$@"
status=$?
case "$*" in
  *--listFiles*)
    if [ -f %q ]; then
      printf 'import {value} from "pkg"; export const n = value; export const x = 2\n' > %q
      rm %q
    fi ;;
esac
exit "$status"
`, real, marker, target, marker)
	require.NoError(t, os.WriteFile(wrapper, []byte(script), 0o755))
	installProjectTsc(t, root, wrapper)
	ageTscInputs(t, root, wrapper)
	require.Empty(t, incrementalTscAnswer(t, root))
	cache := filepath.Join(os.Getenv("XDG_CACHE_HOME"), "glint", "tools", "tsc")
	entries, err := filepath.Glob(filepath.Join(cache, "stat-v3-*.json"))
	require.NoError(t, err)
	require.Len(t, entries, 1)
	var fingerprint tscStatFingerprint
	data, err := os.ReadFile(entries[0])
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(data, &fingerprint))
	require.NotNil(t, fingerprint.Answer)
	patterntest.WriteProjectFile(t, root, "src/main.ts", "import {value} from 'pkg'; export const n = value; export const x = 1\n")
	require.NoError(t, os.WriteFile(marker, []byte("edit"), 0o600))
	answer := incrementalTscAnswer(t, root)
	require.NotEmpty(t, answer)
	assert.Equal(t, "TS2307", answer[0].Code)
	data, err = os.ReadFile(entries[0])
	require.NoError(t, err)
	fingerprint = tscStatFingerprint{}
	require.NoError(t, json.Unmarshal(data, &fingerprint))
	assert.Nil(t, fingerprint.Answer, "an unstable unresolved run invalidates the previous answer")
	assert.Empty(t, fingerprint.AnswerKey)
	assert.Equal(t, fullTscAnswer(t, root), incrementalTscAnswer(t, root))
}

func TestTsc5ReusesBuildInfoAfterPackageChange(t *testing.T) {
	path := os.Getenv("GLINT_TEST_TSC5")
	if path == "" {
		t.Skip("set GLINT_TEST_TSC5 to a local TypeScript 5 compiler")
	}
	wrapper, log := buildInfoCountingTsc(t, path)
	root := tscProject(t, wrapper, map[string]string{
		"tsconfig.json":                 strictTSConfig,
		"src/main.ts":                   "import {value} from 'pkg'; export const n: number = value\n",
		"node_modules/pkg/package.json": `{"name":"pkg","types":"index.d.ts"}`,
		"node_modules/pkg/index.d.ts":   "export const value: number\n",
		"node_modules/pkg/other.d.ts":   "export const value: string\n",
	})
	ageTscInputs(t, root, wrapper)
	require.Empty(t, incrementalTscAnswer(t, root))
	patterntest.WriteProjectFile(t, root, "node_modules/pkg/package.json", `{"name":"pkg","types":"other.d.ts"}`)
	assert.Equal(t, fullTscAnswer(t, root), incrementalTscAnswer(t, root))
	requireBuildInfoReused(t, log)
}

func TestTscOlderVersionKeepsBuildInfoAfterConfigChange(t *testing.T) {
	real := globalTsc7(t)
	log := filepath.Join(t.TempDir(), "reused")
	wrapper := filepath.Join(t.TempDir(), "tsc")
	script := fmt.Sprintf(`#!/bin/sh
if [ "$1" = --version ]; then printf 'Version 5.9.9\n'; exit 0; fi
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
		"src/main.ts":   "const xs: number[] = [1]; export const n: number = xs[0]\n",
	})
	ageTscInputs(t, root, wrapper)
	require.Empty(t, incrementalTscAnswer(t, root))
	updated := strings.Replace(strictTSConfig, `"strict": true`, `"strict": true, "noUncheckedIndexedAccess": true`, 1)
	patterntest.WriteProjectFile(t, root, "tsconfig.json", updated)
	full := fullTscAnswer(t, root)
	require.NotEmpty(t, full)
	assert.Equal(t, full, incrementalTscAnswer(t, root))
	requireBuildInfoReused(t, log)
}

func TestTscRecentInputsMustStayStableDuringRun(t *testing.T) {
	root := tscProject(t, "", map[string]string{
		"tsconfig.json": strictTSConfig,
		"src/main.ts":   "export const n = 1\n",
	})
	config := filepath.Join(root, "tsconfig.json")
	listed := []byte(filepath.Join(root, "src", "main.ts") + "\n")
	before, err := makeStatFingerprint(nil, config, listed, "")
	require.NoError(t, err)
	started := time.Now()
	patterntest.WriteProjectFile(t, root, "src/main.ts", "export const n = 2\n")
	stored, err := storeProjectStatFingerprintIfStable([]string{"race"}, nil, config, listed, tscAnswer{}, started, &before, 7, "Version 7.0.0")
	require.NoError(t, err)
	assert.False(t, stored, "an input edited during tsc cannot be cached")
	before, err = makeStatFingerprint(nil, config, listed, "")
	require.NoError(t, err)
	stored, err = storeProjectStatFingerprintIfStable([]string{"stable"}, nil, config, listed, tscAnswer{}, time.Now(), &before, 7, "Version 7.0.0")
	require.NoError(t, err)
	assert.True(t, stored, "recent inputs that stayed unchanged may be cached")
}

func TestTscNewPackageMetadataInvalidatesFingerprint(t *testing.T) {
	root := tscProject(t, "", map[string]string{
		"tsconfig.json": strictTSConfig,
		"src/main.ts":   "export const n = 1\n",
	})
	config := filepath.Join(root, "tsconfig.json")
	listed := []byte(filepath.Join(root, "src", "main.ts") + "\n")
	fingerprint, err := makeStatFingerprint(nil, config, listed, "")
	require.NoError(t, err)
	fingerprint.Answer = &tscAnswer{}
	identity := []string{"package-metadata"}
	require.NoError(t, tscCache.Store(statFingerprintKey(identity), fingerprint))
	patterntest.WriteProjectFile(t, root, "src/package.json", `{"type":"module"}`)
	lookup, err := statCachedAnswer(identity, nil)
	require.NoError(t, err)
	assert.Equal(t, tscStatStale, lookup.status)
	assert.False(t, lookup.reuseBuildInfo)
}

func TestTscConfigResolutionChangesMatchFull(t *testing.T) {
	for _, tc := range []struct {
		name   string
		before string
		after  string
		files  map[string]string
	}{
		{
			name:   "types",
			before: `{"compilerOptions":{"strict":true,"module":"esnext","moduleResolution":"bundler","noEmit":true,"types":[]},"include":["src"]}`,
			after:  `{"compilerOptions":{"strict":true,"module":"esnext","moduleResolution":"bundler","noEmit":true,"types":["probe"]},"include":["src"]}`,
			files:  map[string]string{"node_modules/@types/probe/package.json": `{"name":"@types/probe","types":"index.d.ts"}`, "node_modules/@types/probe/index.d.ts": "declare const probeGlobal: number;\n"},
		},
		{
			name:   "include",
			before: `{"compilerOptions":{"strict":true,"module":"esnext","moduleResolution":"bundler","noEmit":true},"include":["src"]}`,
			after:  `{"compilerOptions":{"strict":true,"module":"esnext","moduleResolution":"bundler","noEmit":true},"include":["src","types"]}`,
			files:  map[string]string{"types/globals.d.ts": "declare const probeGlobal: number;\n"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files := map[string]string{"tsconfig.json": tc.before, "src/main.ts": "export const n: number = probeGlobal;\n"}
			maps.Copy(files, tc.files)
			root, local, _ := countedTscProject(t, files)
			ageTscInputs(t, root, local)
			initial := incrementalTscAnswer(t, root)
			require.NotEmpty(t, initial)
			assert.Equal(t, "TS2304", initial[0].Code)
			patterntest.WriteProjectFile(t, root, "tsconfig.json", tc.after)
			full := fullTscAnswer(t, root)
			require.Empty(t, full)
			assert.Equal(t, full, incrementalTscAnswer(t, root))
		})
	}
}
