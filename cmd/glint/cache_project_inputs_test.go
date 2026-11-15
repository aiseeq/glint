package main

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/patterns/qarules"
)

// writeLiveGateModule writes a module whose test skips unless a token is set.
// The gate is a real guard only while no env file of the project names the
// token, so the finding of test-external-service depends on the env files,
// which are no input of the typed load.
func writeLiveGateModule(t *testing.T, root string) {
	t.Helper()
	writeModuleFile(t, root, "go.mod", "module example.com/app\n\ngo 1.24\n")
	writeModuleFile(t, root, "vault/vault.go", "// Package vault reads secrets.\npackage vault\n\n// Name is the name of the store.\nconst Name = \"vault\"\n")
	writeModuleFile(t, root, "vault/live_test.go", `package vault

import (
	"os"
	"testing"
)

func TestLiveVault(t *testing.T) {
	addr := os.Getenv("LIVE_VAULT_ADDR")
	token := os.Getenv("LIVE_VAULT_TOKEN")
	if addr == "" || token == "" {
		t.Skip("live vault check needs LIVE_VAULT_ADDR and LIVE_VAULT_TOKEN")
	}
}
`)
	writeModuleFile(t, root, ".env", "DB_HOST=localhost\n")
}

// analyzeUncachedRoot runs one root through the check pipeline without the
// cache, as a run with --no-cache does.
func analyzeUncachedRoot(t *testing.T, root string, list []rules.Rule) core.ViolationList {
	t.Helper()
	cfg := core.DefaultConfig()
	prepared, err := prepareAnalysis(core.NewGoProjectLoader(), root, cfg, list, false)
	require.NoError(t, err)
	require.Nil(t, prepared.cache)
	rootRules := append(rules.GetEnabled(cfg), list...)
	violations, panics, err := analyzeProjectContained(prepared.contexts, prepared.rootFiles, list, rootRules, cfg, prepared.project, nil)
	require.Empty(t, panics)
	require.NoError(t, err)
	return violations
}

// A project rule that reads files outside the typed load declares them in
// CacheInputs, and they key its cached findings: an edit of .env, or of the
// .gitignore that decides which env files are read, changes the cached run
// as it changes a run without the cache, while unchanged inputs reuse the
// findings without loading the project. Each run gets new rules, as each
// glint process does: the rule reads the env files once per process.
func TestProjectRuleCacheInputsKeyItsFindings(t *testing.T) {
	list := func() []rules.Rule { return []rules.Rule{qarules.NewTestExternalServiceRule()} }

	t.Run("env file edit", func(t *testing.T) {
		t.Setenv("GLINT_CACHE_DIR", t.TempDir())
		root := t.TempDir()
		writeLiveGateModule(t, root)

		_, first := analyzeCachedRoot(t, root, list())
		require.Empty(t, first, "no env file names the token: the gate is a real guard")
		second, reused := analyzeCachedRoot(t, root, list())
		assert.Nil(t, second.project, "unchanged inputs are not loaded")
		assert.Equal(t, "1 cached, 0 rerun", second.cache.projectState())
		assert.Empty(t, reused)

		writeModuleFile(t, root, ".env", "DB_HOST=localhost\nLIVE_VAULT_TOKEN=x\n")
		want := analyzeUncachedRoot(t, root, list())
		require.Len(t, want, 1, "the env file sets the token: the gate is open")
		third, got := analyzeCachedRoot(t, root, list())
		assert.Equal(t, fingerprint(want), fingerprint(got))
		assert.Equal(t, "0 cached, 1 rerun", third.cache.projectState())

		fourth, again := analyzeCachedRoot(t, root, list())
		assert.Nil(t, fourth.project, "the new env file is the input of the stored findings")
		assert.Equal(t, "1 cached, 0 rerun", fourth.cache.projectState())
		assert.Equal(t, fingerprint(want), fingerprint(again))
	})

	t.Run("gitignore edit", func(t *testing.T) {
		t.Setenv("GLINT_CACHE_DIR", t.TempDir())
		root := t.TempDir()
		writeLiveGateModule(t, root)
		writeModuleFile(t, root, "deploy/.env", "LIVE_VAULT_TOKEN=x\n")
		writeModuleFile(t, root, ".gitignore", "deploy/\n")

		_, first := analyzeCachedRoot(t, root, list())
		require.Empty(t, first, "the ignored directory is not read: no env file names the token")

		writeModuleFile(t, root, ".gitignore", "")
		want := analyzeUncachedRoot(t, root, list())
		require.Len(t, want, 1, "deploy/.env is read now and sets the token")
		_, got := analyzeCachedRoot(t, root, list())
		assert.Equal(t, fingerprint(want), fingerprint(got))
	})
}

// inputProjectRule is a project rule with inputs outside the typed load.
type inputProjectRule struct {
	*projectStubRule
	input string
	err   error
	roots []string
}

func (r *inputProjectRule) CacheInputs(root string) (string, error) {
	r.roots = append(r.roots, root)
	return r.input, r.err
}

// The inputs of a project rule are read for the project root, and a run that
// cannot read them neither reuses the rule's findings nor stores them for
// reuse: the next run, with its inputs back, analyzes the project again.
func TestProjectRuleWithoutItsInputsIsRerun(t *testing.T) {
	t.Setenv("GLINT_CACHE_DIR", t.TempDir())
	root := t.TempDir()
	writeModuleFile(t, root, "go.mod", "module example.com/check\n\ngo 1.24\n")
	writeModuleFile(t, root, "check.go", "package check\n\nfunc Value() int { return 1 }\n")
	rule := &inputProjectRule{projectStubRule: newProjectStubRule(), input: "first"}
	rule.findings = []*core.Violation{rule.CreateViolation("check.go", 3, "finding")}
	list := []rules.Rule{rule}

	analyzeCachedRoot(t, root, list)
	require.Equal(t, 1, rule.projectCalls)
	require.NotEmpty(t, rule.roots)
	assert.Equal(t, root, rule.roots[0], "the inputs are those of the project root")
	second, _ := analyzeCachedRoot(t, root, list)
	assert.Nil(t, second.project, "unchanged inputs reuse the findings")
	assert.Equal(t, 1, rule.projectCalls)

	rule.input = "second"
	analyzeCachedRoot(t, root, list)
	assert.Equal(t, 2, rule.projectCalls, "changed inputs rerun the rule")

	rule.err = errors.New("unreadable")
	failed, got := analyzeCachedRoot(t, root, list)
	assert.Equal(t, 3, rule.projectCalls, "unknown inputs rerun the rule")
	assert.Equal(t, "0 cached, 1 rerun", failed.cache.projectState())
	assert.Len(t, got, 1)
	failedAgain, _ := analyzeCachedRoot(t, root, list)
	assert.Equal(t, 4, rule.projectCalls, "two runs without the inputs share no key")
	assert.Equal(t, "0 cached, 1 rerun", failedAgain.cache.projectState())

	rule.err = nil
	analyzeCachedRoot(t, root, list)
	assert.Equal(t, 5, rule.projectCalls, "a run without the inputs stored nothing to reuse")
	analyzeCachedRoot(t, root, list)
	assert.Equal(t, 5, rule.projectCalls)
}

// The cache key asks for the env files of the root as the run names it, the
// analysis by the absolute root of the load: both get the same snapshot.
func TestEnvFilesAreReadOncePerRootHoweverItIsNamed(t *testing.T) {
	root := t.TempDir()
	writeModuleFile(t, root, ".env", "DB_HOST=localhost\n")
	t.Chdir(root)
	rule := qarules.NewTestExternalServiceRule()
	relative, err := rule.CacheInputs(".")
	require.NoError(t, err)
	writeModuleFile(t, root, ".env", "LIVE_VAULT_TOKEN=x\n")
	absolute, err := rule.CacheInputs(root)
	require.NoError(t, err)
	assert.Equal(t, relative, absolute)

	_, err = rule.CacheInputs(filepath.Join(root, "missing"))
	assert.Error(t, err, "env files that cannot be listed are no key")
}
