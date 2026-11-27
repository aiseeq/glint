//go:build !race

package main

import (
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/patterns/frontendrules"
)

// These tests inspect cache fingerprints and input keys directly; they do not
// analyze files or start Walker or statelessRun workers in the test process.

func TestRootProjectRuleCacheFingerprintIncludesConfig(t *testing.T) {
	root := []*core.FileContext{goContext(t, "a.go", "package a\n")}
	rule := newIndexedFindingRule()
	first := &resultCache{build: "build", root: "/project", rootRuleFindings: make(map[string]map[string][]core.Violation), subsetPrevious: make(map[string]rootSubsetEntry)}
	first.configFingerprint = "config-one"
	first.keyRootFiles(root, map[string][sha256.Size]byte{"a.go": sha256.Sum256(root[0].Content)}, []rules.Rule{rule})
	second := &resultCache{build: "build", root: "/project", rootRuleFindings: make(map[string]map[string][]core.Violation), subsetPrevious: make(map[string]rootSubsetEntry)}
	second.configFingerprint = "config-two"
	second.keyRootFiles(root, map[string][sha256.Size]byte{"a.go": sha256.Sum256(root[0].Content)}, []rules.Rule{rule})
	assert.NotEqual(t, first.rootRuleFingerprints[rule.Name()], second.rootRuleFingerprints[rule.Name()])
}

func TestRootIndexCacheIgnoresUnrelatedGoEdit(t *testing.T) {
	dir := t.TempDir()
	cfg := core.DefaultConfig()
	rule := frontendrules.NewTSDerivedFieldRecomputedRule()
	list := []rules.Rule{rule}
	files := func(goCode, tsCode string) []*core.FileContext {
		return []*core.FileContext{
			goContext(t, "a.go", goCode),
			core.NewFileContext("/project/b.ts", "/project", []byte(tsCode), cfg),
		}
	}
	open := func(inputs string, contexts []*core.FileContext) *resultCache {
		cache, err := openResultCache(dir, "/project", "", "build", "stamp")
		require.NoError(t, err)
		cache.keyProject("", inputs, nil, list, "")
		keyRootFileCache(cache, contexts, append(rules.GetEnabled(cfg), rule), cfg, true)
		return cache
	}
	original := files("package a\n", "export type T = { status: string; statusGroup: string }\n")
	first := open("go-before", original)
	first.storeRootProjectResults(map[string]core.ViolationList{rule.Name(): nil})
	require.NoError(t, first.save())
	editedGo := open("go-after", files("package a // edited\n", "export type T = { status: string; statusGroup: string }\n"))
	require.True(t, editedGo.rootRuleReusable(rule), "Go input is not read by the TypeScript index or its file analysis")
	editedTS := open("go-after", files("package a // edited\n", "export type T = { status: string }\n"))
	require.False(t, editedTS.rootRuleReusable(rule), "TypeScript changes invalidate the index")
}
