package main

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/deadcode"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTicketReviewScopesAndYAML(t *testing.T) {
	root := t.TempDir()
	home := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", home)
	dir := filepath.Join(home, "tickets")
	require.NoError(t, os.MkdirAll(dir, 0755))
	require.NoError(t, os.MkdirAll(filepath.Join(home, "glint"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(home, "glint", "config.yaml"), []byte("tickets_dir: "+dir+"\n"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "20260101-0100-HIGH-sample.md"), []byte("Статус: отклонён\n"), 0644))
	writeModuleFile(t, root, "go.mod", "module example.org/test\n\ngo 1.24\n")
	writeModuleFile(t, root, ".glint.yaml", `settings:
  exclude: ["excluded/**"]
categories:
  deadcode:
    rules:
      never-assigned-func-var:
        exceptions:
          - file: a.go
            reason: glint#sample
          - files: "**/*.go"
            reason: glint#sample
          - file: b.go
            reason: glint#sample
          - function: Global
            reason: glint#sample
`)
	writeModuleFile(t, root, "a.go", "package example\n")
	writeModuleFile(t, root, "b.go", "package example\n")
	writeModuleFile(t, root, "nested/c.go", "package nested\n")
	writeModuleFile(t, root, "extra/action.yaml", "# never-assigned-func-var: safe — glint#sample\n#nolint:never-assigned-func-var // glint#sample\n")
	writeModuleFile(t, root, ".gitignore", "ignored/\n")
	writeModuleFile(t, root, "ignored/action.yaml", "#nolint:never-assigned-func-var // glint#sample\n")
	writeModuleFile(t, root, "excluded/action.yaml", "#nolint:never-assigned-func-var // glint#sample\n")
	writeModuleFile(t, root, "vendor/action.yaml", "#nolint:never-assigned-func-var // glint#sample\n")
	withFlags(t, "", "exception-ticket-closed")
	run := func(paths ...string) core.ViolationList {
		t.Helper()
		roots, err := analysisRoots(paths)
		require.NoError(t, err)
		require.Len(t, roots, 1)
		scope := roots[0]
		cfg, enabled, err := loadConfig(scope.dir)
		require.NoError(t, err)
		prepared, err := prepareScopedAnalysis(core.NewGoProjectLoader(), scope, cfg, enabled, false)
		require.NoError(t, err)
		found, err := closedTicketSuppressions(enabled, deadcode.StaleSuppressionRun{Contexts: append(slices.Clone(prepared.contexts), prepared.ticketFiles...), Config: cfg, WholeRoot: scope.wholeRoot(), Scopes: scope.walkScopes()})
		require.NoError(t, err)
		return found
	}
	full := run(root)
	var yamlLines []int
	for _, v := range full {
		if v.File == "extra/action.yaml" {
			yamlLines = append(yamlLines, v.Line)
		}
		require.NotContains(t, v.File, "ignored/")
		require.NotContains(t, v.File, "excluded/")
		require.NotContains(t, v.File, "vendor/")
	}
	assert.Equal(t, []int{1, 2}, yamlLines)
	onlyA := run(filepath.Join(root, "a.go"))
	var configLines []int
	for _, v := range onlyA {
		if v.File == ".glint.yaml" {
			configLines = append(configLines, v.Line)
		}
	}
	require.Equal(t, []int{8, 10, 14}, configLines)
	onlyNested := run(filepath.Join(root, "nested"))
	var nestedLines []int
	for _, v := range onlyNested {
		if v.File == ".glint.yaml" {
			nestedLines = append(nestedLines, v.Line)
		}
	}
	require.Equal(t, []int{10, 14}, nestedLines)
	onlyYAML := run(filepath.Join(root, "extra/action.yaml"))
	var scopedYAML []int
	for _, v := range onlyYAML {
		if v.File == "extra/action.yaml" {
			scopedYAML = append(scopedYAML, v.Line)
		}
	}
	require.Equal(t, []int{1, 2}, scopedYAML)
}

// A YAML file read only for exception-ticket-closed can hide that rule's
// finding with a bare marker; suppression-without-reason must report it there.
func TestTicketYAMLMarkerWithoutReasonIsReported(t *testing.T) {
	root := t.TempDir()
	home := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", home)
	dir := filepath.Join(home, "tickets")
	require.NoError(t, os.MkdirAll(dir, 0755))
	require.NoError(t, os.MkdirAll(filepath.Join(home, "glint"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(home, "glint", "config.yaml"), []byte("tickets_dir: "+dir+"\n"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "20260101-0100-HIGH-sample.md"), []byte("Статус: отклонён\n"), 0644))
	writeModuleFile(t, root, "go.mod", "module example.org/test\n\ngo 1.24\n")
	writeModuleFile(t, root, ".glint.yaml", "version: 1\n")
	writeModuleFile(t, root, "settings.yaml", "#nolint:exception-ticket-closed\n#nolint:never-assigned-func-var -- glint#sample\n#nolint:never-assigned-func-var\n")
	writeModuleFile(t, root, "reasoned.yaml", "#nolint:exception-ticket-closed -- ticket review pending\n#nolint:never-assigned-func-var -- glint#sample\n")
	withFlags(t, "", "exception-ticket-closed", "suppression-without-reason")
	roots, err := analysisRoots([]string{root})
	require.NoError(t, err)
	scope := roots[0]
	cfg, enabled, err := loadConfig(scope.dir)
	require.NoError(t, err)
	prepared, err := prepareScopedAnalysis(core.NewGoProjectLoader(), scope, cfg, enabled, false)
	require.NoError(t, err)
	var found []string
	for _, v := range ticketFileSuppressionsWithoutReason(enabled, cfg, prepared.ticketFiles) {
		found = append(found, v.File+":"+strconv.Itoa(v.Line)+":"+v.Rule)
	}
	assert.Equal(t, []string{"settings.yaml:1:suppression-without-reason"}, found)
}
