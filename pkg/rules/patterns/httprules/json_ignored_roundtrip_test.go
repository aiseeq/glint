package httprules

import (
	"strings"
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/tools/go/packages"
)

func TestJSONIgnoredRoundTripProjectPrecheck(t *testing.T) {
	plain := rulestest.Project(t, map[string]string{"sample.go": `package sample
type Record struct { Name string }
`})
	assert.False(t, projectHasIgnoredJSONField(plain))
	rule := NewJSONIgnoredFieldLostInRoundTripRule()
	analysisCalled := false
	rule.projectAnalysis = func(*core.GoProjectContext) ([]*core.Violation, error) {
		analysisCalled = true
		return nil, nil
	}
	violations, err := rule.AnalyzeGoProject(plain)
	require.NoError(t, err)
	assert.Empty(t, violations)
	assert.False(t, analysisCalled, "ранний выход должен пропустить дорогой анализ")

	namedTag := rulestest.Project(t, map[string]string{"sample.go": "package sample\ntype Record struct { Hidden string `json:\"hidden\"` }\n"})
	assert.False(t, projectHasIgnoredJSONField(namedTag))

	testFiles := map[string]string{
		"sample.go":      "package sample\ntype Record struct { Name string }\n",
		"sample_test.go": "package sample\ntype fixture struct { Hidden string `json:\"-\"` }\n",
	}
	testRoot, testContexts := rulestest.Module(t, testFiles)
	ignoredTestOnly, err := core.LoadGoProject(testRoot, testContexts, core.GoProjectOptions{ListPackages: rulestest.ListPackages})
	require.NoError(t, err)
	loaded, err := packages.Load(&packages.Config{Mode: packages.LoadSyntax, Dir: testRoot, Fset: ignoredTestOnly.FileSet, Tests: true}, "./...")
	require.NoError(t, err)
	loadedTestSyntax := false
	for _, loadedPackage := range loaded {
		for _, file := range loadedPackage.Syntax {
			if strings.HasSuffix(loadedPackage.Fset.Position(file.Pos()).Filename, "_test.go") {
				loadedTestSyntax = true
				ignoredTestOnly.Packages = append(ignoredTestOnly.Packages, &core.GoPackageContext{Package: loadedPackage})
				break
			}
		}
	}
	require.True(t, loadedTestSyntax)
	assert.False(t, projectHasIgnoredJSONField(ignoredTestOnly))

	candidate := rulestest.Project(t, map[string]string{"sample.go": "package sample\ntype Record struct { Hidden string `json:\"-\"` }\n"})
	assert.True(t, projectHasIgnoredJSONField(candidate))
	candidate.FileSet = nil
	assert.True(t, projectHasIgnoredJSONField(candidate))
	analysisCalled = false
	violations, err = rule.AnalyzeGoProject(candidate)
	require.NoError(t, err)
	assert.Empty(t, violations)
	assert.True(t, analysisCalled, "без FileSet предпроверка обязана оставить проект кандидатом")
}
