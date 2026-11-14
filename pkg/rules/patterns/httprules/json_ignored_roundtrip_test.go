package httprules

import (
	"go/types"
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

// fieldOwnerByScope is the owner of a field searched through the sorted
// scope of its package, one search per field: the path fieldOwners replaces.
// Alias, Base and Copy share one struct, and the first name, Alias, owns it.
func fieldOwnerByScope(v *types.Var) *types.TypeName {
	if v.Pkg() == nil {
		return nil
	}
	scope := v.Pkg().Scope()
	for _, name := range scope.Names() {
		tn, ok := scope.Lookup(name).(*types.TypeName)
		if !ok {
			continue
		}
		st, ok := tn.Type().Underlying().(*types.Struct)
		if !ok {
			continue
		}
		for field := range st.Fields() {
			if field == v {
				return tn
			}
		}
	}
	return nil
}

func TestJSONRoundTripFieldOwnerMatchesScopeSearch(t *testing.T) {
	project := rulestest.Project(t, map[string]string{
		"model/model.go": `package model
type Base struct { ID string; Hidden string ` + "`json:\"-\"`" + ` }
type Copy Base
type Alias = Base
type Wrapper struct { Base; Extra int; Inner struct { Deep int } }
type Box[T any] struct { Value T }
type Ints []int
`,
		"use/use.go": `package use
import "example.com/rulestest/model"
type Zed struct { Name string }
func Fill() int {
	b := model.Box[int]{Value: 1}
	c := model.Copy{ID: "x"}
	w := model.Wrapper{Extra: 2}
	w.Inner.Deep = 3
	type local struct { L int }
	l := local{L: 4}
	z := Zed{Name: "z"}
	a := model.Alias{Hidden: "h"}
	return b.Value + len(c.ID) + w.Extra + l.L + len(z.Name) + len(a.Hidden) + len(w.ID)
}
`,
	})
	trip := jsonRoundTrip{owners: map[*types.Package]map[*types.Var]*types.TypeName{}}
	checked := map[string]bool{}
	for _, pkg := range project.Packages {
		info := pkg.Package.TypesInfo
		visit := func(v *types.Var) {
			if !v.IsField() {
				return
			}
			want := fieldOwnerByScope(v)
			assert.Equal(t, want, trip.owner(v), "owner of %s", v)
			owner := "<nil>"
			if want != nil {
				owner = want.Name()
			}
			checked[v.Name()+" in "+owner] = true
		}
		for _, obj := range info.Defs {
			if v, ok := obj.(*types.Var); ok {
				visit(v)
			}
		}
		for _, selection := range info.Selections {
			if v, ok := selection.Obj().(*types.Var); ok {
				visit(v)
			}
		}
	}
	for _, want := range []string{"ID in Alias", "Hidden in Alias", "Extra in Wrapper", "Deep in <nil>", "L in <nil>", "Name in Zed", "Value in <nil>", "Value in Box"} {
		assert.True(t, checked[want], "the fixture covers %s, got %v", want, checked)
	}
}
