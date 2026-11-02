package patternkit

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/require"
)

func TestSetReportFilesDoesNotChangeFunctionDeclarationIndex(t *testing.T) {
	project := rulestest.Project(t, map[string]string{
		"a.go": "package sample\nfunc First() { Second() }\n",
		"b.go": "package sample\nfunc Second() {}\n",
	})
	before, err := FuncDeclsByObject(project)
	require.NoError(t, err)
	require.Len(t, before, 2)
	project.SetReportFiles([]*core.FileContext{project.Files[0]})
	scoped, err := FuncDeclsByObject(project)
	require.NoError(t, err)
	require.Equal(t, before, scoped)
	project.SetReportFiles([]*core.FileContext{})
	empty, err := FuncDeclsByObject(project)
	require.NoError(t, err)
	require.Equal(t, before, empty)
}
