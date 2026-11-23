package patternkit

import (
	"go/types"
	"path/filepath"
	"testing"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/require"
)

func TestCollectCallSitesOrder(t *testing.T) {
	project := rulestest.Project(t, map[string]string{
		"z.go":      "package sample\nfunc Zed() { target(); target() }\n",
		"a.go":      "package sample\nfunc Able() { target() }\n",
		"target.go": "package sample\nfunc target() {}\n",
	})
	decls, err := FuncDeclsByObject(project)
	require.NoError(t, err)
	var target *types.Func
	for fn := range decls {
		if fn.Name() == "target" {
			target = fn
			break
		}
	}
	require.NotNil(t, target)

	for range 20 {
		sites := CollectCallSites(decls)[target.Origin()]
		require.Len(t, sites, 3)
		got := make([]string, len(sites))
		for i, site := range sites {
			pos := project.FileSet.Position(site.Call.Pos())
			got[i] = filepath.Base(pos.Filename) + ":" + site.Caller.Decl.Name.Name
		}
		require.Equal(t, []string{"a.go:Able", "z.go:Zed", "z.go:Zed"}, got)
	}
}
