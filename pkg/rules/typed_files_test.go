package rules

import (
	"go/ast"
	"go/types"
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"golang.org/x/tools/go/packages"
)

func TestAnalyzeTypedRunFilesUsesReportScope(t *testing.T) {
	first := &core.FileContext{RelPath: "first.go", GoAST: &ast.File{}}
	second := &core.FileContext{RelPath: "second.go", GoAST: &ast.File{}}
	project := &core.GoProjectContext{Packages: []*core.GoPackageContext{{
		Package: &packages.Package{TypesInfo: &types.Info{}},
		Files:   []*core.FileContext{first, second},
	}}}
	project.SetReportFiles([]*core.FileContext{second})

	var visited []*core.FileContext
	_, err := AnalyzeTypedRunFiles(project, "test", func(file *core.FileContext, _ *types.Info) []*core.Violation {
		visited = append(visited, file)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(visited) != 1 || visited[0] != second {
		t.Fatalf("visited %v, want only second.go", visited)
	}

	visited = nil
	_, err = AnalyzeTypedFiles(project, "test", func(file *core.FileContext, _ *types.Info) []*core.Violation {
		visited = append(visited, file)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(visited) != 2 {
		t.Fatalf("AnalyzeTypedFiles visited %d files, want full project", len(visited))
	}
}
