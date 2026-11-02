package rules

import (
	"go/ast"
	"go/types"
	"strings"
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

func TestAnalyzeRunFilesValidatesFindingFile(t *testing.T) {
	for _, scoped := range []bool{false, true} {
		testRunFilesFindingFileContract(t, scoped)
	}
}

// testRunFilesFindingFileContract makes the callback of first.go return a
// finding of second.go, with first.go as the report scope or without one.
func testRunFilesFindingFileContract(t *testing.T, scoped bool) {
	t.Helper()
	first := &core.FileContext{RelPath: "first.go", GoAST: &ast.File{}}
	second := &core.FileContext{RelPath: "second.go", GoAST: &ast.File{}}
	project := &core.GoProjectContext{Packages: []*core.GoPackageContext{{
		Package: &packages.Package{TypesInfo: &types.Info{}}, Files: []*core.FileContext{first, second},
	}}}
	if scoped {
		project.SetReportFiles([]*core.FileContext{first})
	}
	for _, run := range []struct {
		name string
		call func() ([]*core.Violation, error)
	}{
		{name: "typed", call: func() ([]*core.Violation, error) {
			return AnalyzeTypedRunFiles(project, "synthetic", func(file *core.FileContext, _ *types.Info) []*core.Violation {
				if file == first {
					return []*core.Violation{{File: second.RelPath}}
				}
				return nil
			})
		}},
		{name: "go", call: func() ([]*core.Violation, error) {
			return AnalyzeGoRunFiles(project, "synthetic", func(file *core.FileContext, _ *types.Info) []*core.Violation {
				if file == first {
					return []*core.Violation{{File: second.RelPath}}
				}
				return nil
			})
		}},
	} {
		_, err := run.call()
		if err == nil || !strings.Contains(err.Error(), "returned a finding for") {
			t.Fatalf("%s, scoped %v: expected callback contract error, got %v", run.name, scoped, err)
		}
	}
}

func TestAnalyzeRunFilesWithoutReportScopeVisitsWholeProject(t *testing.T) {
	first := &core.FileContext{RelPath: "first.go", GoAST: &ast.File{}}
	second := &core.FileContext{RelPath: "second.go", GoAST: &ast.File{}}
	project := &core.GoProjectContext{Packages: []*core.GoPackageContext{{
		Package: &packages.Package{TypesInfo: &types.Info{}}, Files: []*core.FileContext{first, second},
	}}}
	var visited int
	_, err := AnalyzeTypedRunFiles(project, "synthetic", func(*core.FileContext, *types.Info) []*core.Violation { visited++; return nil })
	if err != nil {
		t.Fatal(err)
	}
	if visited != 2 {
		t.Fatalf("visited %d files, want 2", visited)
	}
}
