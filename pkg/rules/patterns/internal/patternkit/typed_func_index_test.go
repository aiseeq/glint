package patternkit

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/stretchr/testify/require"
	"golang.org/x/tools/go/packages"
)

type indexedSource struct {
	name string
	code string
}

func TestCollectCallSitesOrder(t *testing.T) {
	sources := []indexedSource{
		{name: "z.go", code: "package sample\nfunc Zed() { target(); target() }\n"},
		{name: "a.go", code: "package sample\nfunc Able() { target() }; func Baker() { target() }\n"},
		{name: "target.go", code: "package sample\nfunc target() {}\n"},
	}
	fset, files, info, pkg := typecheckIndexedSources(t, sources)
	project := &core.GoProjectContext{
		FileSet: fset,
		Packages: []*core.GoPackageContext{{Package: &packages.Package{
			Types: pkg, TypesInfo: info, Syntax: files, Fset: fset,
		}}},
	}
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
		require.Len(t, sites, 4)
		got := make([]string, len(sites))
		for i, site := range sites {
			pos := fset.Position(site.Call.Pos())
			got[i] = filepath.Base(pos.Filename) + ":" + site.Caller.Decl.Name.Name
		}
		require.Equal(t, []string{"a.go:Able", "a.go:Baker", "z.go:Zed", "z.go:Zed"}, got)
	}
}

func typecheckIndexedSources(tb testing.TB, sources []indexedSource) (*token.FileSet, []*ast.File, *types.Info, *types.Package) {
	tb.Helper()
	fset := token.NewFileSet()
	files := make([]*ast.File, 0, len(sources))
	for _, source := range sources {
		file, err := parser.ParseFile(fset, source.name, source.code, parser.AllErrors)
		if err != nil {
			tb.Fatal(err)
		}
		files = append(files, file)
	}
	info := &types.Info{
		Types: make(map[ast.Expr]types.TypeAndValue), Defs: make(map[*ast.Ident]types.Object),
		Uses: make(map[*ast.Ident]types.Object), Selections: make(map[*ast.SelectorExpr]*types.Selection),
		Scopes: make(map[ast.Node]*types.Scope),
	}
	pkg, err := new(types.Config).Check("example.com/sample", fset, files, info)
	if err != nil {
		tb.Fatal(err)
	}
	return fset, files, info, pkg
}

func BenchmarkCollectCallSitesLargeProject(b *testing.B) {
	const filesCount, functionsPerFile, callsPerFunction = 96, 100, 5
	sources := make([]indexedSource, 0, filesCount+1)
	for file := range filesCount {
		var source strings.Builder
		fmt.Fprintln(&source, "package large")
		for fn := range functionsPerFile {
			fmt.Fprintf(&source, "func Caller%03d_%03d() {", file, fn)
			for range callsPerFunction {
				source.WriteString("target();")
			}
			source.WriteString("}\n")
		}
		sources = append(sources, indexedSource{name: fmt.Sprintf("src/%03d.go", file), code: source.String()})
	}
	sources = append(sources, indexedSource{name: "target.go", code: "package large\nfunc target() {}\n"})
	fset, files, info, _ := typecheckIndexedSources(b, sources)
	decls := make(map[*types.Func]TypedFuncDecl)
	for _, file := range files {
		for _, declaration := range file.Decls {
			fn, ok := declaration.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			if obj, ok := info.Defs[fn.Name].(*types.Func); ok {
				decls[obj] = TypedFuncDecl{Decl: fn, Info: info, FileSet: fset}
			}
		}
	}
	b.ResetTimer()
	b.ReportMetric(float64(len(decls)), "decls/op")
	b.ReportMetric(float64(filesCount*functionsPerFile*callsPerFunction), "calls/op")
	for range b.N {
		_ = CollectCallSites(decls)
	}
}
