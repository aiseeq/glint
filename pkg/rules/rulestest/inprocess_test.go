package rulestest

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/tools/go/gcexportdata"
	"golang.org/x/tools/go/packages"
)

// inProcessModule has what the rule tests use: two packages, one importing
// the other, the standard library, generics, and a third-party package
// replaced by a stub module inside the module.
var inProcessModule = map[string]string{
	"go.mod":                         "module example.com/rulestest\n\ngo 1.24\n\nrequire github.com/shopspring/decimal v1.0.0\n\nreplace github.com/shopspring/decimal => ./third_party/decimal\n",
	"third_party/decimal/go.mod":     "module github.com/shopspring/decimal\n\ngo 1.24\n",
	"third_party/decimal/decimal.go": "package decimal\n\ntype Decimal struct{ v int64 }\n\nfunc New(v int64) Decimal { return Decimal{v} }\n\nfunc (d Decimal) Add(o Decimal) Decimal { return Decimal{d.v + o.v} }\n",
	"store/store.go": `package store

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"slices"

	"github.com/shopspring/decimal"
)

type Repo[T any] struct{ db *sql.DB; rows []T }

func (r *Repo[T]) Sorted(less func(a, b T) int) []T {
	out := slices.Clone(r.rows)
	slices.SortFunc(out, less)
	return out
}

func Total(ctx context.Context, w http.ResponseWriter, xs []decimal.Decimal) error {
	sum := decimal.New(0)
	for _, x := range xs {
		sum = sum.Add(x)
	}
	_, err := fmt.Fprintf(w, "%v", sum)
	return err
}
`,
	"api/api.go": `package api

import (
	"net/http"

	"example.com/rulestest/store"
)

type Item struct{ ID int }

func Handle(w http.ResponseWriter, r *http.Request) {
	var repo store.Repo[Item]
	_ = repo.Sorted(func(a, b Item) int { return a.ID - b.ID })
	_ = store.Total(r.Context(), w, nil)
}
`,
}

// loadBoth loads a module with packages.Load and in process, each into its
// own file set, the way core does.
func loadBoth(t *testing.T, files map[string]string) (real, fast []*packages.Package, realSet, fastSet *token.FileSet) {
	t.Helper()
	root, _ := Module(t, files)
	cfg := func(fset *token.FileSet) *packages.Config {
		return &packages.Config{
			Mode: packages.LoadSyntax | packages.NeedModule,
			Dir:  root,
			Fset: fset,
			ParseFile: func(fset *token.FileSet, filename string, src []byte) (*ast.File, error) {
				return parser.ParseFile(fset, filename, src, parser.ParseComments|parser.SkipObjectResolution)
			},
		}
	}
	realSet, fastSet = token.NewFileSet(), token.NewFileSet()
	var err error
	real, err = packages.Load(cfg(realSet), "./...")
	require.NoError(t, err)
	fast, err = loadInProcess(cfg(fastSet), []string{"./..."})
	require.NoError(t, err, "the module is one the in-process load mirrors")
	byPath := func(pkgs []*packages.Package) {
		sort.Slice(pkgs, func(i, j int) bool { return pkgs[i].PkgPath < pkgs[j].PkgPath })
	}
	byPath(real)
	byPath(fast)
	return real, fast, realSet, fastSet
}

func TestInProcessLoadMatchesPackagesLoad(t *testing.T) {
	real, fast, realSet, fastSet := loadBoth(t, inProcessModule)
	require.Len(t, fast, len(real))
	for i := range real {
		r, f := real[i], fast[i]
		require.Empty(t, r.Errors, "packages.Load: %v", r.Errors)
		assert.Equal(t, r.ID, f.ID)
		assert.Equal(t, r.Name, f.Name)
		assert.Equal(t, r.PkgPath, f.PkgPath)
		assert.Equal(t, r.GoFiles, f.GoFiles)
		assert.Equal(t, r.CompiledGoFiles, f.CompiledGoFiles)
		assert.Equal(t, r.Module.Path, f.Module.Path)
		assert.Equal(t, r.Module.Dir, f.Module.Dir)
		assert.Equal(t, r.Module.GoVersion, f.Module.GoVersion)
		assert.Equal(t, r.Module.Main, f.Module.Main)
		assert.Equal(t, sortedKeys(r.Imports), sortedKeys(f.Imports))
		for path, dep := range r.Imports {
			assert.Equal(t, dep.PkgPath, f.Imports[path].PkgPath)
			assert.Equal(t, dep.Name, f.Imports[path].Name)
			assert.Equal(t, dep.Module != nil, f.Imports[path].Module != nil, "module of %s", path)
		}
		assert.Equal(t, r.TypesSizes, f.TypesSizes)
		assert.Equal(t, typedIdents(r, realSet), typedIdents(f, fastSet), "types of %s", r.PkgPath)
	}
}

// typedIdents describes every identifier the type checker resolved: where it
// is, what it denotes, of what type, declared where. Positions of standard
// library objects come from export data, so they show the file and line the
// two loads read.
func typedIdents(pkg *packages.Package, fset *token.FileSet) []string {
	var out []string
	describe := func(kind string, ident *ast.Ident, obj types.Object) {
		if obj == nil {
			return
		}
		decl := fset.Position(obj.Pos())
		out = append(out, fmt.Sprintf("%s %s %s %T %s %s:%d", kind, fset.Position(ident.Pos()), ident.Name, obj, obj.Type(), filepath.Base(decl.Filename), decl.Line))
	}
	for ident, obj := range pkg.TypesInfo.Defs {
		describe("def", ident, obj)
	}
	for ident, obj := range pkg.TypesInfo.Uses {
		describe("use", ident, obj)
	}
	for expr, tv := range pkg.TypesInfo.Types {
		out = append(out, fmt.Sprintf("expr %s %s %v", fset.Position(expr.Pos()), tv.Type, tv.Value))
	}
	out = append(out, fmt.Sprintf("selections %d instances %d implicits %d scopes %d", len(pkg.TypesInfo.Selections), len(pkg.TypesInfo.Instances), len(pkg.TypesInfo.Implicits), len(pkg.TypesInfo.Scopes)))
	slices.Sort(out)
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// A module the in-process load does not mirror goes to packages.Load.
func TestInProcessLoadLeavesUnusualModulesToPackagesLoad(t *testing.T) {
	plain := "package p\n\nfunc F() int { return 1 }\n"
	cases := map[string]map[string]string{
		"build constraint":       {"p/p.go": "//go:build linux\n\n" + plain},
		"type error":             {"p/p.go": "package p\n\nfunc F() int { return \"one\" }\n"},
		"parse error":            {"p/p.go": "package p\n\nfunc F( {\n"},
		"cgo":                    {"p/p.go": "package p\n\nimport \"C\"\n\nfunc F() {}\n"},
		"import outside":         {"p/p.go": "package p\n\nimport \"github.com/google/uuid\"\n\nvar _ = uuid.New\n"},
		"nested module":          {"p/p.go": plain, "q/go.mod": "module example.com/q\n\ngo 1.24\n", "q/q.go": plain},
		"requirement unreplaced": {"go.mod": "module example.com/rulestest\n\ngo 1.24\n\nrequire github.com/google/uuid v1.6.0\n", "p/p.go": plain},
		"toolchain":              {"go.mod": "module example.com/rulestest\n\ngo 1.24\n\ntoolchain go1.24.1\n", "p/p.go": plain},
		"test files alone":       {"p/p_test.go": "package p\n"},
		"go files in vendor":     {"p/p.go": plain, "vendor/v/v.go": plain},
		"go files in testdata":   {"p/p.go": plain, "p/testdata/t.go": plain},
	}
	for name, files := range cases {
		t.Run(name, func(t *testing.T) {
			root, _ := Module(t, files)
			fset := token.NewFileSet()
			cfg := &packages.Config{
				Mode: packages.LoadSyntax | packages.NeedModule, Dir: root, Fset: fset,
				ParseFile: func(fset *token.FileSet, filename string, src []byte) (*ast.File, error) {
					return parser.ParseFile(fset, filename, src, parser.ParseComments)
				},
			}
			_, err := loadInProcess(cfg, []string{"./..."})
			require.ErrorIs(t, err, errNotMirrored)
		})
	}
}

// From Go 1.28 go list -export writes the export data of cmd/export, with no
// compiler archive around it: the loader reads such a file directly, as
// well as the archives of the toolchains before.
func TestInProcessLoadReadsExportDataWithoutArchive(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "p.go", "package p\n\nfunc Answer() int { return 42 }\n", 0)
	require.NoError(t, err)
	pkg, err := new(types.Config).Check("example.com/p", fset, []*ast.File{file}, nil)
	require.NoError(t, err)
	exportFile := filepath.Join(t.TempDir(), "p.export")
	out, err := os.Create(exportFile)
	require.NoError(t, err)
	require.NoError(t, gcexportdata.Write(out, fset, pkg))
	require.NoError(t, out.Close())

	l := &inProcessLoad{cfg: &packages.Config{Fset: token.NewFileSet()}, imports: map[string]*types.Package{}}
	typed, err := l.readExport(exportFile, "example.com/p")
	require.NoError(t, err)
	assert.NotNil(t, typed.Scope().Lookup("Answer"))
}
