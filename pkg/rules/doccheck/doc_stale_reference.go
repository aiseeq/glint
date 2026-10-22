package doccheck

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewDocStaleReferenceRule())
}

// DocStaleReferenceRule detects a comment that refers to `pkg.Name` of a module
// package that declares no such name:
//
//	// run hands the request to planner.Order before the reply.   // Order moved to build
//
// A type or function moved to another package, the code that used it was
// fixed by the compiler, and the comments kept the old package. A reader who
// follows the comment searches the old package and finds nothing.
//
// A lower-case name is reported only when another package of the module
// declares it — the name moved; otherwise it is as likely a quote of another
// language or a file of an archive. Methods and struct fields of the package's
// types and the declarations of its tests count as its names.
//
// Only packages of the module are checked, by their package name: a name of
// the file's own package, a package the file imports under that name, or the
// only module package with that name. A name two module packages share and the
// file does not import is left alone, so is anything outside the module
// (fmt.Sprintf), a file name (planner.go) and a path (dir/planner.Order).
// Code in backticks (`data.data?.id`) quotes source of any language and
// refers to a Go name only as pkg.Exported. A lower-case path the struct tags
// of the module spell out (lock.scope for a field tagged yaml:"lock" whose
// struct tags a field yaml:"scope") is a key of a config file or a payload,
// not a package. Test files keep fixtures and
// quotes of old output and are not checked.
type DocStaleReferenceRule struct {
	*rules.BaseRule
}

// NewDocStaleReferenceRule creates the rule
func NewDocStaleReferenceRule() *DocStaleReferenceRule {
	return &DocStaleReferenceRule{
		BaseRule: rules.NewBaseRule(
			"doc-stale-reference",
			"documentation",
			"Detects a comment reference pkg.Name to a module package that declares no such name — the name moved or was removed",
			core.SeverityMedium,
		),
	}
}

// AnalyzeFile is a no-op: a reference resolves against every package of the module.
func (r *DocStaleReferenceRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *DocStaleReferenceRule) RequiresSSA() bool { return false }

// staleRefPattern — a lower-case package name, a dot and an identifier (Go
// names are Unicode), not glued to a path or a longer selector on the left; the
// third group catches a lower-case continuation (a.b.c — a file or an attribute path).
var staleRefPattern = regexp.MustCompile(`(?:^|[^\p{L}\p{N}_./])([a-z][a-z0-9_]*)\.([\p{L}_][\p{L}\p{N}_]*)(\.\p{Ll})?`)

// fileExtensions — words after a dot that make a file name, not a reference.
var fileExtensions = map[string]bool{
	"go": true, "md": true, "txt": true, "sh": true, "py": true, "yaml": true, "yml": true, "json": true,
	"js": true, "ts": true, "cs": true, "log": true, "tsv": true, "csv": true, "toml": true, "mod": true,
	"sum": true, "proto": true, "pb": true, "gz": true, "html": true, "css": true, "png": true, "sql": true,
}

// modulePackages — names the module packages declare: by import path and by package name.
type modulePackages struct {
	byPath map[string]map[string]bool // import path → declared names
	byName map[string]map[string]bool // package name → import paths
	any    map[string]bool            // names declared anywhere in the module
	// external are the names of the packages outside the module that the
	// module imports (sql, http, decimal): a comment may mean either.
	external map[string]bool
	// keyPaths are the key paths the struct tags spell out: key → the keys
	// of the struct of the field tagged key.
	keyPaths map[string]map[string]bool
}

// keyPathTags are the tags naming the keys of a decoded document: a config
// file or a payload.
var keyPathTags = append([]string{"json", "xml"}, helpers.ConfigTags...)

func collectModulePackages(ctx *core.GoProjectContext) (*modulePackages, error) {
	m := &modulePackages{byPath: map[string]map[string]bool{}, byName: map[string]map[string]bool{}, any: map[string]bool{}, external: map[string]bool{}, keyPaths: map[string]map[string]bool{}}
	imported := map[string]string{} // import path → package name
	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil {
			return nil, errors.New("doc stale reference: package has no syntax")
		}
		p := pkg.Package
		if p.Types != nil {
			for _, imp := range p.Types.Imports() {
				imported[imp.Path()] = imp.Name()
			}
		}
		// a main package is never imported: main.X in a comment is prose
		if p.Types == nil || p.Name == "main" || strings.HasSuffix(p.Name, "_test") {
			continue
		}
		names := m.byPath[p.PkgPath]
		if names == nil {
			names = map[string]bool{}
			m.byPath[p.PkgPath] = names
		}
		addScopeNames(names, p.Types.Scope())
		m.addKeyPaths(p.Types.Scope())
		if len(p.GoFiles) > 0 {
			if err := addTestNames(names, filepath.Dir(p.GoFiles[0]), p.Name); err != nil {
				return nil, err
			}
		}
		for name := range names {
			m.any[name] = true
		}
		if m.byName[p.Name] == nil {
			m.byName[p.Name] = map[string]bool{}
		}
		m.byName[p.Name][p.PkgPath] = true
	}
	for path, name := range imported {
		if _, inModule := m.byPath[path]; !inModule {
			m.external[name] = true
		}
	}
	return m, nil
}

// addScopeNames — names of the package scope with the methods and struct
// fields of its types: a comment names Ctx.Run as pkg.Run as often as not.
func addScopeNames(names map[string]bool, scope *types.Scope) {
	for _, name := range scope.Names() {
		names[name] = true
		tn, ok := scope.Lookup(name).(*types.TypeName)
		if !ok {
			continue
		}
		if named, ok := tn.Type().(*types.Named); ok {
			for method := range named.Methods() {
				names[method.Name()] = true
			}
		}
		if st, ok := tn.Type().Underlying().(*types.Struct); ok {
			for field := range st.Fields() {
				names[field.Name()] = true
			}
		}
	}
}

// addKeyPaths records the key paths of the structs of the package scope: a
// field tagged key whose struct, behind pointers, slices and maps, tags its
// fields sub gives the path key.sub.
func (m *modulePackages) addKeyPaths(scope *types.Scope) {
	for _, name := range scope.Names() {
		tn, ok := scope.Lookup(name).(*types.TypeName)
		if !ok {
			continue
		}
		st, ok := tn.Type().Underlying().(*types.Struct)
		if !ok {
			continue
		}
		for i := range st.NumFields() {
			keys := helpers.TagKeys(reflect.StructTag(st.Tag(i)), keyPathTags)
			inner, ok := elemStruct(st.Field(i).Type())
			if len(keys) == 0 || !ok {
				continue
			}
			for j := range inner.NumFields() {
				for _, key := range keys {
					m.addKeyPath(key, helpers.TagKeys(reflect.StructTag(inner.Tag(j)), keyPathTags))
				}
			}
		}
	}
}

func (m *modulePackages) addKeyPath(key string, subs []string) {
	for _, sub := range subs {
		if m.keyPaths[key] == nil {
			m.keyPaths[key] = map[string]bool{}
		}
		m.keyPaths[key][sub] = true
	}
}

// elemStruct returns the struct a field of type t holds, behind pointers,
// slices, arrays and map values.
func elemStruct(t types.Type) (*types.Struct, bool) {
	for {
		switch u := t.Underlying().(type) {
		case *types.Pointer:
			t = u.Elem()
		case *types.Slice:
			t = u.Elem()
		case *types.Array:
			t = u.Elem()
		case *types.Map:
			t = u.Elem()
		case *types.Struct:
			return u, true
		default:
			return nil, false
		}
	}
}

// addTestNames — top-level names of the package's _test.go files. The typed
// packages carry no test files, and the project files hold only those under
// the checked root, while a comment names a test of any module package: the
// files are read from the package directory.
func addTestNames(names map[string]bool, dir, pkg string) error {
	paths, err := filepath.Glob(filepath.Join(dir, "*_test.go"))
	if err != nil {
		return fmt.Errorf("doc stale reference: %w", err)
	}
	fset := token.NewFileSet()
	for _, path := range paths {
		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return fmt.Errorf("doc stale reference: %w", err)
		}
		if file.Name.Name == pkg || file.Name.Name == pkg+"_test" {
			addDeclNames(names, file)
		}
	}
	return nil
}

// addDeclNames — top-level names of one _test.go file of the package, internal or external.
func addDeclNames(names map[string]bool, file *ast.File) {
	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			names[d.Name.Name] = true
		case *ast.GenDecl:
			for _, spec := range d.Specs {
				switch sp := spec.(type) {
				case *ast.TypeSpec:
					names[sp.Name.Name] = true
				case *ast.ValueSpec:
					for _, id := range sp.Names {
						names[id.Name] = true
					}
				}
			}
		}
	}
}

// stale — a reference pkg.name, resolved to the package at path, points
// nowhere: neither that package nor a namesake of it declares the name (the
// comment may mean the namesake). A lower-case name counts only when another
// package of the module declares it (the name moved): otherwise it is as
// likely a quote of another language (self.engine.execute) or a file of an
// archive (bundle.details).
func (m *modulePackages) stale(pkg, path, name string) bool {
	for other := range m.byName[pkg] {
		if m.byPath[other][name] {
			return false
		}
	}
	if m.byPath[path][name] {
		return false
	}
	first, _ := utf8.DecodeRuneInString(name)
	return !unicode.IsLower(first) || m.any[name]
}

// staleFamily — a reference pkg.Prefix*, resolved to the package at path,
// points nowhere: neither that package nor a namesake of it declares a name
// with the prefix.
func (m *modulePackages) staleFamily(pkg, path, prefix string) bool {
	paths := []string{path}
	for other := range m.byName[pkg] {
		paths = append(paths, other)
	}
	for _, p := range paths {
		for name := range m.byPath[p] {
			if strings.HasPrefix(name, prefix) {
				return false
			}
		}
	}
	return true
}

// AnalyzeGoProject checks the comments of every non-test file.
func (r *DocStaleReferenceRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, errors.New("doc stale reference: nil Go project context")
	}
	mod, err := collectModulePackages(ctx)
	if err != nil {
		return nil, err
	}

	var violations []*core.Violation
	seen := map[string]bool{}
	for _, pkg := range ctx.Packages {
		for _, fileCtx := range pkg.Files {
			if fileCtx.GoAST == nil || fileCtx.IsTestFile() || seen[fileCtx.RelPath] {
				continue
			}
			seen[fileCtx.RelPath] = true
			violations = append(violations, r.analyzeFile(fileCtx, pkg.Package.PkgPath, mod)...)
		}
	}

	sort.SliceStable(violations, func(i, j int) bool {
		if violations[i].File != violations[j].File {
			return violations[i].File < violations[j].File
		}
		return violations[i].Line < violations[j].Line
	})
	return violations, nil
}

func (r *DocStaleReferenceRule) analyzeFile(fileCtx *core.FileContext, ownPath string, mod *modulePackages) []*core.Violation {
	imports := fileImports(fileCtx.GoAST)
	own := fileCtx.GoAST.Name.Name
	var violations []*core.Violation
	for _, group := range fileCtx.GoAST.Comments {
		for _, c := range group.List {
			first := fileCtx.LineFor(c)
			for i, text := range strings.Split(c.Text, "\n") {
				for _, at := range staleRefPattern.FindAllStringSubmatchIndex(text, -1) {
					name, ident := text[at[2]:at[3]], text[at[4]:at[5]]
					lead, _ := utf8.DecodeRuneInString(ident)
					if fileExtensions[ident] || at[6] >= 0 && unicode.IsLower(lead) {
						continue
					}
					// Code in backticks quotes source, of any language: it
					// means a Go name only as pkg.Exported.
					if unicode.IsLower(lead) && strings.Count(text[:at[2]], "`")%2 == 1 {
						continue
					}
					if unicode.IsLower(lead) && mod.keyPaths[name][ident] {
						continue // a key path of a config file or a payload
					}
					path, ok := resolvePackage(name, own, ownPath, imports, mod)
					if !ok {
						continue
					}
					// pkg.Prefix* names a family of names by its prefix.
					family := at[5] < len(text) && text[at[5]] == '*'
					if family && !mod.staleFamily(name, path, ident) || !family && !mod.stale(name, path, ident) {
						continue
					}
					if family {
						ident += "*"
					}
					violations = append(violations, r.report(fileCtx, first+i, name, ident))
				}
			}
		}
	}
	return violations
}

// resolvePackage — the module package a comment means by name: an import of
// the file under that name (package http importing net/http means net/http
// by http.Cookie), else nothing when a package outside the module that the
// project imports has the name (the comment may mean it, under an alias too),
// else the file's own package or the only module package with the name
// the file could import.
func resolvePackage(name, own, ownPath string, imports map[string]string, mod *modulePackages) (string, bool) {
	if path, ok := imports[name]; ok {
		_, inModule := mod.byPath[path]
		return path, inModule
	}
	if mod.external[name] {
		return "", false
	}
	if name == own {
		_, checked := mod.byPath[ownPath] // a main package is not checked
		return ownPath, checked
	}
	found, visible := "", 0
	for path := range mod.byName[name] {
		if importable(ownPath, path) {
			found = path
			visible++
		}
	}
	return found, visible == 1
}

// importable reports whether the package at from may import the package at
// path: a package under an internal directory is visible only to the tree
// rooted at that directory's parent.
func importable(from, path string) bool {
	at := strings.LastIndex("/"+path+"/", "/internal/")
	if at < 0 {
		return true
	}
	parent := strings.TrimSuffix(path[:at], "/")
	return parent == "" || from == parent || strings.HasPrefix(from, parent+"/")
}

// fileImports — local name → import path of the file's imports.
func fileImports(file *ast.File) map[string]string {
	out := map[string]string{}
	for _, spec := range file.Imports {
		path := strings.Trim(spec.Path.Value, "\"`") // the parser keeps the literal quoted
		name := path[strings.LastIndex(path, "/")+1:]
		if spec.Name != nil {
			name = spec.Name.Name
		}
		out[name] = path
	}
	return out
}

func (r *DocStaleReferenceRule) report(fileCtx *core.FileContext, line int, pkg, ident string) *core.Violation {
	v := r.CreateViolation(fileCtx.RelPath, line,
		fmt.Sprintf("Comment refers to %s.%s, but package %s declares no %s — the name moved or was removed", pkg, ident, pkg, ident))
	v.WithCode(strings.TrimSpace(fileCtx.GetLine(line)))
	v.WithSuggestion(fmt.Sprintf("Point the comment at where %s lives now, or drop the reference", ident))
	v.WithContext("pattern", "doc_stale_reference")
	return v
}
