package patterns

import (
	"fmt"
	"go/ast"
	"go/types"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
)

// templateEnumParam is a template function whose argument at index is
// converted to a string enum type.
type templateEnumParam struct {
	index  int
	named  *types.Named
	values map[string]bool
	// file and line are where the FuncMap entry is: a finding in a template,
	// which the analysis does not list, is reported there.
	file *core.FileContext
	line int
}

// templateEnumFuncs returns the FuncMap entries of the project that convert
// one of their string parameters to a string enum type:
//
//	"hasPerm": func(role, perm string) bool { return HasPermission(Role(role), Permission(perm)) }
func templateEnumFuncs(ctx *core.GoProjectContext, enums enumIndex) map[string][]templateEnumParam {
	funcs := make(map[string][]templateEnumParam)
	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil || pkg.Package.TypesInfo == nil {
			continue
		}
		info := pkg.Package.TypesInfo
		for _, file := range pkg.Files {
			if file == nil || file.GoAST == nil {
				continue
			}
			ast.Inspect(file.GoAST, func(n ast.Node) bool {
				lit, ok := n.(*ast.CompositeLit)
				if !ok || !isFuncMapType(info.TypeOf(lit)) {
					return true
				}
				for _, elt := range lit.Elts {
					kv, ok := elt.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					key, ok := stringLiteral(kv.Key)
					fn, isLit := kv.Value.(*ast.FuncLit)
					if !ok || !isLit {
						continue
					}
					for _, param := range enumConvertedParams(fn, info, enums) {
						param.file, param.line = file, file.LineFor(kv)
						funcs[key] = append(funcs[key], param)
					}
				}
				return true
			})
		}
	}
	return funcs
}

// isFuncMapType reports template.FuncMap of text/template or html/template.
func isFuncMapType(t types.Type) bool {
	named, ok := types.Unalias(t).(*types.Named)
	if !ok || named.Obj().Pkg() == nil || named.Obj().Name() != "FuncMap" {
		return false
	}
	path := named.Obj().Pkg().Path()
	return path == "html/template" || path == "text/template"
}

// enumConvertedParams returns the parameters of a function literal that its
// body converts to a string enum type of the project.
func enumConvertedParams(fn *ast.FuncLit, info *types.Info, enums enumIndex) []templateEnumParam {
	params := make(map[types.Object]int)
	index := 0
	for _, field := range fn.Type.Params.List {
		for _, name := range field.Names {
			if obj := info.Defs[name]; obj != nil {
				params[obj] = index
			}
			index++
		}
	}
	var out []templateEnumParam
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 1 {
			return true
		}
		tv, ok := info.Types[call.Fun]
		id, isIdent := ast.Unparen(call.Args[0]).(*ast.Ident)
		if !ok || !tv.IsType() || !isIdent {
			return true
		}
		at, isParam := params[info.Uses[id]]
		if !isParam {
			return true
		}
		converted, isNamed := types.Unalias(tv.Type).(*types.Named)
		if !isNamed {
			return true
		}
		if named, values := enums.enumValues(converted); named != nil {
			out = append(out, templateEnumParam{index: at, named: named, values: values})
		}
		return true
	})
	return out
}

// templateFiles returns the Go template files under the project root.
func templateFiles(root string) ([]string, error) {
	return filesWithExt(root, ".html", ".tmpl", ".gohtml")
}

// filesWithExt returns the files under root with one of the extensions,
// outside dependency, build and hidden directories: templates and
// stylesheets, which the analysis does not list.
func filesWithExt(root string, exts ...string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != root && (envFileSkipDirs[d.Name()] || strings.HasPrefix(d.Name(), ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if slices.Contains(exts, strings.ToLower(filepath.Ext(path))) {
			files = append(files, path)
		}
		return nil
	})
	sort.Strings(files)
	return files, err
}

// templateArgs splits the arguments after a function name in a template
// action: words, $vars, .Fields and quoted strings.
var templateArgs = regexp.MustCompile(`"(?:\\.|[^"\\])*"|[^\s()|}]+`)

// templateForeignLiterals reports literals a template passes to an enum
// parameter of a FuncMap function that no constant of the enum holds.
func (r *EnumComparedToForeignLiteralRule) templateForeignLiterals(ctx *core.GoProjectContext, enums enumIndex) ([]*core.Violation, error) {
	funcs := templateEnumFuncs(ctx, enums)
	if len(funcs) == 0 {
		return nil, nil
	}
	names := make([]string, 0, len(funcs))
	for name := range funcs {
		names = append(names, regexp.QuoteMeta(name))
	}
	sort.Strings(names)
	call := regexp.MustCompile(`(?:\{\{-?|\(|\|)\s*(?:if\s+|with\s+|not\s+)?(` + strings.Join(names, "|") + `)\s+([^}]*)`)
	files, err := templateFiles(ctx.ProjectRoot)
	if err != nil {
		return nil, err
	}
	var violations []*core.Violation
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		rel, err := filepath.Rel(ctx.ProjectRoot, path)
		if err != nil {
			return nil, err
		}
		for i, line := range strings.Split(string(data), "\n") {
			for _, m := range call.FindAllStringSubmatch(line, -1) {
				args := templateArgs.FindAllString(m[2], -1)
				for _, param := range funcs[m[1]] {
					if param.index >= len(args) {
						continue
					}
					value, err := strconv.Unquote(args[param.index])
					if err != nil || !enumLiteral.MatchString(value) || param.values[value] {
						continue
					}
					v := r.CreateViolation(param.file.RelPath, param.line, fmt.Sprintf(
						"%s:%d passes %q to %s, which converts it to %s, and no constant of that type holds it — a value of another set that never matches",
						filepath.ToSlash(rel), i+1, value, m[1], param.named.Obj().Name()))
					v.WithCode(strings.TrimSpace(line))
					v.WithSuggestion("Use a value of " + param.named.Obj().Name() + ", or pass the constant from the handler instead of a literal")
					violations = append(violations, v)
				}
			}
		}
	}
	return violations, nil
}
