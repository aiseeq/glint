package duplication

import (
	"errors"
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"regexp"
	"slices"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewDuplicateConstAcrossPackagesRule())
}

// qualifiedName is a pkg.Name reference written in a comment.
var qualifiedName = regexp.MustCompile(`\b([a-z][a-z0-9_]*)\.([A-Za-z_][A-Za-z0-9_]*)\b`)

// DuplicateConstAcrossPackagesRule detects one setting kept as two copies:
//
//	// plan/threat.go
//	const foeNearBaseR = 15
//
//	// plan/situation/situation.go
//	const foeNearBaseR = 15
//
// an unexported constant of the same name and value declared in two packages
// of the module, and a literal copy whose comment names the constant it
// copies:
//
//	const localR = 18.0 // plan.LocalR
//
// A change of the threshold lands in one place, and the other goes on
// measuring by the old one. Only literal values count — a constant defined
// through another one shares it already. Two packages count only when one
// imports the other within one module: then the importer can use the
// constant the imported package exports, while unrelated packages often
// give one role name (maxBatchSize) their own setting. A one-word name
// (limit, size) is a role every package fills its own way, and an iota
// enumeration counts its own states; test files and mock packages are left
// out.
type DuplicateConstAcrossPackagesRule struct {
	*rules.BaseRule
}

// NewDuplicateConstAcrossPackagesRule creates the rule
func NewDuplicateConstAcrossPackagesRule() *DuplicateConstAcrossPackagesRule {
	return &DuplicateConstAcrossPackagesRule{BaseRule: rules.NewBaseRule(
		"duplicate-const-across-packages",
		"duplication",
		"Detects an unexported constant declared in two packages under one name and value, and a constant whose comment names the module constant it copies as a literal — two copies of one setting that drift apart",
		core.SeverityMedium,
	)}
}

// AnalyzeFile is a no-op: the copies live in different packages.
func (r *DuplicateConstAcrossPackagesRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *DuplicateConstAcrossPackagesRule) RequiresSSA() bool { return false }

// AnalyzeGoProject reports each copy of a constant duplicated across packages.
func (r *DuplicateConstAcrossPackagesRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, errors.New("duplicate const across packages: nil Go project context")
	}
	byKey := make(map[string][]*types.Const)
	imports := newImportReach(ctx)
	aliasOf := make(map[*types.Const]*types.Const)
	// byPackageName holds the constants of the module by the name a comment
	// would qualify them with.
	byPackageName := make(map[string]map[string]*types.Const)
	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil || pkg.Package.TypesInfo == nil {
			return nil, errors.New("duplicate const across packages: package has no typed syntax")
		}
		if testDoublePackage(pkg.Package.PkgPath) {
			continue
		}
		info := pkg.Package.TypesInfo
		for _, file := range pkg.Files {
			if file.GoAST == nil || file.IsTestFile() || file.IsGenerated() {
				continue
			}
			for _, pc := range packageConsts(file.GoAST, info) {
				c := pc.obj
				named := byPackageName[c.Pkg().Name()]
				if named == nil {
					named = make(map[string]*types.Const)
					byPackageName[c.Pkg().Name()] = named
				}
				named[c.Name()] = c
				if pc.alias != nil {
					aliasOf[c] = pc.alias
				}
				if pc.literal && !ast.IsExported(c.Name()) && len(helpers.IdentifierWords(c.Name())) >= 2 {
					key := c.Name() + "|" + constKey(c.Val())
					byKey[key] = append(byKey[key], c)
				}
			}
		}
	}
	twins := constTwins(byKey, imports)
	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(file *core.FileContext, info *types.Info) []*core.Violation {
		var violations []*core.Violation
		ast.Inspect(file.GoAST, func(n ast.Node) bool {
			decl, ok := n.(*ast.GenDecl)
			if !ok || decl.Tok != token.CONST {
				return true
			}
			for _, spec := range decl.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for _, name := range vs.Names {
					c, ok := info.Defs[name].(*types.Const)
					if !ok {
						continue
					}
					line := file.LineFor(name)
					if file.IsSuppressed(line, r.Name()) {
						continue
					}
					if twin := twins[c]; twin != "" {
						violations = append(violations, r.report(file, line,
							fmt.Sprintf("Constant %s has a copy with the same value in %s — two copies of one setting: a change lands in one and the other drifts", c.Name(), twin),
							"Keep one constant in a package both import and use it from both places"))
						continue
					}
					if !literalValues(vs) {
						continue
					}
					if source := copiedSource(c, vs, decl, byPackageName, aliasOf); source != "" {
						violations = append(violations, r.report(file, line,
							fmt.Sprintf("Constant %s copies %s (%s) as a literal — the comment names where the value lives, and the copy drifts when it changes", c.Name(), source, c.Val().String()),
							fmt.Sprintf("Use %s, or move it to a package both can import", source)))
					}
				}
			}
			return true
		})
		return violations
	})
}

func (r *DuplicateConstAcrossPackagesRule) report(file *core.FileContext, line int, message, suggestion string) *core.Violation {
	v := r.CreateViolation(file.RelPath, line, message)
	v.WithCode(strings.TrimSpace(file.GetLine(line)))
	v.WithSuggestion(suggestion)
	return v
}

// packageConst is a package-level constant with how its value is spelled.
type packageConst struct {
	obj *types.Const
	// literal: the value is spelled with literals only.
	literal bool
	// alias: the constant the value names, when it is just a name.
	alias *types.Const
}

// packageConsts returns the file's package-level constants.
func packageConsts(file *ast.File, info *types.Info) []packageConst {
	var out []packageConst
	for _, decl := range file.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			literal := literalValues(vs)
			for i, name := range vs.Names {
				c, ok := info.Defs[name].(*types.Const)
				if !ok {
					continue
				}
				pc := packageConst{obj: c, literal: literal}
				if i < len(vs.Values) {
					pc.alias = namedConst(vs.Values[i], info)
				}
				out = append(out, pc)
			}
		}
	}
	return out
}

// namedConst returns the constant an expression is, when it is only its name.
func namedConst(expr ast.Expr, info *types.Info) *types.Const {
	var id *ast.Ident
	switch e := ast.Unparen(expr).(type) {
	case *ast.Ident:
		id = e
	case *ast.SelectorExpr:
		id = e.Sel
	}
	if id == nil {
		return nil
	}
	c, _ := info.Uses[id].(*types.Const)
	return c
}

// literalValues reports a spec whose values are spelled with literals and
// operators only, with no name in them (not iota, not another constant, not a
// conversion); a spec repeating the value above it has none.
func literalValues(vs *ast.ValueSpec) bool {
	if len(vs.Values) == 0 {
		return false
	}
	for _, value := range vs.Values {
		named := false
		ast.Inspect(value, func(n ast.Node) bool {
			if _, ok := n.(*ast.Ident); ok {
				named = true
			}
			return !named
		})
		if named {
			return false
		}
	}
	return true
}

// importReach answers whether one package of the project imports another,
// directly or through others, within one module.
type importReach struct {
	byPath  map[string]*packages.Package
	reached map[string]map[string]bool
}

func newImportReach(ctx *core.GoProjectContext) *importReach {
	reach := &importReach{byPath: make(map[string]*packages.Package), reached: make(map[string]map[string]bool)}
	for _, pkg := range ctx.Packages {
		if pkg != nil && pkg.Package != nil {
			reach.byPath[pkg.Package.PkgPath] = pkg.Package
		}
	}
	return reach
}

// related reports two packages of one module where one imports the other.
func (r *importReach) related(a, b *types.Package) bool {
	pa, pb := r.byPath[a.Path()], r.byPath[b.Path()]
	if pa == nil || pb == nil || moduleOf(pa) != moduleOf(pb) {
		return false
	}
	return r.imports(pa)[pb.PkgPath] || r.imports(pb)[pa.PkgPath]
}

// imports returns every package path the package reaches through imports.
func (r *importReach) imports(pkg *packages.Package) map[string]bool {
	if seen, ok := r.reached[pkg.PkgPath]; ok {
		return seen
	}
	seen := make(map[string]bool)
	r.reached[pkg.PkgPath] = seen
	var walk func(p *packages.Package)
	walk = func(p *packages.Package) {
		for path, dep := range p.Imports {
			if seen[path] {
				continue
			}
			seen[path] = true
			walk(dep)
		}
	}
	walk(pkg)
	return seen
}

func moduleOf(pkg *packages.Package) string {
	if pkg.Module == nil {
		return ""
	}
	return pkg.Module.Path
}

// constTwins maps each copy to the package path of a related package holding
// another copy.
func constTwins(byKey map[string][]*types.Const, imports *importReach) map[*types.Const]string {
	twins := make(map[*types.Const]string)
	keys := make([]string, 0, len(byKey))
	for key := range byKey {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		copies := byKey[key]
		var holders []*types.Package
		for _, c := range copies {
			if !slices.Contains(holders, c.Pkg()) {
				holders = append(holders, c.Pkg())
			}
		}
		for _, c := range copies {
			for _, other := range holders {
				if other != c.Pkg() && imports.related(c.Pkg(), other) {
					twins[c] = other.Path()
					break
				}
			}
		}
	}
	return twins
}

// constKey prints a value so that 15 and 15.0 give one key.
func constKey(v constant.Value) string {
	if v.Kind() == constant.Float {
		if i := constant.ToInt(v); i.Kind() == constant.Int {
			return i.ExactString()
		}
	}
	return v.ExactString()
}

// copiedSource returns pkg.Name of a module constant of another package that
// the comment of the constant names and whose value it repeats, unless the
// constant is defined through that name.
func copiedSource(c *types.Const, vs *ast.ValueSpec, decl *ast.GenDecl, byPackageName map[string]map[string]*types.Const, aliasOf map[*types.Const]*types.Const) string {
	var text strings.Builder
	for _, group := range []*ast.CommentGroup{vs.Doc, vs.Comment} {
		if group != nil {
			text.WriteString(group.Text())
		}
	}
	if len(decl.Specs) == 1 && decl.Doc != nil {
		text.WriteString(decl.Doc.Text())
	}
	for _, m := range qualifiedName.FindAllStringSubmatch(text.String(), -1) {
		if c.Pkg() != nil && m[1] == c.Pkg().Name() {
			continue
		}
		source, ok := byPackageName[m[1]][m[2]]
		if !ok || source == c || definedThrough(source, c, aliasOf) {
			continue
		}
		if constKey(source.Val()) == constKey(c.Val()) {
			return m[1] + "." + m[2]
		}
	}
	return ""
}

// definedThrough reports a constant defined, through a chain of names, as
// target: the comment names an alias of the constant itself.
func definedThrough(c, target *types.Const, aliasOf map[*types.Const]*types.Const) bool {
	for seen := 0; c != nil && seen < len(aliasOf)+1; seen++ {
		if c == target {
			return true
		}
		c = aliasOf[c]
	}
	return false
}
