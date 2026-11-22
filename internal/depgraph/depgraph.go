// Package depgraph finds, at build time, the source a cached finding of each
// rule depends on, so that a release changes the cache key of the rules whose
// code it changed and not of every rule.
//
// The program is loaded with types (module packages from source, the rest from
// export data) and built into SSA. Reachability is a rapid type analysis over
// the module's functions: a static call reaches its callee; a function or
// closure whose value is taken in reachable code is reachable (it can only run
// if it was made somewhere, and a value made in reachable code may be called
// by anyone, the standard library included); a module type converted to an
// interface in reachable code makes reachable its methods whose name some
// reachable code invokes through an interface, or that satisfy an interface
// of a package outside the module (the standard library calls String, Error,
// Visit, Less, MarshalJSON...), and so do the types it holds (fmt, json and
// yaml reach the fields by reflection). Calls the module code makes into
// packages outside the module are not followed: they can only come back
// through such values. Their source is read for what they can call on such
// a value: the methods of the interfaces they spell out in place
// (v.(interface{ M() })), and, when they call methods by name (reflect's
// MethodByName in text/template), every exported method of a type the scope
// converts to an interface. A generic function outside the module may
// convert any type argument to an interface.
//
// A package variable a scope reads brings in the functions that can change
// it: those that store into its memory or let a reference into it go (pass
// it to a call, store it, capture it, return it to their callers), the
// callers of a function that stores what its caller passed, and the writers
// of a variable it was stored into.
//
// Two scopes come out:
//   - the driver: what any run executes whatever rules it runs - main, every
//     package initializer (so the constructor and the registration of every
//     rule) and the methods the registry calls on every rule (Name,
//     Configure...). Its source is in every cache key.
//   - a rule: what is reachable from the methods of the registered value and
//     from the function values its registration passes (newShellRule(name,
//     check)), and not in the driver. A rule is identified by where
//     rules.Register was called for it.
//
// A scope's hash covers the source tokens (comments and layout aside) of its
// functions, of the types, constants and package variables they name (with
// the variable's initializer and its go:embed files), the import paths the
// declarations resolve, and for a type the module interfaces it implements;
// //go: directives count as code. The driver's hash also covers the order of
// initialization - init functions, and variables whose initializer calls
// module code, by file name and place - which the sets of hashes lose.
//
// Where the call graph cannot follow (a //go:linkname directive, Register
// taken as a value, a type nested beyond maxDepth) every rule is keyed by
// the whole module; rules registered on one line share their keys.
package depgraph

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"go/ast"
	"go/parser"
	"go/scanner"
	"go/token"
	"go/types"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
	"golang.org/x/tools/go/types/typeutil"
)

// Config names the parts of the program the analysis treats specially.
type Config struct {
	// Dir is the module root; every package of the module is loaded.
	Dir string
	// Command is the import path of the main package of the binary.
	Command string
	// Entry is the function of Command that handles the command whose
	// findings are cached. The other functions of Command with its signature
	// (the handlers of the other commands) are not followed from the driver.
	Entry string
	// Register is the function rules are registered with ("pkg.Register").
	Register string
	// Rule is the interface every rule implements ("pkg.Rule").
	Rule string
	// RegistryMethods are the methods of a rule the registry and the run call
	// on every registered rule, whatever rules the run selects.
	RegistryMethods []string
}

// Site is one call of the register function: the rules it registers.
type Site struct {
	// File is "<import path>/<file name>", From and To the lines of the call.
	File     string
	From, To int
	// Type is the registered value's type, empty when only the interface is
	// known at the call.
	Type  string
	Hash  string
	Funcs []string
}

// Result is what a build records about its rules.
type Result struct {
	Driver      string
	DriverFuncs []string
	// All covers the whole module: the key of a rule no site describes.
	All   string
	Sites []Site
	// Notes are the places the analysis could not resolve precisely.
	Notes []string
}

// Analyze loads the module at cfg.Dir and computes its scopes.
func Analyze(ctx context.Context, cfg Config) (*Result, error) {
	loadCfg := &packages.Config{
		Context: ctx,
		Dir:     cfg.Dir,
		Mode:    packages.LoadSyntax | packages.NeedModule | packages.NeedEmbedFiles,
	}
	pkgs, err := packages.Load(loadCfg, "./...")
	if err != nil {
		return nil, fmt.Errorf("load packages: %w", err)
	}
	var errs []string
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		for _, e := range p.Errors {
			errs = append(errs, e.Error())
		}
	})
	if len(errs) > 0 {
		return nil, fmt.Errorf("load packages: %s", strings.Join(errs, "; "))
	}
	a, err := newAnalyzer(cfg, pkgs)
	if err != nil {
		return nil, err
	}
	if err := a.scanExternal(ctx); err != nil {
		return nil, err
	}
	return a.run()
}

// scanExternal reads the source of the packages outside the module, whose
// bodies export data does not carry: the methods they can call on a module
// value through an interface they spell out in place (v.(interface{ M() }))
// join the names any interfaced type is reached by, and the packages that
// call methods by name (reflect's Method, MethodByName: text/template) or
// import one that does are reflective.
func (a *analyzer) scanExternal(ctx context.Context) error {
	pkgs, err := packages.Load(&packages.Config{
		Context: ctx,
		Dir:     a.cfg.Dir,
		Mode:    packages.NeedName | packages.NeedFiles | packages.NeedImports | packages.NeedDeps,
	}, "./...")
	if err != nil {
		return fmt.Errorf("list the packages outside the module: %w", err)
	}
	direct := make(map[string]bool)
	var all []*packages.Package
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		if a.inModulePath(p.PkgPath) {
			return
		}
		all = append(all, p)
	})
	fset := token.NewFileSet()
	for _, p := range all {
		for _, name := range p.GoFiles {
			file, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
			if err != nil {
				return fmt.Errorf("parse %s: %w", name, err)
			}
			ast.Inspect(file, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.InterfaceType:
					for _, field := range n.Methods.List {
						if _, ok := field.Type.(*ast.FuncType); !ok {
							continue
						}
						for _, id := range field.Names {
							if id.IsExported() {
								a.extNames[id.Name] = true
							}
						}
					}
				case *ast.CallExpr:
					if sel, ok := ast.Unparen(n.Fun).(*ast.SelectorExpr); ok && byName[sel.Sel.Name] && !reflectItself[p.PkgPath] {
						direct[p.PkgPath] = true
					}
				}
				return true
			})
		}
	}
	reflective := make(map[string]bool)
	done := make(map[string]bool)
	var visit func(p *packages.Package) bool
	visit = func(p *packages.Package) bool {
		if done[p.PkgPath] {
			return reflective[p.PkgPath]
		}
		done[p.PkgPath] = true
		r := direct[p.PkgPath]
		for _, imp := range p.Imports {
			if !a.inModulePath(imp.PkgPath) && visit(imp) {
				r = true
			}
		}
		reflective[p.PkgPath] = r
		return r
	}
	for _, p := range all {
		visit(p)
	}
	a.reflective = make(map[*types.Package]bool)
	for _, p := range a.prog.AllPackages() {
		if reflective[p.Pkg.Path()] {
			a.reflective[p.Pkg] = true
		}
	}
	return nil
}

// byName are the methods of reflect that call a method chosen at run time.
var byName = map[string]bool{"Method": true, "MethodByName": true}

// reflectItself implements them: it calls nothing on its own.
var reflectItself = map[string]bool{"reflect": true, "internal/reflectlite": true}

type analyzer struct {
	cfg     Config
	fset    *token.FileSet
	prog    *ssa.Program
	module  string
	pkgs    map[*types.Package]*packages.Package
	files   map[*token.File]*fileIndex
	units   []*unit
	facts   map[*ssa.Function]*facts
	anon    map[token.Pos]*ssa.Function
	writers map[*unit][]*ssa.Function
	sites   []*site
	// siteFuncs holds the sites by the innermost function syntax around them.
	siteFuncs map[ast.Node][]*site
	register  *types.Func
	ruleIface *types.Interface
	ruleTypes map[*types.TypeName]bool
	registry  map[string]bool
	extNames  map[string]bool
	ifaces    []*types.TypeName
	entry     *ssa.Function
	command   *ssa.Package
	notes     []string
	sources   map[string][]byte
	msets     typeutil.MethodSetCache
	// aliases links package variables one's memory was stored into the
	// other's: a write through either is a write to both.
	aliases map[*unit][]*unit
	// taint holds, by function, the values computed from its parameters.
	taint map[*ssa.Function]map[ssa.Value]bool
	// reflective holds the packages outside the module that call methods by
	// name (reflect's Method, MethodByName), or import one that does.
	reflective map[*types.Package]bool
	// all is the hash of the whole module, the key of a scope the analysis
	// cannot bound.
	all string
	// whole: the module holds what the call graph cannot follow (a
	// //go:linkname directive, rules.Register taken as a value); every rule is
	// keyed by the whole module.
	whole []string
}

type fileIndex struct {
	pkg   *packages.Package
	file  *ast.File
	key   string
	units []*unit
}

type unitKind int

const (
	funcUnit unitKind = iota
	typeUnit
	varUnit
	constUnit
)

type unit struct {
	kind unitKind
	// key is "<import path>/<file>:<line>"; a function's line is the one of
	// the brace its body opens with, where go tool covdata func names it.
	key      string
	name     string
	idx      *fileIndex
	node     ast.Node
	from, to token.Pos
	// typeSpec and valueSpec are node for a type and a variable.
	typeSpec  *ast.TypeSpec
	valueSpec *ast.ValueSpec
	// keyPos, when set, gives the key its line instead of from.
	keyPos token.Pos

	hashed bool
	hash   string

	refsDone bool
	refs     []*unit
	// For a variable: the function values and types its initializer holds
	// outside calls (calls run in the package initializer, in the driver).
	initFuncs []*ssa.Function
	initTypes []types.Type
}

type facts struct {
	calls   []*ssa.Function
	values  []*ssa.Function
	invokes []string
	ifaces  []types.Type
	globals []*unit
	// held: values and types the function passes at a registration site or
	// stores into package variables at initialization; they belong to the
	// rule or the variable, not to whoever runs the function.
	heldValues []*ssa.Function
	heldIfaces []types.Type
}

type site struct {
	call  *ast.CallExpr
	idx   *fileIndex
	outer ast.Node // innermost FuncDecl or FuncLit
	file  string
	from  int
	to    int
	typ   types.Type
	// unknown: the registered value comes from variables of the enclosing
	// function, so the whole function is the rule's.
	locals bool
	// open: the enclosing function is not an initializer and its values come
	// from its callers: the rule depends on everything.
	open   bool
	values []*ssa.Function
	types  []types.Type
}

func newAnalyzer(cfg Config, pkgs []*packages.Package) (*analyzer, error) {
	a := &analyzer{
		cfg:       cfg,
		pkgs:      make(map[*types.Package]*packages.Package),
		files:     make(map[*token.File]*fileIndex),
		facts:     make(map[*ssa.Function]*facts),
		anon:      make(map[token.Pos]*ssa.Function),
		writers:   make(map[*unit][]*ssa.Function),
		siteFuncs: make(map[ast.Node][]*site),
		ruleTypes: make(map[*types.TypeName]bool),
		registry:  make(map[string]bool),
		extNames:  make(map[string]bool),
		sources:   make(map[string][]byte),
		aliases:   make(map[*unit][]*unit),
		taint:     make(map[*ssa.Function]map[ssa.Value]bool),
	}
	for _, name := range cfg.RegistryMethods {
		a.registry[name] = true
	}
	for _, p := range pkgs {
		if p.Module != nil && p.Module.Main {
			a.module = p.Module.Path
			break
		}
	}
	if a.module == "" {
		return nil, fmt.Errorf("no package of the main module")
	}
	prog, ssaPkgs := ssautil.Packages(pkgs, ssa.InstantiateGenerics)
	a.prog, a.fset = prog, prog.Fset
	for i, p := range pkgs {
		if ssaPkgs[i] == nil {
			return nil, fmt.Errorf("package %s has no SSA form", p.PkgPath)
		}
		if a.inModule(p.Types) {
			a.pkgs[p.Types] = p
		}
	}
	a.createMissing()
	prog.Build()
	for _, p := range pkgs {
		if a.inModule(p.Types) {
			a.indexPackage(p)
		}
	}
	if err := a.resolveConfig(); err != nil {
		return nil, err
	}
	a.collectNames()
	a.indexFunctions()
	return a, nil
}

// createMissing creates the packages export data refers to that no import
// list of the loaded packages names: methods promoted from their types need
// them.
func (a *analyzer) createMissing() {
	var visit func(p *types.Package)
	seen := make(map[*types.Package]bool)
	visit = func(p *types.Package) {
		if seen[p] {
			return
		}
		seen[p] = true
		if a.prog.Package(p) == nil {
			a.prog.CreatePackage(p, nil, nil, true)
		}
		for _, imp := range p.Imports() {
			visit(imp)
		}
	}
	for _, p := range a.prog.AllPackages() {
		visit(p.Pkg)
	}
}

func (a *analyzer) inModule(p *types.Package) bool {
	return p != nil && a.inModulePath(p.Path())
}

func (a *analyzer) inModulePath(path string) bool {
	return path == a.module || strings.HasPrefix(path, a.module+"/")
}

func (a *analyzer) indexPackage(p *packages.Package) {
	for _, file := range p.Syntax {
		tf := a.fset.File(file.Pos())
		name := filepath.Base(tf.Name())
		idx := &fileIndex{pkg: p, file: file, key: p.PkgPath + "/" + name}
		a.files[tf] = idx
		for _, group := range file.Comments {
			for _, c := range group.List {
				if strings.HasPrefix(c.Text, "//go:linkname") {
					a.whole = append(a.whole, fmt.Sprintf("%s:%d: //go:linkname binds code the call graph does not see", idx.key, a.fset.Position(c.Pos()).Line))
				}
			}
		}
		for _, decl := range file.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				u := &unit{kind: funcUnit, name: funcName(d), node: d, from: d.Pos(), to: d.End()}
				if d.Body != nil {
					u.keyPos = d.Body.Lbrace
				}
				a.addUnit(idx, u)
			case *ast.GenDecl:
				a.indexGenDecl(idx, d)
			}
		}
	}
}

// indexGenDecl makes a unit of a constant block, of each type and of each
// variable spec.
func (a *analyzer) indexGenDecl(idx *fileIndex, d *ast.GenDecl) {
	if d.Tok == token.CONST {
		a.addUnit(idx, &unit{kind: constUnit, name: "const", node: d, from: d.Pos(), to: d.End()})
		return
	}
	for _, spec := range d.Specs {
		switch spec := spec.(type) {
		case *ast.TypeSpec:
			a.addUnit(idx, &unit{kind: typeUnit, name: spec.Name.Name, node: spec, typeSpec: spec, from: spec.Pos(), to: spec.End()})
		case *ast.ValueSpec:
			a.addUnit(idx, &unit{kind: varUnit, name: spec.Names[0].Name, node: spec, valueSpec: spec, from: spec.Pos(), to: spec.End()})
		}
	}
}

func funcName(d *ast.FuncDecl) string {
	if d.Recv == nil || len(d.Recv.List) == 0 {
		return d.Name.Name
	}
	return types.ExprString(d.Recv.List[0].Type) + "." + d.Name.Name
}

func (a *analyzer) addUnit(idx *fileIndex, u *unit) {
	u.idx = idx
	at := u.from
	if u.keyPos.IsValid() {
		at = u.keyPos
	}
	line := a.fset.Position(at).Line
	u.key = fmt.Sprintf("%s:%d", idx.key, line)
	idx.units = append(idx.units, u)
	a.units = append(a.units, u)
}

// unitAt returns the top-level declaration holding pos, nil outside the
// module.
func (a *analyzer) unitAt(pos token.Pos) *unit {
	if !pos.IsValid() {
		return nil
	}
	idx := a.files[a.fset.File(pos)]
	if idx == nil {
		return nil
	}
	i := sort.Search(len(idx.units), func(i int) bool { return idx.units[i].to > pos })
	if i < len(idx.units) && idx.units[i].from <= pos {
		return idx.units[i]
	}
	return nil
}

func (a *analyzer) resolveConfig() error {
	lookup := func(qualified string) (types.Object, error) {
		dot := strings.LastIndex(qualified, ".")
		if dot < 0 {
			return nil, fmt.Errorf("%q is not package.Name", qualified)
		}
		for tp := range a.pkgs {
			if tp.Path() == qualified[:dot] {
				if obj := tp.Scope().Lookup(qualified[dot+1:]); obj != nil {
					return obj, nil
				}
			}
		}
		return nil, fmt.Errorf("%s not found in the module", qualified)
	}
	obj, err := lookup(a.cfg.Register)
	if err != nil {
		return err
	}
	register, ok := obj.(*types.Func)
	if !ok {
		return fmt.Errorf("%s is not a function", a.cfg.Register)
	}
	a.register = register
	obj, err = lookup(a.cfg.Rule)
	if err != nil {
		return err
	}
	iface, ok := obj.Type().Underlying().(*types.Interface)
	if !ok {
		return fmt.Errorf("%s is not an interface", a.cfg.Rule)
	}
	a.ruleIface = iface
	obj, err = lookup(a.cfg.Command + "." + a.cfg.Entry)
	if err != nil {
		return err
	}
	entry, ok := obj.(*types.Func)
	if !ok {
		return fmt.Errorf("%s.%s is not a function", a.cfg.Command, a.cfg.Entry)
	}
	a.entry = a.prog.FuncValue(entry)
	a.command = a.prog.Package(obj.Pkg())
	if a.entry == nil || a.command == nil {
		return fmt.Errorf("no SSA function for %s.%s", a.cfg.Command, a.cfg.Entry)
	}
	return nil
}

// collectNames records the method names of interfaces outside the module
// (code there may call them on a module value), the module's interfaces and
// the rule types.
func (a *analyzer) collectNames() {
	for _, name := range []string{"Error", "String", "GoString", "Format", "Is", "As", "Unwrap", "Timeout", "Temporary"} {
		a.extNames[name] = true
	}
	for _, p := range a.prog.AllPackages() {
		scope := p.Pkg.Scope()
		for _, name := range scope.Names() {
			tn, ok := scope.Lookup(name).(*types.TypeName)
			if !ok || tn.IsAlias() {
				continue
			}
			if iface, ok := tn.Type().Underlying().(*types.Interface); ok {
				if a.inModule(p.Pkg) {
					if iface.NumMethods() > 0 {
						a.ifaces = append(a.ifaces, tn)
					}
					continue
				}
				for m := range iface.Methods() {
					if m.Exported() {
						a.extNames[m.Name()] = true
					}
				}
				continue
			}
			if !a.inModule(p.Pkg) {
				continue
			}
			if named, ok := tn.Type().(*types.Named); ok && named.TypeParams().Len() == 0 {
				if types.Implements(named, a.ruleIface) || types.Implements(types.NewPointer(named), a.ruleIface) {
					a.ruleTypes[tn] = true
				}
			}
		}
	}
	sort.Slice(a.ifaces, func(i, j int) bool {
		return a.ifaces[i].Pkg().Path()+"."+a.ifaces[i].Name() < a.ifaces[j].Pkg().Path()+"."+a.ifaces[j].Name()
	})
}

// indexFunctions finds the registration sites, indexes closures by position
// and the writers of package variables. Every function SSA built is looked
// at - methods of generic types and the instances of generic code too.
func (a *analyzer) indexFunctions() {
	for _, p := range a.pkgs {
		for _, file := range p.Syntax {
			a.findSites(p, file)
		}
	}
	all := ssautil.AllFunctions(a.prog)
	fns := make([]*ssa.Function, 0, len(all))
	for fn := range all {
		if a.scanned(fn) && len(fn.Blocks) > 0 {
			fns = append(fns, fn)
		}
	}
	sort.Slice(fns, func(i, j int) bool {
		if fns[i].Pos() != fns[j].Pos() {
			return fns[i].Pos() < fns[j].Pos()
		}
		return fns[i].String() < fns[j].String()
	})
	for _, fn := range fns {
		if fn.Parent() != nil && fn.Origin() == nil {
			if _, seen := a.anon[fn.Pos()]; !seen {
				a.anon[fn.Pos()] = fn
			}
		}
	}
	a.indexWriters(fns)
}

// indexWriters finds, for each package variable, the functions that can
// change what it holds: those that store into its memory, and those that let
// a reference into it go - pass it to a call, store it, capture it, send it,
// put it in an interface - since the code it reaches may store through it.
// A function that returns such a reference makes its callers' results
// references too. A reference stored into another variable's memory links
// the two.
func (a *analyzer) indexWriters(fns []*ssa.Function) {
	sources := make(map[*ssa.Function]map[*unit]bool)
	setters := make(map[*ssa.Function]map[*unit]bool)
	for range 8 {
		grew := false
		for _, fn := range fns {
			if fn.Synthetic == "package initializer" {
				continue
			}
			w := &writerScan{a: a, fn: fn, sources: sources, derived: make(map[ssa.Value]map[*unit]bool), setters: setters}
			w.scan()
			if len(w.returned) > 0 {
				own := sources[fn]
				if own == nil {
					own = make(map[*unit]bool)
					sources[fn] = own
				}
				for u := range w.returned {
					if !own[u] {
						own[u] = true
						grew = true
					}
				}
			}
		}
		if !grew {
			break
		}
	}
	a.callersOfSetters(fns, setters)
	for u, ws := range a.writers {
		slices.SortFunc(ws, func(x, y *ssa.Function) int { return strings.Compare(x.String(), y.String()) })
		a.writers[u] = slices.Compact(ws)
	}
}

// writerScan follows, within one function, the values that refer into
// package variables.
type writerScan struct {
	a       *analyzer
	fn      *ssa.Function
	sources map[*ssa.Function]map[*unit]bool
	// setters: the functions that store what their callers pass.
	setters  map[*ssa.Function]map[*unit]bool
	derived  map[ssa.Value]map[*unit]bool
	queue    []ssa.Value
	returned map[*unit]bool
}

func (w *writerScan) scan() {
	var ops []*ssa.Value
	for _, b := range w.fn.Blocks {
		for _, instr := range b.Instrs {
			ops = instr.Operands(ops[:0])
			for _, op := range ops {
				if op == nil || *op == nil {
					continue
				}
				// A global has no referrers: its uses are classified here.
				if g, ok := (*op).(*ssa.Global); ok {
					if u := w.a.unitAt(g.Pos()); u != nil && u.kind == varUnit {
						w.use(g, map[*unit]bool{u: true}, instr)
					}
				}
			}
			if call, ok := instr.(*ssa.Call); ok {
				if callee := call.Call.StaticCallee(); callee != nil {
					origin := callee
					if callee.Origin() != nil {
						origin = callee.Origin()
					}
					from := w.sources[callee]
					if from == nil {
						from = w.sources[origin]
					}
					if len(from) > 0 {
						w.mark(call, from)
					}
				}
			}
		}
	}
	for len(w.queue) > 0 {
		v := w.queue[len(w.queue)-1]
		w.queue = w.queue[:len(w.queue)-1]
		us := w.derived[v]
		refs := v.Referrers()
		if refs == nil {
			continue
		}
		for _, r := range *refs {
			w.use(v, us, r)
		}
	}
}

func (w *writerScan) mark(v ssa.Value, us map[*unit]bool) {
	have := w.derived[v]
	if have == nil {
		have = make(map[*unit]bool)
		w.derived[v] = have
	}
	grew := false
	for u := range us {
		if !have[u] {
			have[u] = true
			grew = true
		}
	}
	if grew {
		w.queue = append(w.queue, v)
	}
}

func (w *writerScan) setter(us map[*unit]bool) {
	own := w.setters[w.fn]
	if own == nil {
		own = make(map[*unit]bool)
		w.setters[w.fn] = own
	}
	for u := range us {
		own[u] = true
	}
}

// callersOfSetters: what a setter stores, its caller chose; the caller writes
// the variable too, and is a setter itself when it passes on its own
// parameters. A call through an interface counts for every setter method of
// the name.
func (a *analyzer) callersOfSetters(fns []*ssa.Function, setters map[*ssa.Function]map[*unit]bool) {
	byName := make(map[string][]*ssa.Function)
	index := func() {
		clear(byName)
		for fn := range setters {
			if fn.Signature.Recv() != nil {
				byName[fn.Name()] = append(byName[fn.Name()], fn)
			}
		}
	}
	for range 32 {
		index()
		grew := false
		for _, fn := range fns {
			taint := a.fromParams(fn)
			for _, b := range fn.Blocks {
				for _, instr := range b.Instrs {
					if call, ok := instr.(ssa.CallInstruction); ok && a.callsSetter(fn, call.Common(), taint, byName, setters) {
						grew = true
					}
				}
			}
		}
		if !grew {
			return
		}
	}
}

// callsSetter records fn as a writer of what the setters common may call
// store, and as a setter of it when fn passes on a value of its parameters
// taint holds; it reports whether fn became a setter of more.
func (a *analyzer) callsSetter(fn *ssa.Function, common *ssa.CallCommon, taint map[ssa.Value]bool,
	byName map[string][]*ssa.Function, setters map[*ssa.Function]map[*unit]bool) bool {
	var callees []*ssa.Function
	if common.IsInvoke() {
		callees = byName[common.Method.Name()]
	} else if callee := common.StaticCallee(); callee != nil {
		callees = append(callees, callee)
		if callee.Origin() != nil {
			callees = append(callees, callee.Origin())
		}
	}
	passes := fn.Synthetic != "package initializer" &&
		(slices.ContainsFunc(common.Args, func(v ssa.Value) bool { return taint[v] }) || (common.IsInvoke() && taint[common.Value]))
	grew := false
	for _, callee := range callees {
		for u := range setters[callee] {
			if !slices.Contains(a.writers[u], fn) {
				a.writers[u] = append(a.writers[u], fn)
			}
			if !passes || setters[fn][u] {
				continue
			}
			if setters[fn] == nil {
				setters[fn] = make(map[*unit]bool)
			}
			setters[fn][u] = true
			grew = true
		}
	}
	return grew
}

// fromParams returns the values of a function computed from its parameters
// and captured variables.
func (a *analyzer) fromParams(fn *ssa.Function) map[ssa.Value]bool {
	if t, ok := a.taint[fn]; ok {
		return t
	}
	t := make(map[ssa.Value]bool)
	a.taint[fn] = t
	var queue []ssa.Value
	add := func(v ssa.Value) {
		if v != nil && !t[v] {
			t[v] = true
			queue = append(queue, v)
		}
	}
	for _, p := range fn.Params {
		add(p)
	}
	for _, fv := range fn.FreeVars {
		add(fv)
	}
	for len(queue) > 0 {
		v := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		refs := v.Referrers()
		if refs == nil {
			continue
		}
		for _, r := range *refs {
			switch r := r.(type) {
			case ssa.Value:
				add(r)
			case *ssa.Store:
				if r.Val == v {
					if _, local := r.Addr.(*ssa.Alloc); local {
						add(r.Addr)
					}
				}
			}
		}
	}
	return t
}

func (w *writerScan) write(us map[*unit]bool) {
	for u := range us {
		w.a.writers[u] = append(w.a.writers[u], w.fn)
	}
}

// use classifies one use of a reference into the variables us.
func (w *writerScan) use(v ssa.Value, us map[*unit]bool, r ssa.Instruction) {
	switch r := r.(type) {
	case *ssa.FieldAddr, *ssa.IndexAddr, *ssa.Slice, *ssa.ChangeType, *ssa.ChangeInterface, *ssa.Convert,
		*ssa.MultiConvert, *ssa.SliceToArrayPointer, *ssa.Phi:
		if val, ok := r.(ssa.Value); ok {
			w.mark(val, us)
		}
	case *ssa.UnOp:
		if r.Op == token.MUL && mayRefer(r.Type()) {
			w.mark(r, us)
		}
	case *ssa.Field, *ssa.Index, *ssa.Lookup, *ssa.TypeAssert, *ssa.Extract:
		if val, ok := r.(ssa.Value); ok && mayRefer(val.Type()) {
			w.mark(val, us)
		}
	case *ssa.MakeInterface:
		if mayRefer(r.X.Type()) {
			w.mark(r, us)
		}
	case *ssa.Store:
		w.write(us)
		if r.Val == v {
			w.link(r.Addr, us)
		} else if w.a.fromParams(w.fn)[r.Val] {
			w.setter(us)
		}
	case *ssa.MapUpdate:
		w.write(us)
		if r.Map != v {
			w.link(r.Map, us)
		} else if taint := w.a.fromParams(w.fn); taint[r.Key] || taint[r.Value] {
			w.setter(us)
		}
	case ssa.CallInstruction:
		common := r.Common()
		if b, ok := common.Value.(*ssa.Builtin); ok && readOnlyBuiltin[b.Name()] {
			return
		}
		if !common.IsInvoke() && common.Value == v && !slices.Contains(common.Args, v) {
			// Calling a function value read from a variable.
			return
		}
		w.write(us)
	case *ssa.Return:
		if w.returned == nil {
			w.returned = make(map[*unit]bool)
		}
		for u := range us {
			w.returned[u] = true
		}
	case *ssa.BinOp, *ssa.If, *ssa.Panic, *ssa.Range, *ssa.Next, *ssa.DebugRef, *ssa.Jump, *ssa.RunDefers:
	default:
		// Send, MakeClosure, Select and anything else: the reference leaves.
		w.write(us)
	}
}

// link records that the memory of the variables us was stored into the
// memory addr refers to: when that is a package variable, the two alias.
func (w *writerScan) link(addr ssa.Value, us map[*unit]bool) {
	g := rootGlobal(addr)
	if g == nil {
		return
	}
	h := w.a.unitAt(g.Pos())
	if h == nil {
		return
	}
	for u := range us {
		if u != h {
			w.a.aliases[u] = appendNew(w.a.aliases[u], h)
			w.a.aliases[h] = appendNew(w.a.aliases[h], u)
		}
	}
}

func appendNew(list []*unit, u *unit) []*unit {
	if slices.Contains(list, u) {
		return list
	}
	return append(list, u)
}

// readOnlyBuiltin are the builtins that change nothing their arguments refer
// to.
var readOnlyBuiltin = map[string]bool{"len": true, "cap": true, "print": true, "println": true, "real": true,
	"imag": true, "min": true, "max": true, "complex": true}

// mayRefer reports whether a value of type t can refer to other memory.
func mayRefer(t types.Type) bool {
	seen := make(map[types.Type]bool)
	var refer func(t types.Type) bool
	refer = func(t types.Type) bool {
		if seen[t] {
			return false
		}
		seen[t] = true
		switch u := t.Underlying().(type) {
		case *types.Basic:
			return u.Kind() == types.UnsafePointer
		case *types.Struct:
			for f := range u.Fields() {
				if refer(f.Type()) {
					return true
				}
			}
			return false
		case *types.Array:
			return refer(u.Elem())
		case *types.Tuple:
			for v := range u.Variables() {
				if refer(v.Type()) {
					return true
				}
			}
			return false
		default:
			return true
		}
	}
	return refer(t)
}

// rootGlobal follows an address or a loaded map back to a package variable.
func rootGlobal(v ssa.Value) *ssa.Global {
	for range 16 {
		switch x := v.(type) {
		case *ssa.Global:
			return x
		case *ssa.FieldAddr:
			v = x.X
		case *ssa.IndexAddr:
			v = x.X
		case *ssa.UnOp:
			if x.Op != token.MUL {
				return nil
			}
			v = x.X
		case *ssa.Field:
			v = x.X
		case *ssa.Index:
			v = x.X
		case *ssa.Lookup:
			v = x.X
		case *ssa.Slice:
			v = x.X
		default:
			return nil
		}
	}
	return nil
}

func (a *analyzer) findSites(p *packages.Package, file *ast.File) {
	tf := a.fset.File(file.Pos())
	idx := a.files[tf]
	called := make(map[*ast.Ident]bool)
	ast.Inspect(file, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			switch fun := ast.Unparen(call.Fun).(type) {
			case *ast.Ident:
				called[fun] = true
			case *ast.SelectorExpr:
				called[fun.Sel] = true
			}
		}
		if id, ok := n.(*ast.Ident); ok && !called[id] && p.TypesInfo.Uses[id] == a.register {
			a.whole = append(a.whole, fmt.Sprintf("%s:%d: %s taken as a value: the rules it registers have no site", idx.key, a.fset.Position(id.Pos()).Line, a.cfg.Register))
		}
		return true
	})
	var stack []ast.Node
	ast.Inspect(file, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		stack = append(stack, n)
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 1 || calleeFunc(p.TypesInfo, call) != a.register {
			return true
		}
		var outer ast.Node
		for i := len(stack) - 1; i >= 0; i-- {
			switch stack[i].(type) {
			case *ast.FuncDecl, *ast.FuncLit:
				outer = stack[i]
			}
			if outer != nil {
				break
			}
		}
		s := &site{
			call: call, idx: idx, outer: outer, file: idx.key,
			from: a.fset.Position(call.Pos()).Line, to: a.fset.Position(call.End()).Line,
			typ: p.TypesInfo.TypeOf(call.Args[0]),
		}
		if decl, ok := outer.(*ast.FuncDecl); !ok || decl.Recv != nil || decl.Name.Name != "init" {
			s.open = true
		}
		a.sites = append(a.sites, s)
		a.siteFuncs[outer] = append(a.siteFuncs[outer], s)
		return true
	})
}

func calleeFunc(info *types.Info, call *ast.CallExpr) *types.Func {
	var id *ast.Ident
	switch fun := ast.Unparen(call.Fun).(type) {
	case *ast.Ident:
		id = fun
	case *ast.SelectorExpr:
		id = fun.Sel
	default:
		return nil
	}
	fn, _ := info.Uses[id].(*types.Func)
	return fn
}

// held walks an expression evaluated at initialization or registration and
// returns the function values and types it holds. Calls are left out unless
// intoCalls: the package initializer runs them, the driver has them.
func (a *analyzer) held(info *types.Info, root ast.Node, intoCalls bool) (fns []*ssa.Function, typs []types.Type, locals bool) {
	callFun := make(map[ast.Expr]bool)
	ast.Inspect(root, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.FuncLit:
			if fn := a.anon[n.Type.Func]; fn != nil {
				fns = append(fns, fn)
			}
			return false
		case *ast.CallExpr:
			if tv, ok := info.Types[n.Fun]; ok && tv.IsType() {
				return true
			}
			callFun[ast.Unparen(n.Fun)] = true
			if sel, ok := ast.Unparen(n.Fun).(*ast.SelectorExpr); ok {
				callFun[sel.Sel] = true
			}
			return intoCalls
		case *ast.CompositeLit:
			if t := info.TypeOf(n); t != nil {
				typs = append(typs, t)
			}
		case *ast.UnaryExpr:
			if n.Op == token.AND {
				if t := info.TypeOf(n); t != nil {
					typs = append(typs, t)
				}
			}
		case *ast.SelectorExpr:
			if callFun[n] {
				return true
			}
			if sel := info.Selections[n]; sel != nil && (sel.Kind() == types.MethodVal || sel.Kind() == types.MethodExpr) {
				if m, ok := sel.Obj().(*types.Func); ok && !types.IsInterface(sel.Recv()) {
					if fn := a.methodFunc(sel); fn != nil {
						fns = append(fns, fn)
					} else if fn := a.prog.FuncValue(m.Origin()); fn != nil {
						fns = append(fns, fn)
					}
				}
			}
		case *ast.Ident:
			if callFun[n] {
				return true
			}
			switch obj := info.Uses[n].(type) {
			case *types.Func:
				if obj.Signature().Recv() == nil {
					if fn := a.prog.FuncValue(obj.Origin()); fn != nil {
						fns = append(fns, fn)
					}
				}
			case *types.Var:
				if !obj.IsField() && obj.Pkg() != nil && obj.Parent() != obj.Pkg().Scope() {
					locals = true
				}
			}
		}
		return true
	})
	return fns, typs, locals
}

func (a *analyzer) methodFunc(sel *types.Selection) (fn *ssa.Function) {
	defer func() {
		if recover() != nil {
			fn = nil
		}
	}()
	if m, ok := sel.Obj().(*types.Func); ok && sel.Kind() == types.MethodExpr {
		return a.prog.FuncValue(m.Origin())
	}
	return a.prog.MethodValue(sel)
}

// unitOf returns the declaration a function's source belongs to: a closure
// belongs to its function, a closure in a variable's initializer to the
// variable; wrappers and the package initializer have none.
func (a *analyzer) unitOf(fn *ssa.Function) *unit {
	if fn.Origin() != nil {
		fn = fn.Origin()
	}
	pos := fn.Pos()
	top := fn
	for top.Parent() != nil {
		top = top.Parent()
	}
	if top.Synthetic != "" && top.Synthetic != "package initializer" {
		return nil
	}
	if top.Pkg == nil || !a.inModule(top.Pkg.Pkg) {
		return nil
	}
	if top.Synthetic == "package initializer" && top == fn {
		return nil
	}
	return a.unitAt(pos)
}

// factsOf scans a function's body once.
func (a *analyzer) factsOf(fn *ssa.Function) *facts {
	if f, ok := a.facts[fn]; ok {
		return f
	}
	f := &facts{}
	a.facts[fn] = f
	if len(fn.Blocks) == 0 || !a.scanned(fn) {
		return f
	}
	scan := &factScan{a: a, f: f, initializer: fn.Synthetic == "package initializer"}
	if syn := fn.Syntax(); syn != nil {
		scan.sites = a.siteFuncs[syn]
	}
	for _, b := range fn.Blocks {
		for _, instr := range b.Instrs {
			scan.instr(instr)
		}
	}
	return f
}

// factScan collects the facts of one function's instructions.
type factScan struct {
	a *analyzer
	f *facts
	// initializer: in a package initializer only calls and the values passed
	// to them run; stored values belong to the variables they initialize.
	initializer bool
	sites       []*site
	ops         []*ssa.Value
}

// inSite reports whether pos lies in a registration call of the function.
func (s *factScan) inSite(pos token.Pos) bool {
	for _, st := range s.sites {
		if pos.IsValid() && st.call.Pos() <= pos && pos < st.call.End() {
			return true
		}
	}
	return false
}

func (s *factScan) instr(instr ssa.Instruction) {
	held := s.inSite(instr.Pos())
	var common *ssa.CallCommon
	if call, ok := instr.(ssa.CallInstruction); ok {
		common = call.Common()
		s.call(common)
	}
	if mi, ok := instr.(*ssa.MakeInterface); ok {
		t := mi.X.Type()
		if held || (s.initializer && !usedAsArg(mi)) {
			s.f.heldIfaces = append(s.f.heldIfaces, t)
		} else {
			s.f.ifaces = append(s.f.ifaces, t)
		}
	}
	s.ops = instr.Operands(s.ops[:0])
	for i, op := range s.ops {
		if op == nil || *op == nil || isStaticCallee(common, i, *op) {
			continue
		}
		s.operand(*op, held || (s.initializer && common == nil))
	}
}

func (s *factScan) call(common *ssa.CallCommon) {
	if common.IsInvoke() {
		s.f.invokes = append(s.f.invokes, methodID(common.Method))
	} else if callee := common.StaticCallee(); callee != nil {
		s.f.calls = append(s.f.calls, callee)
		s.a.constraintTypes(callee, s.f)
	}
}

func (s *factScan) operand(v ssa.Value, held bool) {
	switch v := v.(type) {
	case *ssa.Function:
		if held {
			s.f.heldValues = append(s.f.heldValues, v)
		} else {
			s.f.values = append(s.f.values, v)
		}
	case *ssa.Global:
		if s.initializer {
			return
		}
		if u := s.a.unitAt(v.Pos()); u != nil {
			s.f.globals = append(s.f.globals, u)
		}
	}
}

// isStaticCallee reports whether operand i is the function a call names.
func isStaticCallee(common *ssa.CallCommon, i int, op ssa.Value) bool {
	if common == nil || common.IsInvoke() || i != 0 || op != common.Value {
		return false
	}
	_, isFn := common.Value.(*ssa.Function)
	return isFn
}

func usedAsArg(v ssa.Value) bool {
	refs := v.Referrers()
	if refs == nil {
		return false
	}
	for _, r := range *refs {
		if _, ok := r.(ssa.CallInstruction); ok {
			return true
		}
	}
	return false
}

// scanned reports whether a function's body is the module's: its own
// functions and closures, their instances and the wrappers SSA makes.
func (a *analyzer) scanned(fn *ssa.Function) bool {
	if fn.Synthetic != "" && fn.Synthetic != "package initializer" && fn.Parent() == nil && fn.Origin() == nil {
		return true
	}
	top := fn
	if top.Origin() != nil {
		top = top.Origin()
	}
	for top.Parent() != nil {
		top = top.Parent()
	}
	return top.Pkg != nil && a.inModule(top.Pkg.Pkg)
}

// constraintTypes: an instance of a generic function outside the module may
// call methods on its type arguments, through its constraints or after
// converting them to an interface.
func (a *analyzer) constraintTypes(callee *ssa.Function, f *facts) {
	targs := callee.TypeArgs()
	if len(targs) == 0 || a.scanned(callee) {
		return
	}
	// Whatever the constraint, the instance may convert a type argument to
	// an interface (fmt.Sprint(t) in func Show[T any]), and its methods are
	// then called as on any interfaced value.
	f.ifaces = append(f.ifaces, targs...)
}

func methodID(m *types.Func) string {
	if m.Exported() || m.Pkg() == nil {
		return m.Name()
	}
	return m.Pkg().Path() + "." + m.Name()
}

// refsOf returns the types, constants and variables a declaration names.
func (a *analyzer) refsOf(u *unit) []*unit {
	if u.refsDone {
		return u.refs
	}
	u.refsDone = true
	info := u.idx.pkg.TypesInfo
	refs := &refCollector{a: a, u: u, seen: make(map[*unit]bool)}
	ast.Inspect(u.node, func(n ast.Node) bool {
		refs.node(info, n)
		return true
	})
	if u.valueSpec != nil {
		for _, value := range u.valueSpec.Values {
			fns, typs, _ := a.held(info, value, false)
			u.initFuncs = append(u.initFuncs, fns...)
			u.initTypes = append(u.initTypes, typs...)
		}
	}
	return u.refs
}

// refCollector adds to a unit's refs the declarations its syntax names.
type refCollector struct {
	a    *analyzer
	u    *unit
	seen map[*unit]bool
}

func (c *refCollector) add(r *unit) {
	if r != nil && r != c.u && r.kind != funcUnit && !c.seen[r] {
		c.seen[r] = true
		c.u.refs = append(c.u.refs, r)
	}
}

func (c *refCollector) node(info *types.Info, n ast.Node) {
	if e, ok := n.(ast.Expr); ok {
		if tv, ok := info.Types[e]; ok {
			c.typ(tv.Type, 0)
		}
	}
	id, ok := n.(*ast.Ident)
	if !ok {
		return
	}
	if obj, ok := info.Defs[id].(*types.Var); ok {
		c.typ(obj.Type(), 0)
	}
	switch obj := info.Uses[id].(type) {
	case *types.Const, *types.TypeName:
		if c.a.inModule(obj.Pkg()) {
			c.add(c.a.unitAt(obj.Pos()))
		}
	case *types.Var:
		if c.a.inModule(obj.Pkg()) && !obj.IsField() && obj.Parent() == obj.Pkg().Scope() {
			c.add(c.a.unitAt(obj.Pos()))
		}
	}
}

// typ adds the module's named types t is built of.
func (c *refCollector) typ(t types.Type, depth int) {
	if t == nil {
		return
	}
	if depth > maxDepth {
		c.a.whole = append(c.a.whole, fmt.Sprintf("%s: a type nested deeper than %d levels", c.u.key, maxDepth))
		return
	}
	switch t := types.Unalias(t).(type) {
	case *types.Named:
		if c.a.inModule(t.Obj().Pkg()) {
			c.add(c.a.unitAt(t.Origin().Obj().Pos()))
		}
		for t0 := range t.TypeArgs().Types() {
			c.typ(t0, depth+1)
		}
	case *types.Pointer:
		c.typ(t.Elem(), depth+1)
	case *types.Slice:
		c.typ(t.Elem(), depth+1)
	case *types.Array:
		c.typ(t.Elem(), depth+1)
	case *types.Map:
		c.typ(t.Key(), depth+1)
		c.typ(t.Elem(), depth+1)
	case *types.Chan:
		c.typ(t.Elem(), depth+1)
	case *types.Signature:
		c.tuple(t.Params(), depth+1)
		c.tuple(t.Results(), depth+1)
	}
}

func (c *refCollector) tuple(t *types.Tuple, depth int) {
	for v := range t.Variables() {
		c.typ(v.Type(), depth)
	}
}

func (a *analyzer) source(name string) []byte {
	if src, ok := a.sources[name]; ok {
		return src
	}
	src, err := os.ReadFile(name)
	if err != nil {
		src = []byte("unreadable: " + err.Error())
	}
	a.sources[name] = src
	return src
}

// hashOf hashes a declaration's tokens, the import paths it resolves and, for
// a type, the module interfaces it implements; for a variable with go:embed
// the embedded files.
func (a *analyzer) hashOf(u *unit) string {
	if u.hashed {
		return u.hash
	}
	u.hashed = true
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "%s\x00%d\x00", u.idx.pkg.PkgPath, u.kind)
	tf := a.fset.File(u.from)
	src := a.source(tf.Name())
	from, to := tf.Offset(u.from), tf.Offset(u.to)
	var s scanner.Scanner
	fs := token.NewFileSet()
	part := src[from:to]
	s.Init(fs.AddFile("", -1, len(part)), part, nil, 0)
	for {
		_, tok, lit := s.Scan()
		if tok == token.EOF {
			break
		}
		_, _ = fmt.Fprintf(h, "%d %s\x00", tok, lit)
	}
	info := u.idx.pkg.TypesInfo
	var imports []string
	ast.Inspect(u.node, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok {
			if pn, ok := info.Uses[id].(*types.PkgName); ok {
				imports = append(imports, pn.Imported().Path())
			}
		}
		return true
	})
	slices.Sort(imports)
	_, _ = fmt.Fprintf(h, "imports %s\x00", strings.Join(slices.Compact(imports), " "))
	// Comments aside, directives are code: //go:embed names the files a
	// variable holds.
	for _, directive := range a.directives(u) {
		_, _ = fmt.Fprintf(h, "directive %s\x00", directive)
	}
	switch u.kind {
	case typeUnit:
		if tn, ok := info.Defs[u.typeSpec.Name].(*types.TypeName); ok {
			_, _ = fmt.Fprintf(h, "implements %s\x00", strings.Join(a.implements(tn), " "))
		}
	case varUnit:
		for _, file := range a.embedded(u) {
			_, _ = fmt.Fprintf(h, "embed %s\x00", filepath.Base(file))
			h.Write(a.source(file))
		}
	}
	u.hash = hex.EncodeToString(h.Sum(nil))
	return u.hash
}

func (a *analyzer) implements(tn *types.TypeName) []string {
	if _, ok := tn.Type().Underlying().(*types.Interface); ok {
		return nil
	}
	if named, ok := tn.Type().(*types.Named); ok && named.TypeParams().Len() > 0 {
		return nil
	}
	var names []string
	for _, iface := range a.ifaces {
		it, ok := iface.Type().Underlying().(*types.Interface)
		if named, generic := iface.Type().(*types.Named); !ok || (generic && named.TypeParams().Len() > 0) {
			continue
		}
		if types.Implements(tn.Type(), it) || types.Implements(types.NewPointer(tn.Type()), it) {
			names = append(names, iface.Pkg().Path()+"."+iface.Name())
		}
	}
	return names
}

// directives returns the //go: lines of a declaration's doc comments.
func (a *analyzer) directives(u *unit) []string {
	var docs []*ast.CommentGroup
	switch n := u.node.(type) {
	case *ast.FuncDecl:
		docs = append(docs, n.Doc)
	case *ast.GenDecl:
		docs = append(docs, n.Doc)
	case *ast.TypeSpec:
		docs = append(docs, n.Doc, a.genDoc(u))
	case *ast.ValueSpec:
		docs = append(docs, n.Doc, a.genDoc(u))
	}
	var out []string
	for _, doc := range docs {
		if doc == nil {
			continue
		}
		for _, c := range doc.List {
			if strings.HasPrefix(c.Text, "//go:") {
				out = append(out, c.Text)
			}
		}
	}
	return out
}

// genDoc returns the doc of the declaration a spec unit belongs to.
func (a *analyzer) genDoc(u *unit) *ast.CommentGroup {
	for _, decl := range u.idx.file.Decls {
		if gd, ok := decl.(*ast.GenDecl); ok && gd.Pos() <= u.from && u.to <= gd.End() {
			return gd.Doc
		}
	}
	return nil
}

// embedded returns the files a go:embed variable holds: every embedded file
// of its package, a superset of what its patterns match.
func (a *analyzer) embedded(u *unit) []string {
	vs := u.valueSpec
	if vs == nil {
		return nil
	}
	docs := []*ast.CommentGroup{vs.Doc}
	for _, decl := range u.idx.file.Decls {
		if gd, ok := decl.(*ast.GenDecl); ok && gd.Pos() <= vs.Pos() && vs.End() <= gd.End() {
			docs = append(docs, gd.Doc)
		}
	}
	for _, doc := range docs {
		if doc == nil {
			continue
		}
		for _, c := range doc.List {
			if strings.HasPrefix(c.Text, "//go:embed") {
				files := slices.Clone(u.idx.pkg.EmbedFiles)
				slices.Sort(files)
				return files
			}
		}
	}
	return nil
}

// maxDepth bounds the walks over type structure; beyond it every rule is
// keyed by the whole module.
const maxDepth = 1000

func (a *analyzer) isRuleType(t *types.Named) bool {
	return a.ruleTypes[t.Origin().Obj()]
}

// cut reports a function the driver does not follow: a handler of another
// command of the binary.
func (a *analyzer) cut(fn *ssa.Function) bool {
	if fn == a.entry || fn.Pkg != a.command {
		return false
	}
	return types.Identical(fn.Signature, a.entry.Signature)
}

func (a *analyzer) run() (*Result, error) {
	driver := newScope(a, nil)
	driver.driver = true
	if main := a.command.Func("main"); main != nil {
		driver.addFn(main)
	} else {
		return nil, fmt.Errorf("%s has no main", a.cfg.Command)
	}
	driver.addFn(a.command.Func("init"))
	driver.drain()

	all := sha256.New()
	keys := make([]string, 0, len(a.units))
	for _, u := range a.units {
		keys = append(keys, a.hashOf(u))
	}
	slices.Sort(keys)
	for _, k := range keys {
		_, _ = fmt.Fprintln(all, k)
	}
	a.all = hex.EncodeToString(all.Sum(nil))
	driverHash := sha256.Sum256([]byte(driver.hash() + "\n" + a.initOrder()))
	result := &Result{Driver: hex.EncodeToString(driverHash[:]), DriverFuncs: driver.funcKeys(), All: a.all}

	for _, s := range a.sites {
		info := s.idx.pkg.TypesInfo
		s.values, s.types, s.locals = a.held(info, s.call.Args[0], true)
		rule := newScope(a, driver)
		named := registeredType(s.typ)
		if named != nil && !types.IsInterface(named) {
			rule.addMethods(named)
		} else {
			result.Notes = append(result.Notes, fmt.Sprintf("%s:%d: registered value of interface type %s: the rule depends on every rule type", s.file, s.from, s.typ))
			for tn := range a.ruleTypes {
				if ruleType, ok := tn.Type().(*types.Named); ok {
					rule.addMethods(ruleType)
				}
			}
		}
		for _, fn := range s.values {
			rule.addFn(fn)
		}
		for _, t := range s.types {
			rule.iface(t, 0)
		}
		if s.locals {
			if s.open {
				result.Notes = append(result.Notes, fmt.Sprintf("%s:%d: registration outside an initializer passes its own variables: the rule's key is the whole module", s.file, s.from))
				result.Sites = append(result.Sites, Site{File: s.file, From: s.from, To: s.to, Type: typeKey(named), Hash: result.All, Funcs: allFuncKeys(a)})
				continue
			}
			rule.addWhole(a.enclosing(s))
		}
		rule.drain()
		result.Sites = append(result.Sites, Site{File: s.file, From: s.from, To: s.to, Type: typeKey(named), Hash: rule.hash(), Funcs: rule.funcKeys()})
	}
	result.Notes = append(result.Notes, a.notes...)
	if len(a.whole) > 0 {
		// Collected while scopes were built too: checked last.
		result.Notes = append(result.Notes, a.whole...)
		funcs := allFuncKeys(a)
		for i := range result.Sites {
			result.Sites[i].Hash, result.Sites[i].Funcs = result.All, funcs
		}
		return result, nil
	}
	shareLines(result.Sites)
	return result, nil
}

// shareLines merges the keys of sites on a common line: the run tells a
// rule's site by the line Register was called from, and either site may be
// the one it takes. Sites of a file are swept in the order of their first
// line, so a chain of overlaps makes one group.
func shareLines(sites []Site) {
	order := make([]int, len(sites))
	for i := range order {
		order[i] = i
	}
	slices.SortFunc(order, func(i, j int) int {
		if c := strings.Compare(sites[i].File, sites[j].File); c != 0 {
			return c
		}
		return sites[i].From - sites[j].From
	})
	for start := 0; start < len(order); {
		end, to := start+1, sites[order[start]].To
		for end < len(order) && sites[order[end]].File == sites[order[start]].File && sites[order[end]].From <= to {
			to = max(to, sites[order[end]].To)
			end++
		}
		if end-start > 1 {
			mergeSites(sites, order[start:end])
		}
		start = end
	}
}

// mergeSites gives the sites of group one key: the hash of their hashes and
// the union of their functions.
func mergeSites(sites []Site, group []int) {
	var hashes, funcs []string
	for _, k := range group {
		hashes = append(hashes, sites[k].Hash)
		funcs = append(funcs, sites[k].Funcs...)
	}
	slices.Sort(hashes)
	slices.Sort(funcs)
	sum := sha256.Sum256([]byte(strings.Join(hashes, "\n")))
	merged, mergedFuncs := hex.EncodeToString(sum[:]), slices.Compact(funcs)
	for _, k := range group {
		sites[k].Hash, sites[k].Funcs = merged, mergedFuncs
	}
}

// initOrder spells the order packages initialize their variables and run
// their init functions in - by file name, then by place in the file - which
// the sets of declarations the scopes hash lose. Every init function is the
// driver's, and with its source here so is the order; a variable counts when
// its initializer calls module code, the only way its order can show.
func (a *analyzer) initOrder() string {
	byPkg := make(map[string][]*fileIndex)
	for _, idx := range a.files {
		byPkg[idx.pkg.PkgPath] = append(byPkg[idx.pkg.PkgPath], idx)
	}
	var b strings.Builder
	for _, path := range slices.Sorted(maps.Keys(byPkg)) {
		files := byPkg[path]
		sort.Slice(files, func(i, j int) bool { return files[i].key < files[j].key })
		for _, idx := range files {
			for _, decl := range idx.file.Decls {
				a.initStep(&b, idx, decl)
			}
		}
	}
	return b.String()
}

// initStep spells what decl of the file idx adds to the initialization: an
// init function with its hash, or variables whose initializer calls module
// code.
func (a *analyzer) initStep(b *strings.Builder, idx *fileIndex, decl ast.Decl) {
	switch d := decl.(type) {
	case *ast.FuncDecl:
		if d.Recv != nil || d.Name.Name != "init" {
			return
		}
		if u := a.unitAt(d.Pos()); u != nil {
			_, _ = fmt.Fprintf(b, "init %s %s\n", idx.key, a.hashOf(u))
		}
	case *ast.GenDecl:
		if d.Tok != token.VAR {
			return
		}
		for _, spec := range d.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok || !a.callsModule(idx.pkg.TypesInfo, vs) {
				continue
			}
			names := make([]string, 0, len(vs.Names))
			for _, n := range vs.Names {
				names = append(names, n.Name)
			}
			_, _ = fmt.Fprintf(b, "var %s %s\n", idx.key, strings.Join(names, ","))
		}
	}
}

// callsModule reports whether a variable's initializer calls a function of
// the module or a function literal.
func (a *analyzer) callsModule(info *types.Info, vs *ast.ValueSpec) bool {
	found := false
	for _, value := range vs.Values {
		ast.Inspect(value, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || found {
				return !found
			}
			if _, lit := ast.Unparen(call.Fun).(*ast.FuncLit); lit {
				found = true
			} else if fn := calleeFunc(info, call); fn != nil && a.inModule(fn.Pkg()) {
				found = true
			}
			return !found
		})
	}
	return found
}

func allFuncKeys(a *analyzer) []string {
	var keys []string
	for _, u := range a.units {
		if u.kind == funcUnit {
			keys = append(keys, u.key)
		}
	}
	slices.Sort(keys)
	return keys
}

// enclosing returns the SSA function of the syntax around a site.
func (a *analyzer) enclosing(s *site) *ssa.Function {
	switch outer := s.outer.(type) {
	case *ast.FuncLit:
		return a.anon[outer.Type.Func]
	case *ast.FuncDecl:
		info := s.idx.pkg.TypesInfo
		if obj, ok := info.Defs[outer.Name].(*types.Func); ok {
			if fn := a.prog.FuncValue(obj); fn != nil {
				return fn
			}
		}
		// init functions have no object: find them by position.
		sp := a.prog.Package(s.idx.pkg.Types)
		for _, m := range sp.Members {
			if fn, ok := m.(*ssa.Function); ok && fn.Syntax() == outer {
				return fn
			}
		}
	}
	return nil
}

func registeredType(t types.Type) *types.Named {
	if p, ok := types.Unalias(t).(*types.Pointer); ok {
		return registeredType(p.Elem())
	}
	named, _ := types.Unalias(t).(*types.Named)
	return named
}

func typeKey(named *types.Named) string {
	if named == nil || types.IsInterface(named) {
		return ""
	}
	obj := named.Origin().Obj()
	return obj.Pkg().Path() + "." + obj.Name()
}

// scope is the reachable part of the program from some roots. A rule's scope
// extends the driver's: what the driver reaches is not the rule's.
type scope struct {
	a      *analyzer
	base   *scope
	driver bool
	fns    map[*ssa.Function]bool
	units  map[*unit]bool
	ifaced typeutil.Map
	// cutTypes are the rule types the driver converts to an interface: only
	// their registry methods are the driver's.
	cutTypes typeutil.Map
	invoked  map[string]bool
	// methods holds the selections of interfaced types by method id, for
	// an invoke of that name reached later.
	methods map[string][]*types.Selection
	queue   []*ssa.Function
	// reflective: the scope calls code that calls methods by name; every
	// exported method of a type it or its base converts to an interface is
	// reachable.
	reflective bool
}

func newScope(a *analyzer, base *scope) *scope {
	s := &scope{a: a, base: base, fns: make(map[*ssa.Function]bool), units: make(map[*unit]bool),
		invoked: make(map[string]bool), methods: make(map[string][]*types.Selection)}
	hasher := typeutil.MakeHasher()
	s.ifaced.SetHasher(hasher)
	s.cutTypes.SetHasher(hasher)
	return s
}

func (s *scope) hasFn(fn *ssa.Function) bool {
	return s.fns[fn] || (s.base != nil && s.base.hasFn(fn))
}

func (s *scope) hasUnit(u *unit) bool {
	return s.units[u] || (s.base != nil && s.base.hasUnit(u))
}

func (s *scope) isInvoked(id string) bool {
	return s.invoked[id] || (s.base != nil && s.base.isInvoked(id))
}

func (s *scope) isIfaced(t types.Type) bool {
	return s.ifaced.At(t) != nil || (s.base != nil && s.base.isIfaced(t))
}

func (s *scope) addFn(fn *ssa.Function) {
	if fn == nil || s.hasFn(fn) {
		return
	}
	if s.driver && s.a.cut(fn) {
		return
	}
	s.fns[fn] = true
	s.queue = append(s.queue, fn)
}

// addWhole adds a function with everything it holds, the values it passes
// at registration sites too.
func (s *scope) addWhole(fn *ssa.Function) {
	if fn == nil {
		return
	}
	f := s.a.factsOf(fn)
	for _, v := range f.heldValues {
		s.addFn(v)
	}
	for _, t := range f.heldIfaces {
		s.iface(t, 0)
	}
	for _, v := range f.values {
		s.addFn(v)
	}
	for _, g := range f.globals {
		s.addUnit(g)
	}
	for _, anon := range fn.AnonFuncs {
		s.addFn(anon)
	}
}

func (s *scope) drain() {
	for len(s.queue) > 0 {
		fn := s.queue[len(s.queue)-1]
		s.queue = s.queue[:len(s.queue)-1]
		if u := s.a.unitOf(fn); u != nil {
			s.addUnit(u)
		}
		f := s.a.factsOf(fn)
		for _, c := range f.calls {
			s.addFn(c)
			if c.Pkg != nil && (s.a.reflective[c.Pkg.Pkg] || (reflectItself[c.Pkg.Pkg.Path()] && byName[c.Name()])) {
				s.setReflective()
			}
		}
		for _, v := range f.values {
			s.addFn(v)
		}
		for _, id := range f.invokes {
			s.invoke(id)
		}
		for _, t := range f.ifaces {
			s.iface(t, 0)
		}
		for _, g := range f.globals {
			s.addUnit(g)
		}
	}
}

func (s *scope) addUnit(u *unit) {
	if u == nil || s.hasUnit(u) {
		return
	}
	s.units[u] = true
	for _, r := range s.a.refsOf(u) {
		s.addUnit(r)
	}
	if u.kind == varUnit {
		for _, fn := range u.initFuncs {
			s.addFn(fn)
		}
		for _, t := range u.initTypes {
			s.iface(t, 0)
		}
		for _, w := range s.a.writers[u] {
			s.addFn(w)
		}
		for _, alias := range s.a.aliases[u] {
			s.addUnit(alias)
		}
	}
}

func (s *scope) invoke(id string) {
	if s.isInvoked(id) {
		return
	}
	s.invoked[id] = true
	if byName[id] {
		// reflect.Type's Method and MethodByName are called through an
		// interface.
		s.setReflective()
	}
	for sc := s; sc != nil; sc = sc.base {
		for _, sel := range sc.methods[id] {
			s.addFn(s.a.methodFunc(sel))
		}
	}
}

// setReflective makes reachable every exported method of the types the scope
// and its base convert to an interface, and of those it converts later.
func (s *scope) setReflective() {
	if s.reflective {
		return
	}
	s.reflective = true
	for sc := s; sc != nil; sc = sc.base {
		sc.ifaced.Iterate(func(t types.Type, _ any) {
			mset := s.a.msets.MethodSet(types.NewPointer(t))
			for sel := range mset.Methods() {
				if sel.Obj().Exported() {
					s.addFn(s.a.methodFunc(sel))
				}
			}
		})
	}
}

// addMethods adds the methods declared on a rule type, its roots; a
// promoted method is reachable like any method of an interfaced type, when
// something invokes its name.
func (s *scope) addMethods(named *types.Named) {
	mset := s.a.msets.MethodSet(types.NewPointer(named))
	for sel := range mset.Methods() {
		if len(sel.Index()) == 1 {
			s.addFn(s.a.methodFunc(sel))
		}
	}
	s.iface(named, 0)
}

// iface records a type converted to an interface: its methods that can be
// called through one become reachable, and so do the types it holds.
func (s *scope) iface(t types.Type, depth int) {
	if t == nil {
		return
	}
	// Named types stop the walk once seen; only a literal type nested this
	// deep could exceed it, and then the analysis gives up on bounds.
	if depth > maxDepth {
		s.a.whole = append(s.a.whole, fmt.Sprintf("a type nested deeper than %d levels: %s", maxDepth, t))
		return
	}
	switch t := types.Unalias(t).(type) {
	case *types.Pointer:
		s.iface(t.Elem(), depth)
	case *types.Slice:
		s.iface(t.Elem(), depth+1)
	case *types.Array:
		s.iface(t.Elem(), depth+1)
	case *types.Map:
		s.iface(t.Key(), depth+1)
		s.iface(t.Elem(), depth+1)
	case *types.Chan:
		s.iface(t.Elem(), depth+1)
	case *types.Struct:
		for field := range t.Fields() {
			s.iface(field.Type(), depth+1)
		}
	case *types.Named:
		for t0 := range t.TypeArgs().Types() {
			s.iface(t0, depth+1)
		}
		if !s.a.inModule(t.Obj().Pkg()) || types.IsInterface(t) || s.isIfaced(t) {
			return
		}
		if t.TypeParams().Len() > 0 && t.TypeArgs().Len() == 0 {
			return
		}
		cut := s.driver && s.a.isRuleType(t)
		if cut {
			if s.cutTypes.At(t) != nil {
				return
			}
			s.cutTypes.Set(t, true)
		} else {
			s.ifaced.Set(t, true)
		}
		mset := s.a.msets.MethodSet(types.NewPointer(t))
		for sel := range mset.Methods() {
			m, ok := sel.Obj().(*types.Func)
			if !ok {
				continue
			}
			id := methodID(m)
			if cut {
				if s.a.registry[m.Name()] {
					s.addFn(s.a.methodFunc(sel))
				}
				continue
			}
			s.methods[id] = append(s.methods[id], sel)
			if s.isInvoked(id) || (m.Exported() && (s.a.extNames[m.Name()] || s.reflective)) {
				s.addFn(s.a.methodFunc(sel))
			}
		}
		if !cut {
			s.iface(t.Underlying(), depth+1)
		}
		if u := s.a.unitAt(t.Origin().Obj().Pos()); u != nil {
			s.addUnit(u)
		}
	}
}

func (s *scope) hash() string {
	keys := make([]string, 0, len(s.units))
	for u := range s.units {
		keys = append(keys, s.a.hashOf(u))
	}
	slices.Sort(keys)
	h := sha256.New()
	for _, k := range keys {
		_, _ = fmt.Fprintln(h, k)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (s *scope) funcKeys() []string {
	keys := make([]string, 0, len(s.units))
	for u := range s.units {
		if u.kind == funcUnit {
			keys = append(keys, u.key)
		}
	}
	slices.Sort(keys)
	return keys
}
