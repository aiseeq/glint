package shellrules

import (
	"bytes"
	"go/ast"
	"go/token"
	"go/types"
	"maps"
	"slices"
	"sync"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/helpers"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
)

const akitProcPath = "github.com/aiseeq/akit/proc"

type processSignalKind uint8

const (
	processSignalNone processSignalKind = iota
	processSignalMethod
	processSignalKill
	processSignalTgkill
)

func processSignalFunction(fn *types.Func) processSignalKind {
	if fn == nil || fn.Pkg() == nil {
		return processSignalNone
	}
	path, name := fn.Pkg().Path(), fn.Name()
	if receiver := patternkit.ReceiverNamed(fn); path == "os" && (name == "Kill" || name == "Signal") && receiver != nil && patternkit.IsNamedType(receiver, "os", "Process") {
		return processSignalMethod
	}
	if path == "syscall" || path == "golang.org/x/sys/unix" {
		return processSignalByName(name)
	}
	return processSignalNone
}

func processSignalByName(name string) processSignalKind {
	switch name {
	case "Kill":
		return processSignalKill
	case "Tgkill":
		return processSignalTgkill
	}
	return processSignalNone
}

// unresolvedImportName is the name fun calls when it is a function of one of
// paths without types: the package did not load, its import spec is known.
func unresolvedImportName(fun ast.Expr, file *ast.File, info *types.Info, paths ...string) string {
	switch f := ast.Unparen(fun).(type) {
	case *ast.SelectorExpr:
		if id, ok := ast.Unparen(f.X).(*ast.Ident); ok {
			if pkg, ok := info.Uses[id].(*types.PkgName); ok && slices.Contains(paths, pkg.Imported().Path()) {
				return f.Sel.Name
			}
		}
	case *ast.Ident:
		if info.Uses[f] != nil {
			return ""
		}
		for _, imp := range patternkit.FileImports(file) {
			if imp.Name == "." && slices.Contains(paths, imp.Path) {
				return f.Name
			}
		}
	}
	return ""
}

func isStopChildCall(call *ast.CallExpr, file *ast.File, info *types.Info) bool {
	return patternkit.IsPkgFunc(info, call, akitProcPath, "StopChild") || unresolvedImportName(call.Fun, file, info, akitProcPath) == "StopChild"
}

// signalSite is a call that sends a signal or a signal function taken as a
// value (args nil); the args of a method follow its receiver.
type signalSite struct {
	node     ast.Expr
	kind     processSignalKind
	args     []ast.Expr
	receiver ast.Expr
	request  bool // inside a request literal passed to proc.StopChild
	info     *types.Info
	self     processAliases
	parent   processAliases
}

func (s signalSite) signal() ast.Expr {
	index := 1
	switch s.kind {
	case processSignalMethod:
		index = 0 // Signal(sig); Kill has none.
	case processSignalTgkill:
		index = 2
	}
	if index < len(s.args) {
		return s.args[index]
	}
	return nil
}

// implicitTarget is the one test both rules share: signal-implicit-target
// reports exactly these sites, raw-process-kill leaves them to it.
func (s signalSite) implicitTarget() bool {
	if harmlessSignal(s.signal(), s.info) {
		return false
	}
	if s.kind == processSignalMethod {
		return pidsFrom(s.receiver, s.info, s.parent.Handles)
	}
	target := func(e ast.Expr) bool { return isTarget(e, s.info, s.parent.PIDs) || isZeroInt(e, s.info) }
	return len(s.args) > 0 && (target(s.args[0]) || s.kind == processSignalTgkill && len(s.args) > 1 && target(s.args[1]))
}

func (s signalSite) toSelf() bool {
	if s.kind == processSignalMethod {
		return pidsFrom(s.receiver, s.info, s.self.Handles)
	}
	return len(s.args) > 0 && (isCurrentProcessID(s.args[0], s.info) || pidsFrom(s.args[0], s.info, s.self.PIDs))
}

// signalPackage is the typed syntax of one package; package-level aliases are
// resolved from the writes in all its files, once.
type signalPackage struct {
	path    string
	info    *types.Info
	files   []*ast.File
	project *signalProject

	once      sync.Once
	self      processAliases
	parent    processAliases
	functions map[types.Object]*types.Func
}

func newSignalPackage(path string, info *types.Info, files ...*ast.File) *signalPackage {
	return &signalPackage{path: path, info: info, files: files}
}

func (p *signalPackage) packageAliases() {
	p.once.Do(func() {
		writes := make(aliasWrites)
		for _, file := range p.files {
			collectAliasWrites(file, p.info, true, writes)
		}
		p.self, p.parent, p.functions = resolveScopeAliases(writes, p.info, processAliases{}, processAliases{}, nil)
	})
}

// functionAliases are the package-level aliases of Kill and Tgkill of every
// package of the run: another package (an external test) calls them too.
func (p *signalPackage) functionAliases() map[types.Object]*types.Func {
	p.packageAliases()
	if p.project == nil {
		return p.functions
	}
	return p.project.functionAliases()
}

type signalProject struct {
	packages  []*signalPackage
	once      sync.Once
	functions map[types.Object]*types.Func
}

func (s *signalProject) add(pkg *signalPackage) *signalPackage {
	pkg.project = s
	s.packages = append(s.packages, pkg)
	return pkg
}

func (s *signalProject) functionAliases() map[types.Object]*types.Func {
	s.once.Do(func() {
		s.functions = make(map[types.Object]*types.Func)
		for _, pkg := range s.packages {
			pkg.packageAliases()
			maps.Copy(s.functions, pkg.functions)
		}
	})
	return s.functions
}

// namesAny reports a name of one of the aliases in content.
func namesAny(content []byte, aliases map[types.Object]*types.Func) bool {
	for obj := range aliases {
		if bytes.Contains(content, []byte(obj.Name())) {
			return true
		}
	}
	return false
}

// calledObject is the variable or function fun names.
func calledObject(fun ast.Expr, info *types.Info) types.Object {
	switch f := ast.Unparen(fun).(type) {
	case *ast.Ident:
		return infoObject(info, f)
	case *ast.SelectorExpr:
		return info.Uses[f.Sel]
	}
	return nil
}

func resolveScopeAliases(writes aliasWrites, info *types.Info, self, parent processAliases, functions map[types.Object]*types.Func) (processAliases, processAliases, map[types.Object]*types.Func) {
	self = resolveProcessAliases(writes, info, isCurrentProcessID, self)
	parent = resolveProcessAliases(writes, info, isParentProcessID, parent)
	functions = maps.Clone(functions)
	if functions == nil {
		functions = make(map[types.Object]*types.Func)
	}
	resolveAliases(writes, functions, func(e ast.Expr) *types.Func { return signalFunctionValue(e, info, functions) })
	return self, parent, functions
}

// signalFunctionValue is syscall or unix Kill or Tgkill used as a value; a
// method value is a site where it is taken, not at its call.
func signalFunctionValue(expr ast.Expr, info *types.Info, aliases map[types.Object]*types.Func) *types.Func {
	obj := calledObject(expr, info)
	if fn := aliases[obj]; fn != nil {
		return fn
	}
	fn, _ := obj.(*types.Func)
	if kind := processSignalFunction(fn); kind != processSignalKill && kind != processSignalTgkill {
		return nil
	}
	return fn
}

// fileSignalSites lists the signal sites of a Go file: in function bodies and
// package-level variable initializers.
func fileSignalSites(file *core.FileContext, pkg *signalPackage) []signalSite {
	if file.GoAST == nil || pkg == nil || pkg.info == nil {
		return nil
	}
	if !bytes.Contains(file.Content, []byte("Kill")) && !bytes.Contains(file.Content, []byte("Signal")) && !bytes.Contains(file.Content, []byte("Tgkill")) && !namesAny(file.Content, pkg.functionAliases()) {
		return nil
	}
	var sites []signalSite
	for _, decl := range file.GoAST.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			if d.Body != nil {
				sites = append(sites, scopeSignalSites(d.Body, file.GoAST, pkg)...)
			}
		case *ast.GenDecl:
			if d.Tok == token.VAR {
				sites = append(sites, scopeSignalSites(d, file.GoAST, pkg)...)
			}
		}
	}
	return sites
}

func scopeSignalSites(scope ast.Node, file *ast.File, pkg *signalPackage) []signalSite {
	info := pkg.info
	writes := make(aliasWrites)
	collectAliasWrites(scope, info, false, writes)
	packageFunctions := pkg.functionAliases()
	self, parent, functions := resolveScopeAliases(writes, info, pkg.self, pkg.parent, packageFunctions)
	requests := stopChildRequestLiterals(scope, file, info)
	site := func(node ast.Expr, kind processSignalKind, args []ast.Expr, receiver ast.Expr) signalSite {
		return signalSite{node: node, kind: kind, args: args, receiver: receiver, request: insideStopChildRequestNode(node, requests), info: info, self: self, parent: parent}
	}
	callFuns := make(map[ast.Expr]bool)
	var sites []signalSite
	ast.Inspect(scope, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		callFuns[call.Fun] = true
		fn := helpers.CalledFunc(call, info)
		kind := processSignalFunction(fn)
		args := call.Args
		var receiver ast.Expr
		if selector, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr); ok && kind == processSignalMethod {
			receiver = selector.X
			if selection := info.Selections[selector]; selection != nil && selection.Kind() == types.MethodExpr && len(args) > 0 {
				receiver, args = args[0], args[1:]
			}
		}
		if kind == processSignalNone {
			kind = processSignalFunction(functions[calledObject(call.Fun, info)])
		}
		if kind == processSignalNone {
			kind = processSignalByName(unresolvedImportName(call.Fun, file, info, "syscall", "golang.org/x/sys/unix"))
		}
		if kind != processSignalNone {
			sites = append(sites, site(call, kind, args, receiver))
		}
		return true
	})
	ast.Inspect(scope, func(n ast.Node) bool {
		selector, ok := n.(*ast.SelectorExpr)
		if !ok || callFuns[selector] {
			return true
		}
		fn, _ := info.Uses[selector.Sel].(*types.Func)
		if kind := processSignalFunction(fn); kind != processSignalNone {
			sites = append(sites, site(selector, kind, nil, selector.X))
		}
		return true
	})
	return sites
}

func stopChildRequestLiterals(scope ast.Node, file *ast.File, info *types.Info) map[*ast.FuncLit]bool {
	requests := map[*ast.FuncLit]bool{}
	ast.Inspect(scope, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || !isStopChildCall(call, file, info) {
			return true
		}
		for _, arg := range call.Args {
			if lit, ok := ast.Unparen(arg).(*ast.FuncLit); ok {
				requests[lit] = true
			}
		}
		return true
	})
	return requests
}

func insideStopChildRequestNode(node ast.Node, requests map[*ast.FuncLit]bool) bool {
	for lit := range requests {
		if node.Pos() >= lit.Pos() && node.End() <= lit.End() {
			return true
		}
	}
	return false
}
