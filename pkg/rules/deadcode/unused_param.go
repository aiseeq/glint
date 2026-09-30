package deadcode

import (
	"errors"
	"go/ast"
	"go/types"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewUnusedParamRule())
}

// UnusedParamRule detects function parameters that are never used.
//
// A parameter is used when an identifier in the body resolves to it — a field
// or a composite-literal key spelled the same is a different object. The
// signature of some functions is not theirs to choose, so they are left out:
// a method whose name and signature match a method of an interface the
// project can see (its own packages and everything they import — http.Handler,
// io.Writer, sort.Interface), and a function or method used as a value
// (passed to HandleFunc, stored in a table), whose type the receiving side
// dictates.
type UnusedParamRule struct {
	*rules.BaseRule
}

// NewUnusedParamRule creates the rule
func NewUnusedParamRule() *UnusedParamRule {
	return &UnusedParamRule{
		BaseRule: rules.NewBaseRule(
			"unused-param",
			"deadcode",
			"Detects function parameters that are never used in the function body, except where an interface or a function-typed use fixes the signature",
			core.SeverityLow,
		),
	}
}

// AnalyzeFile checks one file without type information: the fallback for
// files no type-checked package covers. Without types an identifier cannot be
// tied to the parameter it may or may not denote, so the rule stays silent.
func (r *UnusedParamRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	return r.analyze(ctx, nil, nil)
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *UnusedParamRule) RequiresSSA() bool { return false }

// fixedSignatures holds what the project knows about signatures a function
// does not choose: interface methods by name, and the functions used as values.
type fixedSignatures struct {
	interfaceMethods map[string][]*types.Func
	funcValues       map[*types.Func]bool
}

// AnalyzeGoProject checks every file with the interfaces and function values
// of the whole project in view.
func (r *UnusedParamRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, errors.New("unused param: nil Go project context")
	}
	fixed, err := core.SharedLoad(ctx, fixedSignaturesKey{}, func() (*fixedSignatures, error) {
		return collectFixedSignatures(ctx)
	})
	if err != nil {
		return nil, err
	}
	return rules.AnalyzeGoFiles(ctx, r.Name(), func(fileCtx *core.FileContext, info *types.Info) []*core.Violation {
		return r.analyze(fileCtx, info, fixed)
	})
}

// fixedSignaturesKey caches the signatures fixed by interfaces and function
// values once per module load: they depend only on the loaded packages.
type fixedSignaturesKey struct{}

func collectFixedSignatures(ctx *core.GoProjectContext) (*fixedSignatures, error) {
	fixed := &fixedSignatures{
		interfaceMethods: make(map[string][]*types.Func),
		funcValues:       make(map[*types.Func]bool),
	}
	seen := make(map[*types.Package]bool)
	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil || pkg.Package.TypesInfo == nil || pkg.Package.Types == nil {
			return nil, errors.New("unused param: package has no typed syntax")
		}
		fixed.addInterfaces(pkg.Package.Types, seen)
		for _, file := range pkg.Package.Syntax {
			fixed.addFuncValues(file, pkg.Package.TypesInfo)
		}
	}
	return fixed, nil
}

// addInterfaces indexes the methods of the named interfaces declared in a
// package and in everything it imports, transitively.
func (f *fixedSignatures) addInterfaces(pkg *types.Package, seen map[*types.Package]bool) {
	if pkg == nil || seen[pkg] {
		return
	}
	seen[pkg] = true
	scope := pkg.Scope()
	for _, name := range scope.Names() {
		typeName, ok := scope.Lookup(name).(*types.TypeName)
		if !ok {
			continue
		}
		iface, ok := typeName.Type().Underlying().(*types.Interface)
		if !ok {
			continue
		}
		for i := range iface.NumMethods() {
			method := iface.Method(i)
			f.interfaceMethods[method.Name()] = append(f.interfaceMethods[method.Name()], method)
		}
	}
	for _, imported := range pkg.Imports() {
		f.addInterfaces(imported, seen)
	}
}

// addFuncValues records the functions and methods a file uses other than by
// calling them: passed as an argument, assigned, stored in a literal.
func (f *fixedSignatures) addFuncValues(file *ast.File, info *types.Info) {
	callees := make(map[*ast.Ident]bool)
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if ident := calleeIdent(call.Fun); ident != nil {
			callees[ident] = true
		}
		return true
	})
	for ident, obj := range info.Uses {
		fn, ok := obj.(*types.Func)
		if !ok || callees[ident] {
			continue
		}
		f.funcValues[fn.Origin()] = true
	}
}

// calleeIdent returns the identifier naming the function a call invokes.
func calleeIdent(fun ast.Expr) *ast.Ident {
	switch f := ast.Unparen(fun).(type) {
	case *ast.Ident:
		return f
	case *ast.SelectorExpr:
		return f.Sel
	case *ast.IndexExpr:
		return calleeIdent(f.X)
	case *ast.IndexListExpr:
		return calleeIdent(f.X)
	}
	return nil
}

// signatureIsFixed reports whether fn must keep its signature regardless of
// what its body uses.
func (f *fixedSignatures) signatureIsFixed(fn *types.Func) bool {
	if f.funcValues[fn] {
		return true
	}
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return false
	}
	candidates := f.interfaceMethods[fn.Name()]
	if len(candidates) == 0 {
		return false
	}
	// A generic receiver's method mentions type parameters an interface
	// method cannot; matching it would be guessing, so a same-named interface
	// method is enough to stay silent.
	if sig.RecvTypeParams().Len() > 0 {
		return true
	}
	for _, method := range candidates {
		if types.Identical(sig, method.Type()) {
			return true
		}
	}
	return false
}

// analyze reports the unused parameters of one file's functions. info and
// fixed are nil for a file without type information.
func (r *UnusedParamRule) analyze(ctx *core.FileContext, info *types.Info, fixed *fixedSignatures) []*core.Violation {
	if info == nil || fixed == nil || !ctx.IsGoFile() || ctx.GoAST == nil || ctx.IsTestFile() {
		return nil
	}

	var violations []*core.Violation
	for _, decl := range ctx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || fn.Type.Params == nil {
			continue
		}
		if fn.Recv == nil && (fn.Name.Name == "main" || fn.Name.Name == "init") {
			continue
		}
		obj, ok := info.Defs[fn.Name].(*types.Func)
		if !ok || fixed.signatureIsFixed(obj) {
			continue
		}

		used := usedObjects(fn.Body, info)
		for _, field := range fn.Type.Params.List {
			for _, name := range field.Names {
				param := info.Defs[name]
				if name.Name == "_" || param == nil || used[param] {
					continue
				}
				line := ctx.LineFor(name)
				v := r.CreateViolation(ctx.RelPath, line, "Parameter '"+name.Name+"' is never used")
				v.WithCode(ctx.GetLine(line))
				v.WithSuggestion("Remove parameter or use _ if required by interface")
				v.WithContext("param", name.Name)
				violations = append(violations, v)
			}
		}
	}
	return violations
}

// usedObjects returns the objects the identifiers of a body refer to.
func usedObjects(body *ast.BlockStmt, info *types.Info) map[types.Object]bool {
	used := make(map[types.Object]bool)
	ast.Inspect(body, func(n ast.Node) bool {
		if ident, ok := n.(*ast.Ident); ok {
			if obj := info.Uses[ident]; obj != nil {
				used[obj] = true
			}
		}
		return true
	})
	return used
}
