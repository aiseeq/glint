package patternkit

import (
	"go/ast"
	"go/types"
)

// NoReturnKind says whether a call returns to its caller and, if not, whether
// the deferred calls of the goroutine still run.
type NoReturnKind int

const (
	// CallReturns: an ordinary call, or one the helper cannot resolve.
	CallReturns NoReturnKind = iota
	// CallUnwinds: the call never returns but unwinds the goroutine, so its
	// deferred calls run — panic, runtime.Goexit, log.Panic*, and the
	// testing Fatal*/FailNow/Skip* methods (they call runtime.Goexit).
	CallUnwinds
	// CallExits: the call ends the process without running deferred calls —
	// os.Exit and log.Fatal*.
	CallExits
)

// noReturnPackageFuncs lists the package-level functions that never return,
// by import path and name.
var noReturnPackageFuncs = map[string]map[string]NoReturnKind{
	"os":      {"Exit": CallExits},
	"runtime": {"Goexit": CallUnwinds},
	"log": {
		"Fatal": CallExits, "Fatalf": CallExits, "Fatalln": CallExits,
		"Panic": CallUnwinds, "Panicf": CallUnwinds, "Panicln": CallUnwinds,
	},
}

// noReturnTestingMethods lists the testing methods that stop the test
// goroutine through runtime.Goexit.
var noReturnTestingMethods = map[string]bool{
	"Fatal": true, "Fatalf": true, "FailNow": true,
	"Skip": true, "Skipf": true, "SkipNow": true,
}

// callNoReturn classifies a call that never returns to its caller.
//
// With type information the callee is resolved through its object: the
// builtin panic, the package functions above, the Fatal*/Panic* methods of
// *log.Logger and the stopping methods of testing.T/B/F/TB. Without it (info
// is nil) only what the file itself resolves is recognised: the builtin panic
// by name and the package functions through the file's imports; methods are
// left unknown and reported as returning.
func callNoReturn(call *ast.CallExpr, info *types.Info, file *ast.File) NoReturnKind {
	if call == nil {
		return CallReturns
	}
	fun := ast.Unparen(call.Fun)
	if info != nil {
		return typedCallNoReturn(fun, info)
	}
	switch node := fun.(type) {
	case *ast.Ident:
		if node.Name == "panic" {
			return CallUnwinds
		}
	case *ast.SelectorExpr:
		qualifier, ok := node.X.(*ast.Ident)
		if !ok {
			return CallReturns
		}
		importPath, ok := FileImportPath(file, qualifier.Name)
		if !ok {
			return CallReturns
		}
		return noReturnPackageFuncs[importPath][node.Sel.Name]
	}
	return CallReturns
}

// StmtNoReturn classifies an expression statement whose call never returns.
func StmtNoReturn(stmt ast.Stmt, info *types.Info, file *ast.File) NoReturnKind {
	expr, ok := stmt.(*ast.ExprStmt)
	if !ok {
		return CallReturns
	}
	call, ok := ast.Unparen(expr.X).(*ast.CallExpr)
	if !ok {
		return CallReturns
	}
	return callNoReturn(call, info, file)
}

func typedCallNoReturn(fun ast.Expr, info *types.Info) NoReturnKind {
	var ident *ast.Ident
	switch node := fun.(type) {
	case *ast.Ident:
		ident = node
	case *ast.SelectorExpr:
		ident = node.Sel
	default:
		return CallReturns
	}
	switch obj := info.Uses[ident].(type) {
	case *types.Builtin:
		if obj.Name() == "panic" {
			return CallUnwinds
		}
	case *types.Func:
		return funcNoReturn(obj)
	}
	return CallReturns
}

func funcNoReturn(fn *types.Func) NoReturnKind {
	if fn.Pkg() == nil {
		return CallReturns
	}
	pkgPath := fn.Pkg().Path()
	sig, ok := fn.Type().(*types.Signature)
	if !ok {
		return CallReturns
	}
	if sig.Recv() == nil {
		return noReturnPackageFuncs[pkgPath][fn.Name()]
	}
	switch pkgPath {
	case "log":
		// (*log.Logger).Fatal* and Panic* behave like the package functions.
		return noReturnPackageFuncs["log"][fn.Name()]
	case "testing":
		// Methods of T, B, F, the TB interface and the embedded common type.
		if noReturnTestingMethods[fn.Name()] {
			return CallUnwinds
		}
	}
	return CallReturns
}

// FileImportPath resolves a package qualifier through the file's imports.
func FileImportPath(file *ast.File, qualifier string) (string, bool) {
	if file == nil {
		return "", false
	}
	// Only the std packages above are looked up, and their package name is
	// the last path element.
	for _, imp := range FileImports(file) {
		if imp.Name == qualifier {
			return imp.Path, true
		}
	}
	return "", false
}
