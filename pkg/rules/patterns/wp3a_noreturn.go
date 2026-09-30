package patterns

import (
	"go/ast"
	"go/types"
	"path"
	"strings"
)

// noReturnKind says whether a call returns to its caller and, if not, whether
// the deferred calls of the goroutine still run.
type noReturnKind int

const (
	// callReturns: an ordinary call, or one the helper cannot resolve.
	callReturns noReturnKind = iota
	// callUnwinds: the call never returns but unwinds the goroutine, so its
	// deferred calls run — panic, runtime.Goexit, log.Panic*, and the
	// testing Fatal*/FailNow/Skip* methods (they call runtime.Goexit).
	callUnwinds
	// callExits: the call ends the process without running deferred calls —
	// os.Exit and log.Fatal*.
	callExits
)

// noReturnPackageFuncs lists the package-level functions that never return,
// by import path and name.
var noReturnPackageFuncs = map[string]map[string]noReturnKind{
	"os":      {"Exit": callExits},
	"runtime": {"Goexit": callUnwinds},
	"log": {
		"Fatal": callExits, "Fatalf": callExits, "Fatalln": callExits,
		"Panic": callUnwinds, "Panicf": callUnwinds, "Panicln": callUnwinds,
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
func callNoReturn(call *ast.CallExpr, info *types.Info, file *ast.File) noReturnKind {
	if call == nil {
		return callReturns
	}
	fun := ast.Unparen(call.Fun)
	if info != nil {
		return typedCallNoReturn(fun, info)
	}
	switch node := fun.(type) {
	case *ast.Ident:
		if node.Name == "panic" {
			return callUnwinds
		}
	case *ast.SelectorExpr:
		qualifier, ok := node.X.(*ast.Ident)
		if !ok {
			return callReturns
		}
		importPath, ok := fileImportPath(file, qualifier.Name)
		if !ok {
			return callReturns
		}
		return noReturnPackageFuncs[importPath][node.Sel.Name]
	}
	return callReturns
}

// stmtNoReturn classifies an expression statement whose call never returns.
func stmtNoReturn(stmt ast.Stmt, info *types.Info, file *ast.File) noReturnKind {
	expr, ok := stmt.(*ast.ExprStmt)
	if !ok {
		return callReturns
	}
	call, ok := ast.Unparen(expr.X).(*ast.CallExpr)
	if !ok {
		return callReturns
	}
	return callNoReturn(call, info, file)
}

func typedCallNoReturn(fun ast.Expr, info *types.Info) noReturnKind {
	var ident *ast.Ident
	switch node := fun.(type) {
	case *ast.Ident:
		ident = node
	case *ast.SelectorExpr:
		ident = node.Sel
	default:
		return callReturns
	}
	switch obj := info.Uses[ident].(type) {
	case *types.Builtin:
		if obj.Name() == "panic" {
			return callUnwinds
		}
	case *types.Func:
		return funcNoReturn(obj)
	}
	return callReturns
}

func funcNoReturn(fn *types.Func) noReturnKind {
	if fn.Pkg() == nil {
		return callReturns
	}
	pkgPath := fn.Pkg().Path()
	sig, ok := fn.Type().(*types.Signature)
	if !ok {
		return callReturns
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
			return callUnwinds
		}
	}
	return callReturns
}

// fileImportPath resolves a package qualifier through the file's imports.
func fileImportPath(file *ast.File, qualifier string) (string, bool) {
	if file == nil {
		return "", false
	}
	for _, spec := range file.Imports {
		// The parser only accepts string literals here, quoted or raw.
		importPath := strings.Trim(spec.Path.Value, "\"`")
		// Only the std packages above are looked up, and their package name
		// is the last path element.
		name := path.Base(importPath)
		if spec.Name != nil {
			name = spec.Name.Name
		}
		if name == qualifier {
			return importPath, true
		}
	}
	return "", false
}
