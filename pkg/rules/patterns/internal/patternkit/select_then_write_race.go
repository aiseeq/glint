package patternkit

import (
	"go/ast"
)

// SendingFunctions returns the names of the file's functions that issue a
// provider command (SendPayout, TransferFunds), directly or through another
// function of the file.
func SendingFunctions(file *ast.File) map[string]bool {
	sends := make(map[string]bool)
	for changed := true; changed; {
		changed = false
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || sends[fn.Name.Name] {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok && SendsCommand(call, sends) {
					sends[fn.Name.Name], changed = true, true
				}
				return !sends[fn.Name.Name]
			})
		}
	}
	return sends
}

// SendsCommand reports a call of a provider command or of a function that
// issues one.
func SendsCommand(call *ast.CallExpr, sends map[string]bool) bool {
	name := CalledFunctionName(call.Fun)
	if _, method := call.Fun.(*ast.SelectorExpr); method && ProviderCommandMethods[name] {
		return true
	}
	return sends[name]
}
