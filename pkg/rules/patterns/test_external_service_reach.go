package patterns

import (
	"go/ast"
	"go/types"

	"github.com/aiseeq/glint/pkg/core"
)

// liveEntryPoints returns the exported functions of an outbound package through which a test
// actually gets to the wire.
//
// Without this, the whole package is one lump and every call into it is reported. ProjectA's
// cryptoprov package holds both the signing HTTP client and a plain config reader, and a test that
// builds the deposit service with a nil transport to check database writes was flagged twice —
// it sends nothing. A rule that cries on such tests gets switched off, and then the tests that
// really do burn provider requisites go unnoticed too.
//
// Two kinds of function qualify:
//
//   - it reaches an HTTP call through calls inside its own package;
//   - it returns a type of this package whose job is that service — most of its exported
//     methods reach the network. Such a client is worth reporting at construction: it has no
//     offline mode, so whatever the test does with it afterwards ends up on somebody's server,
//     and it is routinely handed to another package that calls it (ProjectA's vault test passes the
//     ExtVault client into the snapshot scheduler).
//
// The majority is what keeps a fat service out. ProjectB keeps its whole domain in one
// package, and DeFiPositionService — ten repository-backed methods, one of which eventually
// asks DefiLlama for a price — was reported in 24 tests that only exercise linking logic
// against a local database.
func liveEntryPoints(pkg *core.GoPackageContext) map[string]bool {
	info := pkg.Package.TypesInfo
	if info == nil || pkg.Package.Types == nil {
		return nil
	}

	decls := packageFuncs(pkg)
	if len(decls) == 0 {
		return nil
	}

	live := make(map[string]bool, len(decls))
	callees := make(map[string][]string, len(decls))
	for key, fn := range decls {
		if fn.Body == nil {
			continue
		}
		if nodeIssuesHTTPRequest(fn.Body, info) {
			live[key] = true
		}
		callees[key] = intraPackageCallees(fn.Body, info, pkg.Package.Types)
	}

	// Транзитивное замыкание: метод, который сам не шлёт запрос, но зовёт того, кто шлёт,
	// для теста ничем не отличается от прямого вызова.
	for changed := true; changed; {
		changed = false
		for key, targets := range callees {
			if live[key] {
				continue
			}
			for _, target := range targets {
				if live[target] {
					live[key] = true
					changed = true
					break
				}
			}
		}
	}

	entries := map[string]bool{}
	for key, fn := range decls {
		if fn.Recv != nil || !fn.Name.IsExported() {
			continue
		}
		if live[key] || returnsLiveType(fn, info, pkg.Package.Types, live) {
			entries[fn.Name.Name] = true
		}
	}
	if len(entries) == 0 {
		return nil
	}
	return entries
}

// packageFuncs indexes the package's own functions: "Func" for plain ones, "Type.Method" for methods.
func packageFuncs(pkg *core.GoPackageContext) map[string]*ast.FuncDecl {
	decls := map[string]*ast.FuncDecl{}
	for _, file := range pkg.Files {
		if file == nil || file.GoAST == nil || file.IsTestFile() {
			continue
		}
		for _, decl := range file.GoAST.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Name == nil {
				continue
			}
			key := fn.Name.Name
			if fn.Recv != nil {
				recv := receiverTypeName(fn.Recv)
				if recv == "" {
					continue
				}
				key = recv + "." + fn.Name.Name
			}
			decls[key] = fn
		}
	}
	return decls
}

// receiverTypeName renders the bare type name of a method receiver, pointer or not.
func receiverTypeName(recv *ast.FieldList) string {
	if recv == nil || len(recv.List) == 0 {
		return ""
	}
	expr := recv.List[0].Type
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = star.X
	}
	if index, ok := expr.(*ast.IndexExpr); ok { // обобщённый тип: Cache[T]
		expr = index.X
	}
	if index, ok := expr.(*ast.IndexListExpr); ok {
		expr = index.X
	}
	ident, ok := expr.(*ast.Ident)
	if !ok {
		return ""
	}
	return ident.Name
}

// intraPackageCallees lists the package's own functions and methods called from the body.
func intraPackageCallees(body *ast.BlockStmt, info *types.Info, self *types.Package) []string {
	var callees []string
	seen := map[string]bool{}
	add := func(key string) {
		if key == "" || seen[key] {
			return
		}
		seen[key] = true
		callees = append(callees, key)
	}

	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch fun := call.Fun.(type) {
		case *ast.Ident:
			if fnObj, ok := info.Uses[fun].(*types.Func); ok && fnObj.Pkg() == self {
				add(fnObj.Name())
			}
		case *ast.SelectorExpr:
			if selection, ok := info.Selections[fun]; ok && selection.Kind() == types.MethodVal {
				if named := namedOf(selection.Recv()); named != nil && named.Obj().Pkg() == self {
					add(named.Obj().Name() + "." + fun.Sel.Name)
				}
				return true
			}
			if fnObj, ok := info.Uses[fun.Sel].(*types.Func); ok && fnObj.Pkg() == self {
				add(fnObj.Name())
			}
		}
		return true
	})
	return callees
}

// returnsLiveType reports whether the function hands back a client of this package dedicated to
// the outside service — one whose exported methods are mostly network calls.
func returnsLiveType(fn *ast.FuncDecl, info *types.Info, self *types.Package, live map[string]bool) bool {
	obj, ok := info.Defs[fn.Name].(*types.Func)
	if !ok || obj.Type() == nil {
		return false
	}
	signature, ok := obj.Type().(*types.Signature)
	if !ok || signature.Results() == nil {
		return false
	}
	for i := 0; i < signature.Results().Len(); i++ {
		named := namedOf(signature.Results().At(i).Type())
		if named == nil || named.Obj().Pkg() != self {
			continue
		}
		var exported, liveCount int
		for i := 0; i < named.NumMethods(); i++ {
			method := named.Method(i)
			if !method.Exported() {
				continue
			}
			exported++
			if live[named.Obj().Name()+"."+method.Name()] {
				liveCount++
			}
		}
		if liveCount > 0 && liveCount*2 > exported {
			return true
		}
	}
	return false
}

// namedOf unwraps pointers and returns the named type, if any.
func namedOf(typ types.Type) *types.Named {
	if ptr, ok := typ.(*types.Pointer); ok {
		typ = ptr.Elem()
	}
	named, ok := typ.(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil {
		return nil
	}
	return named
}
