package patterns

import (
	"go/ast"
	"go/token"
	"go/types"
	"maps"
	"slices"
	"strings"

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
//
// hostOf names the third-party URL of a literal, "" for any other: an entry records the address
// it reaches on its own - a literal in its body or in a function it calls, or a package-level
// constant such as defaultURL - so a finding names that address, not the first one the package
// holds.
func liveEntryPoints(pkg *core.GoPackageContext, hostOf func(*ast.BasicLit) string) map[string]liveEntry {
	info := pkg.Package.TypesInfo
	if info == nil || pkg.Package.Types == nil {
		return nil
	}

	decls := packageFuncs(pkg)
	if len(decls) == 0 {
		return nil
	}

	live := make(map[string]bool, len(decls))
	sends := make(map[string]bool, len(decls))
	callees := make(map[string][]string, len(decls))
	for key, fn := range decls {
		if fn.Body == nil {
			continue
		}
		if nodeIssuesHTTPRequest(fn.Body, info) {
			live[key] = true
		}
		if nodeSendsHTTPRequest(fn.Body, info) {
			sends[key] = true
		}
		callees[key] = intraPackageCallees(fn.Body, info, pkg.Package.Types)
	}

	// Транзитивное замыкание: метод, который сам не шлёт запрос, но зовёт того, кто шлёт,
	// для теста ничем не отличается от прямого вызова.
	closeOverCallees(live, callees)
	closeOverCallees(sends, callees)

	liveTypes := liveTypesOf(pkg.Package.Types, live)
	addresses := entryAddresses(decls, callees, info, packageURLs(pkg, hostOf), hostOf)
	entries := map[string]liveEntry{}
	for key, fn := range decls {
		if fn.Recv != nil || !fn.Name.IsExported() {
			continue
		}
		if live[key] || returnsLiveType(fn, info, pkg.Package.Types, live) {
			entry := newLiveEntry(fn, info, liveTypes)
			methodKeys := returnedLiveMethods(fn, info, pkg.Package.Types, live)
			// Конструктор, собравший &http.Client{}, сам ничего не шлёт: шлют методы клиента.
			entry.direct = sends[key] && len(methodKeys) == 0
			entry.liveMethods = map[string]bool{}
			entry.address = addresses[key]
			for _, methodKey := range methodKeys {
				_, method, _ := strings.Cut(methodKey, ".")
				entry.liveMethods[method] = true
				if entry.address == "" {
					entry.address = addresses[methodKey]
				}
			}
			entries[fn.Name.Name] = entry
		}
	}
	if len(entries) == 0 {
		return nil
	}
	return entries
}

// liveEntry is an exported function through which a test reaches the wire.
type liveEntry struct {
	// transport marks the parameters that hand the function its connection: an HTTP
	// client or round tripper, a type of this package whose methods reach the network,
	// or an interface such a type implements. A nil passed there leaves the function
	// nothing to send with — that is how tests build a real service for its database
	// logic. A nil anywhere else (options, a callback, a context) sends all the same.
	transport []bool
	variadic  bool
	// direct marks a function that reaches an HTTP call itself; otherwise the entry is a
	// constructor of a client whose liveMethods do.
	direct      bool
	liveMethods map[string]bool
	// address is the third-party URL the entry reaches on its own, "" when the address
	// comes from the caller.
	address string
}

// nilTransport reports whether the call passes nil in place of a transport parameter.
func (e liveEntry) nilTransport(call *ast.CallExpr) bool {
	for i, arg := range call.Args {
		ident, ok := arg.(*ast.Ident)
		if !ok || ident.Name != "nil" {
			continue
		}
		idx := i
		if idx >= len(e.transport) {
			if !e.variadic || len(e.transport) == 0 {
				continue
			}
			idx = len(e.transport) - 1
		}
		if e.transport[idx] {
			return true
		}
	}
	return false
}

// newLiveEntry reads the entry's parameters from its type-checked signature.
func newLiveEntry(fn *ast.FuncDecl, info *types.Info, liveTypes []*types.Named) liveEntry {
	obj, ok := info.Defs[fn.Name].(*types.Func)
	if !ok {
		return liveEntry{}
	}
	signature, ok := obj.Type().(*types.Signature)
	if !ok {
		return liveEntry{}
	}
	params := signature.Params()
	entry := liveEntry{transport: make([]bool, params.Len()), variadic: signature.Variadic()}
	for i := 0; i < params.Len(); i++ {
		entry.transport[i] = isTransportType(params.At(i).Type(), liveTypes)
	}
	return entry
}

// liveTypesOf returns the package's named types that have a method reaching the network.
func liveTypesOf(self *types.Package, live map[string]bool) []*types.Named {
	seen := map[string]bool{}
	var named []*types.Named
	for _, key := range slices.Sorted(maps.Keys(live)) {
		typeName, _, isMethod := strings.Cut(key, ".")
		if !live[key] || !isMethod || seen[typeName] {
			continue
		}
		seen[typeName] = true
		if obj, ok := self.Scope().Lookup(typeName).(*types.TypeName); ok {
			if n, ok := obj.Type().(*types.Named); ok {
				named = append(named, n)
			}
		}
	}
	return named
}

// isTransportType reports whether a parameter of this type carries the connection.
func isTransportType(typ types.Type, liveTypes []*types.Named) bool {
	if named := namedOf(typ); named != nil {
		if named.Obj().Pkg().Path() == netHTTPPath {
			switch named.Obj().Name() {
			case "Client", "Transport", "RoundTripper":
				return true
			}
		}
		for _, lt := range liveTypes {
			if types.Identical(named, lt) {
				return true
			}
		}
	}
	iface, ok := typ.Underlying().(*types.Interface)
	if !ok || iface.NumMethods() == 0 {
		return false
	}
	for _, lt := range liveTypes {
		if types.Implements(lt, iface) || types.Implements(types.NewPointer(lt), iface) {
			return true
		}
	}
	return false
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

// packageURLs maps the package-level constants and variables holding a third-party URL to it:
// const defaultURL = "https://feed.vendor.io".
func packageURLs(pkg *core.GoPackageContext, hostOf func(*ast.BasicLit) string) map[types.Object]string {
	urls := map[types.Object]string{}
	for _, file := range pkg.Files {
		if file == nil || file.GoAST == nil || file.IsTestFile() {
			continue
		}
		for _, decl := range file.GoAST.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || (gen.Tok != token.CONST && gen.Tok != token.VAR) {
				continue
			}
			for _, spec := range gen.Specs {
				value, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, name := range value.Names {
					if i >= len(value.Values) {
						break
					}
					if host := literalHost(value.Values[i], hostOf); host != "" && pkg.Package.TypesInfo.Defs[name] != nil {
						urls[pkg.Package.TypesInfo.Defs[name]] = host
					}
				}
			}
		}
	}
	return urls
}

// literalHost returns the first third-party URL among the literals of an expression.
func literalHost(node ast.Node, hostOf func(*ast.BasicLit) string) string {
	var host string
	ast.Inspect(node, func(n ast.Node) bool {
		if lit, ok := n.(*ast.BasicLit); ok && host == "" {
			host = hostOf(lit)
		}
		return host == ""
	})
	return host
}

// entryAddresses returns the third-party URL each function reaches on its own: a literal in its
// body, a package-level URL it reads, or the address of a package function it calls.
func entryAddresses(
	decls map[string]*ast.FuncDecl, callees map[string][]string, info *types.Info,
	urls map[types.Object]string, hostOf func(*ast.BasicLit) string,
) map[string]string {
	addresses := map[string]string{}
	for key, fn := range decls {
		if fn.Body == nil {
			continue
		}
		host := literalHost(fn.Body, hostOf)
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if ident, ok := n.(*ast.Ident); ok && host == "" {
				host = urls[info.Uses[ident]]
			}
			return host == ""
		})
		if host != "" {
			addresses[key] = host
		}
	}
	for changed := true; changed; {
		changed = false
		for _, key := range slices.Sorted(maps.Keys(callees)) {
			if addresses[key] != "" {
				continue
			}
			for _, target := range callees[key] {
				if addresses[target] != "" {
					addresses[key] = addresses[target]
					changed = true
					break
				}
			}
		}
	}
	return addresses
}

// returnedLiveMethods returns the methods reaching the network ("Type.Method", sorted) of the
// package's types the function returns.
func returnedLiveMethods(fn *ast.FuncDecl, info *types.Info, self *types.Package, live map[string]bool) []string {
	obj, ok := info.Defs[fn.Name].(*types.Func)
	if !ok {
		return nil
	}
	signature, ok := obj.Type().(*types.Signature)
	if !ok || signature.Results() == nil {
		return nil
	}
	var methods []string
	for i := 0; i < signature.Results().Len(); i++ {
		named := namedOf(signature.Results().At(i).Type())
		if named == nil || named.Obj().Pkg() != self {
			continue
		}
		for j := 0; j < named.NumMethods(); j++ {
			if key := named.Obj().Name() + "." + named.Method(j).Name(); live[key] {
				methods = append(methods, key)
			}
		}
	}
	slices.Sort(methods)
	return methods
}

// closeOverCallees marks every function that calls a marked one, transitively.
func closeOverCallees(marked map[string]bool, callees map[string][]string) {
	for changed := true; changed; {
		changed = false
		for key, targets := range callees {
			if marked[key] {
				continue
			}
			for _, target := range targets {
				if marked[target] {
					marked[key] = true
					changed = true
					break
				}
			}
		}
	}
}
