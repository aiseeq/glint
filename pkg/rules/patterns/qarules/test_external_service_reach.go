package qarules

import (
	"go/ast"
	"go/token"
	"go/types"
	"maps"
	"slices"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/helpers"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
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
// package, and LedgerService — ten repository-backed methods, one of which eventually
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

	decls := patternkit.PackageFuncs(pkg)
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
	urls := packageURLs(pkg, hostOf)
	fieldURLs := packageFieldURLs(pkg, urls, hostOf)
	addresses := entryAddresses(decls, callees, info, urls, fieldURLs, hostOf, live, pkg.Package.Types)
	entries := map[string]liveEntry{}
	for key, fn := range decls {
		if fn.Recv != nil || !fn.Name.IsExported() {
			continue
		}
		if live[key] || returnsLiveType(fn, info, pkg.Package.Types, live) {
			entry := newLiveEntry(fn, info, liveTypes)
			methodKeys := returnedLiveMethods(fn, info, pkg.Package.Types, live)
			// Если тело конструктора само доходит до отправки, вызов конструктора живой,
			// даже когда оно также возвращает тип с сетевыми методами.
			entry.direct = sends[key]
			entry.liveMethods = map[string]bool{}
			entry.resultIndexes = namedResultIndexes(fn, info)
			entry.knownMembers = returnedClientMembers(fn, info)
			entry.selfMethods = returnedSelfMethods(fn, info)
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
	direct        bool
	liveMethods   map[string]bool
	resultIndexes map[int]bool
	// address is the third-party URL the entry reaches on its own, "" when the address
	// comes from the caller.
	address string
	// knownMembers are methods and fields on returned client types, used to distinguish
	// local inspection from an unknown use when test-file type information is unavailable.
	knownMembers map[string]bool
	// selfMethods are methods of a returned client type that hand back that type
	// (builders: New().WithKey(k)), so their result is the client again.
	selfMethods map[string]bool
}

func namedResultIndexes(fn *ast.FuncDecl, info *types.Info) map[int]bool {
	indexes := map[int]bool{}
	obj, ok := info.Defs[fn.Name].(*types.Func)
	if !ok {
		return indexes
	}
	sig, ok := obj.Type().(*types.Signature)
	if !ok || sig.Results() == nil {
		return indexes
	}
	for i := range sig.Results().Len() {
		v := sig.Results().At(i)
		if patternkit.NamedOf(v.Type()) != nil {
			indexes[i] = true
		}
	}
	return indexes
}

func returnedClientMembers(fn *ast.FuncDecl, info *types.Info) map[string]bool {
	members := map[string]bool{}
	obj, ok := info.Defs[fn.Name].(*types.Func)
	if !ok {
		return members
	}
	sig, ok := obj.Type().(*types.Signature)
	if !ok || sig.Results() == nil {
		return members
	}
	for v := range sig.Results().Variables() {
		named := patternkit.NamedOf(v.Type())
		if named == nil {
			continue
		}
		for _, recv := range []types.Type{named, types.NewPointer(named)} {
			set := types.NewMethodSet(recv)
			for method := range set.Methods() {
				members[method.Obj().Name()] = true
			}
		}
		underlying := named.Underlying()
		if ptr, ok := underlying.(*types.Pointer); ok {
			underlying = ptr.Elem().Underlying()
		}
		if structType, ok := underlying.(*types.Struct); ok {
			for field := range structType.Fields() {
				members[field.Name()] = true
			}
		}
	}
	return members
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
	if named := patternkit.NamedOf(typ); named != nil {
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
				if named := patternkit.NamedOf(selection.Recv()); named != nil && named.Obj().Pkg() == self {
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

// returnsLiveType reports whether the function hands back a type of this package with an
// exported method that reaches the network. Inert methods beside it (getters, labels) do not
// make it less of a client: a test counts as live only when it calls a live method or lets the
// value escape (liveCallScope.reaches).
func returnsLiveType(fn *ast.FuncDecl, info *types.Info, self *types.Package, live map[string]bool) bool {
	obj, ok := info.Defs[fn.Name].(*types.Func)
	if !ok || obj.Type() == nil {
		return false
	}
	signature, ok := obj.Type().(*types.Signature)
	if !ok || signature.Results() == nil {
		return false
	}
	for v := range signature.Results().Variables() {
		named := patternkit.NamedOf(v.Type())
		if named == nil || named.Obj().Pkg() != self {
			continue
		}
		for method := range named.Methods() {
			if method.Exported() && live[named.Obj().Name()+"."+method.Name()] {
				return true
			}
		}
	}
	return false
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
					if !isStringType(pkg.Package.TypesInfo.TypeOf(value.Values[i])) {
						continue
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

func isStringType(typ types.Type) bool {
	if typ == nil {
		return false
	}
	basic, ok := typ.Underlying().(*types.Basic)
	return ok && (basic.Kind() == types.String || basic.Kind() == types.UntypedString)
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
	urls, fieldURLs map[types.Object]string, hostOf func(*ast.BasicLit) string,
	live map[string]bool, self *types.Package,
) map[string]string {
	addresses := map[string]string{}
	for key, fn := range decls {
		if fn.Body == nil {
			continue
		}
		host := httpAddressIn(fn.Body, info, urls, fieldURLs, hostOf)
		if host == "" {
			host = liveClientConstructorArgument(fn.Body, decls, info, urls, fieldURLs, hostOf, live, self)
		}
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

func packageFieldURLs(pkg *core.GoPackageContext, urls map[types.Object]string, hostOf func(*ast.BasicLit) string) map[types.Object]string {
	fields := map[types.Object]string{}
	ambiguous := map[types.Object]bool{}
	info := pkg.Package.TypesInfo
	store := func(field types.Object, value ast.Expr) {
		if field == nil {
			return
		}
		if ambiguous[field] {
			return
		}
		host := expressionURL(value, info, urls, fields, hostOf)
		if host == "" {
			ambiguous[field] = true
			delete(fields, field)
			return
		}
		if previous := fields[field]; previous != "" && previous != host {
			ambiguous[field] = true
			delete(fields, field)
			return
		}
		fields[field] = host
	}
	for _, file := range pkg.Files {
		if file == nil || file.GoAST == nil || file.IsTestFile() {
			continue
		}
		ast.Inspect(file.GoAST, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.CompositeLit:
				for _, elt := range node.Elts {
					kv, ok := elt.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					key, ok := kv.Key.(*ast.Ident)
					if !ok {
						continue
					}
					store(structFieldObject(info.TypeOf(node), key.Name), kv.Value)
				}
			case *ast.AssignStmt:
				if len(node.Lhs) != len(node.Rhs) {
					break
				}
				for i, lhs := range node.Lhs {
					sel, ok := lhs.(*ast.SelectorExpr)
					if !ok {
						continue
					}
					selection := info.Selections[sel]
					if selection != nil {
						store(selection.Obj(), node.Rhs[i])
					}
				}
			}
			return true
		})
	}
	return fields
}

func structFieldObject(typ types.Type, name string) types.Object {
	named := patternkit.NamedOf(typ)
	if named == nil {
		return nil
	}
	underlying := named.Underlying()
	if ptr, ok := underlying.(*types.Pointer); ok {
		underlying = ptr.Elem().Underlying()
	}
	structType, ok := underlying.(*types.Struct)
	if !ok {
		return nil
	}
	for field := range structType.Fields() {
		if field.Name() == name {
			return field
		}
	}
	return nil
}

func expressionURL(expr ast.Expr, info *types.Info, urls, fields map[types.Object]string, hostOf func(*ast.BasicLit) string) string {
	if host := literalHost(expr, hostOf); host != "" {
		return host
	}
	var host string
	ast.Inspect(expr, func(n ast.Node) bool {
		if host != "" {
			return false
		}
		switch node := n.(type) {
		case *ast.Ident:
			host = urls[info.Uses[node]]
		case *ast.SelectorExpr:
			if selection := info.Selections[node]; selection != nil {
				host = fields[selection.Obj()]
			}
			if host == "" {
				host = urls[info.Uses[node.Sel]]
			}
		}
		return host == ""
	})
	return host
}

func httpAddressIn(body *ast.BlockStmt, info *types.Info, urls, fields map[types.Object]string, hostOf func(*ast.BasicLit) string) string {
	requestURLs := map[types.Object]string{}
	requestNames := map[string]string{}
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		index, isRequest := netHTTPRequestURLIndex(call, info)
		if !isRequest || index >= len(call.Args) {
			return true
		}
		host := expressionURL(call.Args[index], info, urls, fields, hostOf)
		if host == "" {
			return true
		}
		for _, node := range []ast.Node{body} {
			ast.Inspect(node, func(child ast.Node) bool {
				assign, ok := child.(*ast.AssignStmt)
				if !ok || len(assign.Rhs) != 1 || assign.Rhs[0] != ast.Expr(call) {
					return true
				}
				for _, lhs := range assign.Lhs {
					if id, ok := lhs.(*ast.Ident); ok {
						requestNames[id.Name] = host
						obj := info.Defs[id]
						if obj == nil {
							obj = info.Uses[id]
						}
						if obj != nil {
							requestURLs[obj] = host
						}
					}
				}
				return true
			})
		}
		return true
	})

	var host string
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || host != "" {
			return host == ""
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if isNetHTTPPackageFunc(sel, info, helpers.NetHTTPSendFuncs) {
			if len(call.Args) > 0 {
				host = expressionURL(call.Args[0], info, urls, fields, hostOf)
			}
			return host == ""
		}
		if !isNetHTTPClientSendMethod(info, sel) {
			return true
		}
		if helpers.NetHTTPSendFuncs[sel.Sel.Name] && len(call.Args) > 0 {
			host = expressionURL(call.Args[0], info, urls, fields, hostOf)
		} else if sel.Sel.Name == "Do" && len(call.Args) > 0 {
			if id, ok := ast.Unparen(call.Args[0]).(*ast.Ident); ok {
				obj := info.Uses[id]
				host = requestURLs[obj]
				if host == "" {
					host = requestNames[id.Name]
				}
			} else if request, ok := ast.Unparen(call.Args[0]).(*ast.CallExpr); ok {
				if index, yes := netHTTPRequestURLIndex(request, info); yes && index < len(request.Args) {
					host = expressionURL(request.Args[index], info, urls, fields, hostOf)
				}
			}
		}
		return host == ""
	})
	return host
}

func netHTTPRequestURLIndex(call *ast.CallExpr, info *types.Info) (int, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || !isNetHTTPPackageFunc(sel, info, helpers.NetHTTPRequestFuncs) {
		return 0, false
	}
	switch sel.Sel.Name {
	case "NewRequest":
		return 1, true
	case "NewRequestWithContext":
		return 2, true
	default:
		if helpers.NetHTTPSendFuncs[sel.Sel.Name] {
			return 0, true
		}
	}
	return 0, false
}

func isNetHTTPPackageFunc(sel *ast.SelectorExpr, info *types.Info, names map[string]bool) bool {
	ident, ok := sel.X.(*ast.Ident)
	if !ok || !names[sel.Sel.Name] {
		return false
	}
	pkg, ok := info.Uses[ident].(*types.PkgName)
	return ok && pkg.Imported().Path() == netHTTPPath
}

func liveClientConstructorArgument(body *ast.BlockStmt, decls map[string]*ast.FuncDecl, info *types.Info, urls, fields map[types.Object]string, hostOf func(*ast.BasicLit) string, live map[string]bool, self *types.Package) string {
	var host string
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || host != "" {
			return host == ""
		}
		var name string
		switch fun := call.Fun.(type) {
		case *ast.Ident:
			if fn, ok := info.Uses[fun].(*types.Func); ok && fn.Pkg() == self {
				name = fn.Name()
			}
		case *ast.SelectorExpr:
			if selection := info.Selections[fun]; selection != nil && selection.Kind() == types.MethodVal {
				if named := patternkit.NamedOf(selection.Recv()); named != nil && named.Obj().Pkg() == self {
					name = named.Obj().Name() + "." + fun.Sel.Name
				}
			}
		}
		callee := decls[name]
		if name == "" || callee == nil || !live[name] || !returnsLiveType(callee, info, self, live) {
			return true
		}
		for index := range liveClientURLParameterIndexes(callee, decls, info, self, live) {
			if index >= len(call.Args) {
				continue
			}
			if host = expressionURL(call.Args[index], info, urls, fields, hostOf); host != "" {
				return false
			}
		}
		return true
	})
	return host
}

func liveClientURLParameterIndexes(fn *ast.FuncDecl, decls map[string]*ast.FuncDecl, info *types.Info, self *types.Package, live map[string]bool) map[int]bool {
	indexes := map[int]bool{}
	obj, ok := info.Defs[fn.Name].(*types.Func)
	if !ok {
		return indexes
	}
	sig, ok := obj.Type().(*types.Signature)
	if !ok || sig.Params() == nil {
		return indexes
	}
	fields := map[types.Object]bool{}
	for _, key := range returnedLiveMethods(fn, info, self, live) {
		method := decls[key]
		if method == nil || !nodeSendsHTTPRequest(method.Body, info) {
			continue
		}
		for field := range httpURLFieldsIn(method.Body, info) {
			fields[field] = true
		}
	}
	if len(fields) == 0 {
		return indexes
	}
	markParam := func(field types.Object, value ast.Expr) {
		if !fields[field] {
			return
		}
		id, ok := ast.Unparen(value).(*ast.Ident)
		if !ok {
			return
		}
		param := info.Uses[id]
		for i := range sig.Params().Len() {
			if sig.Params().At(i) == param {
				indexes[i] = true
			}
		}
	}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CompositeLit:
			for _, elt := range node.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				key, ok := kv.Key.(*ast.Ident)
				if ok {
					markParam(structFieldObject(info.TypeOf(node), key.Name), kv.Value)
				}
			}
		case *ast.AssignStmt:
			if len(node.Lhs) != len(node.Rhs) {
				break
			}
			for i, lhs := range node.Lhs {
				if sel, ok := lhs.(*ast.SelectorExpr); ok {
					if selection := info.Selections[sel]; selection != nil {
						markParam(selection.Obj(), node.Rhs[i])
					}
				}
			}
		}
		return true
	})
	return indexes
}

func httpURLFieldsIn(body *ast.BlockStmt, info *types.Info) map[types.Object]bool {
	fields := map[types.Object]bool{}
	requestFields := map[types.Object]map[types.Object]bool{}
	requestNames := map[string]map[types.Object]bool{}
	addFields := func(dst map[types.Object]bool, expr ast.Expr) {
		ast.Inspect(expr, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if selection := info.Selections[sel]; selection != nil {
				if _, ok := selection.Obj().(*types.Var); ok {
					dst[selection.Obj()] = true
				}
			}
			return true
		})
	}
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		index, request := netHTTPRequestURLIndex(call, info)
		if !request || index >= len(call.Args) {
			return true
		}
		sources := map[types.Object]bool{}
		addFields(sources, call.Args[index])
		if len(sources) == 0 {
			return true
		}
		ast.Inspect(body, func(child ast.Node) bool {
			assign, ok := child.(*ast.AssignStmt)
			if !ok || len(assign.Rhs) != 1 || assign.Rhs[0] != ast.Expr(call) {
				return true
			}
			for _, lhs := range assign.Lhs {
				id, ok := lhs.(*ast.Ident)
				if !ok {
					continue
				}
				obj := info.Defs[id]
				if obj == nil {
					obj = info.Uses[id]
				}
				if obj != nil {
					requestFields[obj] = sources
				}
				requestNames[id.Name] = sources
			}
			return true
		})
		return true
	})
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if isNetHTTPPackageFunc(sel, info, helpers.NetHTTPSendFuncs) {
			if len(call.Args) > 0 {
				addFields(fields, call.Args[0])
			}
			return true
		}
		if !isNetHTTPClientSendMethod(info, sel) {
			return true
		}
		if helpers.NetHTTPSendFuncs[sel.Sel.Name] && len(call.Args) > 0 {
			addFields(fields, call.Args[0])
		} else if sel.Sel.Name == "Do" && len(call.Args) > 0 {
			if id, ok := ast.Unparen(call.Args[0]).(*ast.Ident); ok {
				obj := info.Uses[id]
				for field := range requestFields[obj] {
					fields[field] = true
				}
				for field := range requestNames[id.Name] {
					fields[field] = true
				}
			}
		}
		return true
	})
	return fields
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
	for v := range signature.Results().Variables() {
		named := patternkit.NamedOf(v.Type())
		if named == nil || named.Obj().Pkg() != self {
			continue
		}
		// The method set of *T holds the methods of T and those promoted from
		// embedded types: a live String of an embedded type is a live String of
		// the client.
		for selection := range types.NewMethodSet(types.NewPointer(named)).Methods() {
			method, ok := selection.Obj().(*types.Func)
			if !ok {
				continue
			}
			owner := patternkit.NamedOf(method.Signature().Recv().Type())
			if owner == nil || owner.Obj().Pkg() != self {
				continue
			}
			if key := owner.Obj().Name() + "." + method.Name(); live[key] {
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

// returnedSelfMethods lists the methods of the types fn returns whose results
// include the same type, by value or pointer.
func returnedSelfMethods(fn *ast.FuncDecl, info *types.Info) map[string]bool {
	methods := map[string]bool{}
	obj, ok := info.Defs[fn.Name].(*types.Func)
	if !ok {
		return methods
	}
	signature, ok := obj.Type().(*types.Signature)
	if !ok || signature.Results() == nil {
		return methods
	}
	for v := range signature.Results().Variables() {
		named := patternkit.NamedOf(v.Type())
		if named == nil {
			continue
		}
		set := types.NewMethodSet(types.NewPointer(named))
		for method := range set.Methods() {
			sig, isSig := method.Type().(*types.Signature)
			if !isSig {
				continue
			}
			for result := range sig.Results().Variables() {
				if patternkit.NamedOf(result.Type()) == named {
					methods[method.Obj().Name()] = true
				}
			}
		}
	}
	return methods
}
