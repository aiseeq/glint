package patterns

import (
	"go/ast"
	"go/token"
	"go/types"
	"path/filepath"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewNilDIRule())
}

// NilDIRule detects a nil handed to a dependency: an argument of a
// constructor (New*, Create*) for a pointer or interface parameter named like
// a dependency (logger, service, repo, manager, deps, ...), or such a field of
// a struct literal. The nil may be written as nil or (*T)(nil), or come
// through a local variable that holds nothing else. In a test file only a
// constructor that stores the nil without checking it is reported.
type NilDIRule struct {
	*rules.BaseRule
}

// NewNilDIRule creates the rule
func NewNilDIRule() *NilDIRule {
	return &NilDIRule{
		BaseRule: rules.NewBaseRule(
			"nil-di",
			"patterns",
			"Detects nil handed to a dependency: a constructor argument or a struct literal field of a pointer or interface named logger, service, repo, manager, ...",
			core.SeverityMedium,
		),
	}
}

// AnalyzeFile checks one file without type information: the fallback the
// project analysis uses for files no type-checked package covers.
func (r *NilDIRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	return r.analyze(ctx, nil, nil)
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *NilDIRule) RequiresSSA() bool { return false }

// AnalyzeGoProject checks every file: a constructor declared anywhere in the
// project is resolved through type information, so the nil argument is
// matched against the parameter it really lands in. A file outside the typed
// load resolves the constructors of the project through the index.
func (r *NilDIRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	index := newConstructorIndex(ctx)
	return rules.AnalyzeGoFiles(ctx, r.Name(), func(fileCtx *core.FileContext, info *types.Info) []*core.Violation {
		return r.analyze(fileCtx, info, index)
	})
}

// analyze checks the nil values a file hands to constructors and to the
// dependency fields of struct literals. info is nil for a file without type
// information; a constructor neither the index nor that file declares is then
// unknown, and the rule does not guess its parameters. Test files are left
// out: a nil that crashes a test fails it, and a nil for a dependency the test
// does not reach is how tests are written.
func (r *NilDIRule) analyze(ctx *core.FileContext, info *types.Info, index *constructorIndex) []*core.Violation {
	if !ctx.IsGoFile() || ctx.GoAST == nil || ctx.IsTestFile() {
		return nil
	}

	var violations []*core.Violation
	type place struct {
		line  int
		param string
	}
	reported := make(map[place]bool)
	report := func(line int, message, constructor, param string) {
		if reported[place{line, param}] || r.hasSuppression(ctx, line) {
			return
		}
		reported[place{line, param}] = true
		v := r.CreateViolation(ctx.RelPath, line, message)
		v.WithCode(ctx.GetLine(line))
		v.WithSuggestion("Pass the real dependency. Add '// nil-di: safe' comment to suppress if the nil is intended.")
		v.WithContext("constructor", constructor)
		v.WithContext("param_hint", param)
		violations = append(violations, v)
	}

	for _, decl := range ctx.GoAST.Decls {
		var locals nilLocals
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil {
			locals = collectNilLocals(fn.Body, info)
		}
		ast.Inspect(decl, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.CallExpr:
				r.checkCall(ctx, info, index, locals, node, report)
			case *ast.CompositeLit:
				r.checkLiteral(ctx, info, locals, node, report)
			}
			return true
		})
	}
	return violations
}

// checkCall reports a nil, or a local holding only nil, passed to a
// constructor (New*, Create*) for a parameter that is a dependency.
func (r *NilDIRule) checkCall(ctx *core.FileContext, info *types.Info, index *constructorIndex, locals nilLocals,
	call *ast.CallExpr, report func(line int, message, constructor, param string)) {
	funcName := r.getFuncName(call)
	if !strings.HasPrefix(funcName, "New") && !strings.HasPrefix(funcName, "Create") {
		return
	}
	// Skip known stdlib constructors where the nil-able parameter is not a DI dependency
	// (e.g. http.NewRequest body is io.Reader, bytes.NewReader takes []byte).
	if r.isStdlibNonDI(call) {
		return
	}
	for i, arg := range call.Args {
		holder := locals.lookup(arg, info)
		if holder == nil && !helpers.IsNilValue(arg, info) {
			continue
		}
		// The parameter the nil lands in decides. An unresolved one is not
		// guessed from the constructor name or the position, and one whose
		// type is a collection is not a dependency.
		param := resolveConstructorParam(ctx, info, index, call, i)
		if !param.dependency || !r.isHighRiskParam(param.name) {
			continue
		}
		if holder != nil {
			report(ctx.LineFor(holder), "Variable "+holder.Name+" holds nil and is passed as the "+param.name+
				" dependency of "+funcName, funcName, param.name)
			continue
		}
		report(ctx.LineFor(call), "Nil "+param.name+" argument to constructor "+funcName, funcName, param.name)
	}
}

// checkLiteral reports a nil, or a local holding only nil, written into a
// dependency field of a struct literal.
func (r *NilDIRule) checkLiteral(ctx *core.FileContext, info *types.Info, locals nilLocals, lit *ast.CompositeLit,
	report func(line int, message, constructor, param string)) {
	if !isStructLiteral(lit, info) {
		return
	}
	typeName := types.ExprString(lit.Type)
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok || !r.isHighRiskParam(key.Name) {
			continue
		}
		if info != nil {
			field, ok := info.Uses[key].(*types.Var)
			if !ok || !isDependencyType(field.Type()) {
				continue
			}
		}
		if holder := locals.lookup(kv.Value, info); holder != nil {
			report(ctx.LineFor(holder), "Variable "+holder.Name+" holds nil and is written into the "+key.Name+
				" dependency of "+typeName, typeName, key.Name)
		} else if helpers.IsNilValue(kv.Value, info) {
			report(ctx.LineFor(kv), "Nil "+key.Name+" dependency in a "+typeName+" literal", typeName, key.Name)
		}
	}
}

// isStructLiteral reports a composite literal of a struct type. Without type
// information a literal whose type is written as a map, a slice or an array
// is not one, and a literal with no written type (an element of an outer
// literal) is unknown.
func isStructLiteral(lit *ast.CompositeLit, info *types.Info) bool {
	if info != nil {
		t := info.TypeOf(lit)
		if t == nil {
			return false
		}
		_, ok := t.Underlying().(*types.Struct)
		return ok
	}
	switch lit.Type.(type) {
	case *ast.Ident, *ast.SelectorExpr:
		return true
	}
	return false
}

// nilLocals are the local variables of a function that hold nothing but nil,
// by the identifier that declares them: keyed by object with type
// information, by name without it.
type nilLocals struct {
	byObj  map[types.Object]*ast.Ident
	byName map[string]*ast.Ident
}

// lookup returns the declaration of the nil local expr names, or nil.
func (l nilLocals) lookup(expr ast.Expr, info *types.Info) *ast.Ident {
	ident, ok := ast.Unparen(expr).(*ast.Ident)
	if !ok {
		return nil
	}
	if info != nil {
		return l.byObj[info.Uses[ident]]
	}
	return l.byName[ident.Name]
}

// collectNilLocals finds the variables of body declared as nil — `var x T =
// nil`, `x := (*T)(nil)`, or `var x T` of a pointer or interface type — that
// are never assigned again, taken by address or ranged into. Without type
// information a variable declared without a value counts only when its type
// is written as a pointer, and a name declared twice is dropped.
func collectNilLocals(body *ast.BlockStmt, info *types.Info) nilLocals {
	decls := make(map[any]*ast.Ident)
	spoiled := make(map[any]bool)
	key := func(ident *ast.Ident) any {
		if info != nil {
			return info.ObjectOf(ident)
		}
		return ident.Name
	}
	declare := func(ident *ast.Ident, isNil bool) {
		k := key(ident)
		if _, seen := decls[k]; seen || !isNil {
			spoiled[k] = true
		}
		decls[k] = ident
	}
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.ValueSpec:
			for i, name := range node.Names {
				switch {
				case len(node.Values) == 0:
					declare(name, zeroIsNil(name, node.Type, info))
				case len(node.Values) == len(node.Names):
					declare(name, helpers.IsNilValue(node.Values[i], info))
				default:
					declare(name, false)
				}
			}
		case *ast.AssignStmt:
			for i, lhs := range node.Lhs {
				ident, ok := lhs.(*ast.Ident)
				if !ok {
					continue
				}
				defines := node.Tok == token.DEFINE && (info == nil || info.Defs[ident] != nil)
				if defines && len(node.Lhs) == len(node.Rhs) {
					declare(ident, helpers.IsNilValue(node.Rhs[i], info))
				} else {
					spoiled[key(ident)] = true
				}
			}
		case *ast.UnaryExpr:
			if ident, ok := node.X.(*ast.Ident); ok && node.Op == token.AND {
				spoiled[key(ident)] = true
			}
		case *ast.RangeStmt:
			for _, e := range []ast.Expr{node.Key, node.Value} {
				if ident, ok := e.(*ast.Ident); ok {
					spoiled[key(ident)] = true
				}
			}
		}
		return true
	})
	locals := nilLocals{byObj: make(map[types.Object]*ast.Ident), byName: make(map[string]*ast.Ident)}
	for k, ident := range decls {
		if spoiled[k] || ident.Name == "_" {
			continue
		}
		switch k := k.(type) {
		case types.Object:
			locals.byObj[k] = ident
		case string:
			locals.byName[k] = ident
		}
	}
	return locals
}

// zeroIsNil reports a variable declared without a value whose zero value is
// a missing dependency.
func zeroIsNil(name *ast.Ident, typeExpr ast.Expr, info *types.Info) bool {
	if info != nil {
		obj := info.Defs[name]
		return obj != nil && isDependencyType(obj.Type())
	}
	_, ok := typeExpr.(*ast.StarExpr)
	return ok
}

// highRiskParamWords are the words of a parameter name that mark a
// dependency a constructor cannot work without.
var highRiskParamWords = map[string]bool{
	"logger": true, "log": true,
	"service": true, "svc": true,
	"repo": true, "repository": true,
	"storage": true, "store": true,
	"handler": true, "controller": true,
	"client": true, "conn": true,
	"db": true, "database": true,
	"cache":     true,
	"metrics":   true,
	"validator": true,
	"manager":   true,
	"getter":    true,
	"provider":  true,
	"adapter":   true,
	"deps":      true, "dependencies": true,
}

// isHighRiskParam reports whether one of the words of the parameter name
// (camelCase or snake_case, singular or plural) marks a dependency: userRepo,
// dbConn and loggers do, catalog and blog do not contain the word log.
func (r *NilDIRule) isHighRiskParam(paramHint string) bool {
	return isDependencyName(paramHint)
}

// isDependencyName reports a name one of whose words marks a dependency.
func isDependencyName(paramHint string) bool {
	for _, word := range helpers.IdentifierWords(paramHint) {
		// A plural names several of the same dependency: loggers, repos.
		if highRiskParamWords[word] || highRiskParamWords[strings.TrimSuffix(word, "s")] {
			return true
		}
	}
	return false
}

// hasSuppression delegates to the canonical core suppression check.
func (r *NilDIRule) hasSuppression(ctx *core.FileContext, line int) bool {
	return ctx.IsSuppressed(line, r.Name())
}

// getFuncName extracts the function name from a call expression
func (r *NilDIRule) getFuncName(call *ast.CallExpr) string {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		return fn.Name
	case *ast.SelectorExpr:
		return fn.Sel.Name
	}
	return ""
}

// isStdlibNonDI reports whether the call is a known stdlib constructor where a nil argument
// is a canonical use (not a missing dependency). Example: http.NewRequest(..., nil) is a
// bodiless GET; bytes.NewReader(nil) returns an empty reader.
func (r *NilDIRule) isStdlibNonDI(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	switch pkg.Name + "." + sel.Sel.Name {
	case "http.NewRequest",
		"http.NewRequestWithContext",
		"bytes.NewReader",
		"bytes.NewBuffer",
		"strings.NewReader":
		return true
	}
	return false
}

// constructorParamInfo is the parameter an argument lands in: its name ("" for
// an unnamed or unresolved one) and whether its type can be a dependency left
// unset.
type constructorParamInfo struct {
	name       string
	dependency bool
}

// resolveConstructorParam finds the parameter the argument at argIndex of
// call lands in. With type information the callee's signature answers,
// wherever it is declared: only a pointer or an interface is a dependency.
// Without it the index resolves a function of a type-checked package the
// file calls by its package name or from its own directory, and otherwise
// only a plain call of a function declared in the file is resolved, where a
// parameter declared as a slice, map, channel or function is not a
// dependency.
func resolveConstructorParam(ctx *core.FileContext, info *types.Info, index *constructorIndex, call *ast.CallExpr,
	argIndex int) constructorParamInfo {
	if info != nil {
		tv, ok := info.Types[call.Fun]
		if !ok || !tv.IsValue() || tv.Type == nil {
			return constructorParamInfo{}
		}
		sig, ok := tv.Type.Underlying().(*types.Signature)
		if !ok {
			return constructorParamInfo{}
		}
		return signatureParam(sig, call, argIndex)
	}
	if fn := index.resolveUntyped(ctx, call); fn != nil {
		return signatureParam(fn.Signature(), call, argIndex)
	}
	fn := index.resolveSyntax(ctx, call)
	if fn == nil {
		fn = sameFileFunc(ctx.GoAST, call)
	}
	if fn == nil || fn.Type.Params == nil {
		return constructorParamInfo{}
	}
	name, dependency := fieldListParam(fn.Type.Params, argIndex)
	return constructorParamInfo{name: name, dependency: dependency}
}

// sameFileFunc returns the plain function a call names when the file declares it.
func sameFileFunc(file *ast.File, call *ast.CallExpr) *ast.FuncDecl {
	ident, ok := call.Fun.(*ast.Ident)
	if !ok {
		return nil
	}
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil && fn.Name.Name == ident.Name {
			return fn
		}
	}
	return nil
}

// signatureParam reads the parameter from the callee's signature. A nil
// argument for a variadic parameter is one element of it.
func signatureParam(sig *types.Signature, call *ast.CallExpr, argIndex int) constructorParamInfo {
	params := sig.Params()
	last := params.Len() - 1
	if argIndex < 0 || last < 0 {
		return constructorParamInfo{}
	}
	if sig.Variadic() && argIndex >= last && !call.Ellipsis.IsValid() {
		slice, ok := params.At(last).Type().(*types.Slice)
		if !ok {
			return constructorParamInfo{}
		}
		return constructorParamInfo{name: params.At(last).Name(), dependency: isDependencyType(slice.Elem())}
	}
	if argIndex > last {
		return constructorParamInfo{}
	}
	return constructorParamInfo{name: params.At(argIndex).Name(), dependency: isDependencyType(params.At(argIndex).Type())}
}

// constructorIndex resolves, for files outside the typed load, the functions
// of the type-checked packages. The plain functions of the files outside the typed load (a package that does
// not type-check) are indexed by directory, for a syntactic resolution.
type constructorIndex struct {
	byPath map[string]*types.Package
	byDir  map[string]*types.Package
	// untyped holds, by directory relative to the project root, the plain
	// functions declared outside the typed load.
	untyped map[string]map[string]*ast.FuncDecl
}

func newConstructorIndex(ctx *core.GoProjectContext) *constructorIndex {
	index := &constructorIndex{
		byPath:  make(map[string]*types.Package),
		byDir:   make(map[string]*types.Package),
		untyped: make(map[string]map[string]*ast.FuncDecl),
	}
	typed := make(map[*core.FileContext]bool)
	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil || pkg.Package.Types == nil {
			continue
		}
		index.byPath[pkg.Package.PkgPath] = pkg.Package.Types
		for _, file := range pkg.Package.GoFiles {
			index.byDir[filepath.Dir(file)] = pkg.Package.Types
		}
		for _, fileCtx := range pkg.Files {
			typed[fileCtx] = true
		}
	}
	for _, fileCtx := range ctx.Files {
		if fileCtx == nil || fileCtx.GoAST == nil || typed[fileCtx] || fileCtx.IsTestFile() {
			continue
		}
		dir := filepath.ToSlash(filepath.Dir(fileCtx.RelPath))
		for _, decl := range fileCtx.GoAST.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil {
				continue
			}
			if index.untyped[dir] == nil {
				index.untyped[dir] = make(map[string]*ast.FuncDecl)
			}
			index.untyped[dir][fn.Name.Name] = fn
		}
	}
	return index
}

// resolveSyntax resolves a call of an untyped file to a plain function
// declared outside the typed load: NewX in the file's own directory, pkg.NewX
// in the one directory the import path ends with.
func (x *constructorIndex) resolveSyntax(ctx *core.FileContext, call *ast.CallExpr) *ast.FuncDecl {
	if x == nil {
		return nil
	}
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		return x.untyped[filepath.ToSlash(filepath.Dir(ctx.RelPath))][fun.Name]
	case *ast.SelectorExpr:
		qualifier, ok := fun.X.(*ast.Ident)
		if !ok {
			return nil
		}
		path := importPathOf(ctx.GoAST, qualifier.Name)
		if path == "" {
			return nil
		}
		var found *ast.FuncDecl
		for dir, funcs := range x.untyped {
			if dir == "." || !strings.HasSuffix(path, "/"+dir) {
				continue
			}
			if fn := funcs[fun.Sel.Name]; fn != nil {
				if found != nil {
					return nil // two directories match: ambiguous
				}
				found = fn
			}
		}
		return found
	}
	return nil
}

// importPathOf returns the path of the import the file names name: by its
// explicit name, or by the last element of the path.
func importPathOf(file *ast.File, name string) string {
	for _, spec := range file.Imports {
		path := strings.Trim(spec.Path.Value, "\"`")
		local := path[strings.LastIndex(path, "/")+1:]
		if spec.Name != nil {
			local = spec.Name.Name
		}
		if local == name {
			return path
		}
	}
	return ""
}

// resolveUntyped resolves a call of an untyped file to a function of a
// type-checked package: pkg.NewX through the file's imports, NewX through the
// package in the file's own directory.
func (x *constructorIndex) resolveUntyped(ctx *core.FileContext, call *ast.CallExpr) *types.Func {
	if x == nil {
		return nil
	}
	var pkg *types.Package
	var name string
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		pkg, name = x.byDir[filepath.Dir(ctx.Path)], fun.Name
	case *ast.SelectorExpr:
		qualifier, ok := fun.X.(*ast.Ident)
		if !ok {
			return nil
		}
		pkg, name = x.imported(ctx.GoAST, qualifier.Name), fun.Sel.Name
	}
	if pkg == nil {
		return nil
	}
	fn, _ := pkg.Scope().Lookup(name).(*types.Func)
	return fn
}

// imported returns the type-checked package the file imports under name.
func (x *constructorIndex) imported(file *ast.File, name string) *types.Package {
	for _, spec := range file.Imports {
		path := strings.Trim(spec.Path.Value, "\"`")
		pkg := x.byPath[path]
		if pkg == nil {
			continue
		}
		local := pkg.Name()
		if spec.Name != nil {
			local = spec.Name.Name
		}
		if local == name {
			return pkg
		}
	}
	return nil
}

// isDependencyType reports a type whose nil value is a missing dependency: a
// pointer or an interface. A nil slice or map is an empty collection.
func isDependencyType(t types.Type) bool {
	switch t.Underlying().(type) {
	case *types.Pointer, *types.Interface:
		return true
	}
	return false
}

// fieldListParam returns the name of the parameter at argIndex, "" for an
// unnamed one, and whether its declared type can be a dependency. Arguments
// past the end land in a trailing variadic parameter, one element each.
func fieldListParam(params *ast.FieldList, argIndex int) (string, bool) {
	var names []string
	var typeExprs []ast.Expr
	variadic := false
	for _, field := range params.List {
		_, variadic = field.Type.(*ast.Ellipsis)
		if len(field.Names) == 0 {
			names = append(names, "") // unnamed parameter still occupies a position
			typeExprs = append(typeExprs, field.Type)
			continue
		}
		for _, name := range field.Names {
			names = append(names, name.Name)
			typeExprs = append(typeExprs, field.Type)
		}
	}
	if variadic && argIndex >= len(names) {
		argIndex = len(names) - 1
	}
	if argIndex < 0 || argIndex >= len(names) {
		return "", false
	}
	typeExpr := typeExprs[argIndex]
	if ellipsis, ok := typeExpr.(*ast.Ellipsis); ok {
		typeExpr = ellipsis.Elt
	}
	switch typeExpr.(type) {
	case *ast.ArrayType, *ast.MapType, *ast.ChanType, *ast.FuncType:
		return names[argIndex], false
	}
	return names[argIndex], true
}
