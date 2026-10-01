package patterns

import (
	"errors"
	"go/ast"
	"go/token"
	"go/types"
	"maps"
	"slices"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"golang.org/x/tools/go/types/typeutil"
)

func init() {
	rules.Register(NewUnboundedMapRule())
}

// UnboundedMapRule detects a map held by a struct field or a package-level
// variable that code run again and again fills with keys taken from its input,
// while nothing ever takes an entry out:
//
//	type limiter struct{ clients map[string]*bucket }
//
//	func (l *limiter) allow(ip string) bool {
//	    if _, ok := l.clients[ip]; !ok {
//	        l.clients[ip] = &bucket{}   // one entry per client, forever
//	    }
//	    ...
//	}
//
// A long-running process keeps every key it has ever seen: a slow leak that
// grows with traffic. Only a project that runs a server (ListenAndServe, a
// Serve method) is judged: a command-line tool frees its maps on exit.
//
// A field counts only when its struct outlives a call: it carries a mutex (its
// methods serve several goroutines) or a package-level variable holds one, and
// it is made only while constructing — per-pass state of analyzers, walkers
// and request-scoped caches is dropped with the pass. The map is bounded when
// some code deletes from it, clears it, replaces it outside construction, or
// compares its length with a cap. Inserts made while constructing or loading
// (New…, init, load…, build…, register…, setup…, parse…) run once and are not
// counted.
//
// Only a key drawn from outside data makes the map grow without bound: a key
// built from a hash, a transaction, a query, a domain, an email, an address,
// a URL, a token, an IP, a session or request id, a payment record — by the
// names of the parameters, fields, calls and local variables it comes from —
// or read from the HTTP request. Keys naming clients, endpoints, chats, jobs
// or kinds come from a set the code or its configuration fixes, and such maps
// are not reported. A map that leaves the analysis —
// returned, passed on, aliased — is not judged: what happens to its entries is
// not visible here.
type UnboundedMapRule struct {
	*rules.BaseRule
}

// NewUnboundedMapRule creates the rule.
func NewUnboundedMapRule() *UnboundedMapRule {
	return &UnboundedMapRule{
		BaseRule: rules.NewBaseRule(
			"unbounded-map",
			"patterns",
			"Detects a map field or package-level map filled per call with keys from the input and never deleted from, cleared or replaced — a slow leak in long-running processes",
			core.SeverityMedium,
		),
	}
}

// RequiresSSA reports that typed packages are enough.
func (r *UnboundedMapRule) RequiresSSA() bool { return false }

// AnalyzeFile does nothing: eviction may live in any file of the project.
func (r *UnboundedMapRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// mapUsage aggregates how one long-lived map is used across the project.
type mapUsage struct {
	variable *types.Var
	insertFn string // the function of the first insert under an external key
	bounded  bool
	escaped  bool
}

// mapScope is the function a walk is in: its name, the body of its
// declaration (where a key's local variables are defined) and whether it runs
// once.
type mapScope struct {
	name    string
	body    *ast.BlockStmt
	oneTime bool
}

// oneTimePrefixes start the names of functions that run while a value is
// constructed or loaded, not once per request.
var oneTimePrefixes = []string{"new", "init", "load", "build", "register", "setup", "parse", "configure", "must"}

// AnalyzeGoProject reports grow-only maps at their declaration.
func (r *UnboundedMapRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, errors.New("unbounded map: nil Go project context")
	}

	tracker := &mapTracker{
		usages:  map[token.Pos]*mapUsage{},
		owner:   map[token.Pos]token.Pos{},
		shared:  map[token.Pos]bool{},
		perCall: map[token.Pos]bool{},
	}
	for _, pkgCtx := range ctx.Packages {
		if pkgCtx == nil || pkgCtx.Package == nil || pkgCtx.Package.TypesInfo == nil {
			continue
		}
		tracker.scanPackage(pkgCtx.Package.TypesInfo, pkgCtx.Package.Syntax)
	}
	if !tracker.serves {
		return nil, nil
	}

	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(fileCtx *core.FileContext, _ *types.Info) []*core.Violation {
		var violations []*core.Violation
		for _, pos := range slices.Sorted(maps.Keys(tracker.usages)) {
			if pos < fileCtx.GoAST.FileStart || pos >= fileCtx.GoAST.FileEnd {
				continue
			}
			usage := tracker.usages[pos]
			if usage.insertFn == "" || usage.bounded || usage.escaped || !tracker.longLived(usage) {
				continue
			}
			line := fileCtx.LineForPos(pos)
			if fileCtx.IsSuppressed(line, r.Name()) {
				continue
			}
			violations = append(violations, r.violationFor(fileCtx, line, usage.variable, usage.insertFn))
		}
		return violations
	})
}

// mapTracker walks the syntax of every package and records the uses of
// map-typed fields and package-level variables.
type mapTracker struct {
	usages  map[token.Pos]*mapUsage
	owner   map[token.Pos]token.Pos // field -> the name of its struct type
	shared  map[token.Pos]bool      // struct types with a mutex or a package-level instance
	perCall map[token.Pos]bool      // struct types instantiated in code run repeatedly
	serves  bool                    // the project runs a server: its process outlives a run
}

// serveFunctions start a server loop: http.ListenAndServe and the Serve
// methods of net/http, gRPC and the like.
var serveFunctions = map[string]bool{"ListenAndServe": true, "ListenAndServeTLS": true, "Serve": true, "ServeTLS": true}

// longLived reports a package-level map, or a field of a struct that
// outlives a call: shared, and made only while constructing.
func (t *mapTracker) longLived(usage *mapUsage) bool {
	if !usage.variable.IsField() {
		return true
	}
	// A struct declared inside a function has no recorded owner: its values
	// live as long as that call.
	owner, ok := t.owner[usage.variable.Pos()]
	return ok && t.shared[owner] && !t.perCall[owner]
}

// scanOwners records the struct type of every field and which struct types
// are shared: they carry a mutex (their methods run on several goroutines)
// or a package-level variable holds one. Analyzer and walker state, built and
// dropped within a call, is neither.
func (t *mapTracker) scanOwners(info *types.Info, files []*ast.File) {
	for _, file := range files {
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok {
				continue
			}
			for _, spec := range gen.Specs {
				switch spec := spec.(type) {
				case *ast.TypeSpec:
					t.recordStruct(info, spec)
				case *ast.ValueSpec:
					t.recordInstances(info, spec)
				}
			}
		}
	}
}

// recordStruct maps the fields of a struct declaration to it.
func (t *mapTracker) recordStruct(info *types.Info, spec *ast.TypeSpec) {
	structType, ok := spec.Type.(*ast.StructType)
	if !ok || structType.Fields == nil {
		return
	}
	typeName, ok := info.Defs[spec.Name].(*types.TypeName)
	if !ok {
		return
	}
	for _, field := range structType.Fields.List {
		if isMutexType(info.TypeOf(field.Type)) {
			t.shared[typeName.Pos()] = true
		}
		for _, name := range field.Names {
			if obj := info.Defs[name]; obj != nil {
				t.owner[obj.Pos()] = typeName.Pos()
			}
		}
	}
}

// recordInstances marks the struct types of package-level variables shared.
func (t *mapTracker) recordInstances(info *types.Info, spec *ast.ValueSpec) {
	for _, name := range spec.Names {
		if variable, ok := info.Defs[name].(*types.Var); ok {
			t.recordInstance(variable.Type())
		}
	}
}

// recordInstance marks the struct type of a package-level variable shared.
func (t *mapTracker) recordInstance(typ types.Type) {
	if ptr, ok := typ.(*types.Pointer); ok {
		typ = ptr.Elem()
	}
	if named, ok := types.Unalias(typ).(*types.Named); ok {
		t.shared[named.Obj().Pos()] = true
	}
}

// scanPackage records the uses in one package; any use the walk does not
// account for marks the map escaped.
func (t *mapTracker) scanPackage(info *types.Info, files []*ast.File) {
	t.scanOwners(info, files)
	consumed := map[*ast.Ident]bool{}
	for _, file := range files {
		for _, decl := range file.Decls {
			switch decl := decl.(type) {
			case *ast.FuncDecl:
				if decl.Body != nil {
					t.walk(info, decl.Body, mapScope{name: decl.Name.Name, body: decl.Body, oneTime: isOneTimeName(decl.Name.Name)}, consumed)
				}
			case *ast.GenDecl:
				t.walk(info, decl, mapScope{oneTime: true}, consumed)
			}
		}
	}
	for ident, obj := range info.Uses {
		variable, ok := obj.(*types.Var)
		if !ok || consumed[ident] {
			continue
		}
		if usage, tracked := t.usages[variable.Pos()]; tracked {
			usage.escaped = true
		}
	}
}

// walk visits the statements of a function (or a top-level declaration). A
// function literal runs whenever it is called, so inside one the enclosing
// function's one-time status no longer holds.
func (t *mapTracker) walk(info *types.Info, root ast.Node, scope mapScope, consumed map[*ast.Ident]bool) {
	ast.Inspect(root, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncLit:
			t.walk(info, node.Body, mapScope{name: scope.name, body: scope.body}, consumed)
			return false
		case *ast.AssignStmt:
			for _, lhs := range node.Lhs {
				t.assigned(info, lhs, node.Tok, scope, consumed)
			}
		case *ast.IncDecStmt:
			t.assigned(info, node.X, node.Tok, scope, consumed)
		case *ast.CompositeLit:
			if !scope.oneTime {
				t.instantiated(info.TypeOf(node))
			}
		case *ast.IndexExpr:
			t.consume(info, node.X, consumed)
		case *ast.RangeStmt:
			t.consume(info, node.X, consumed)
		case *ast.KeyValueExpr:
			t.consume(info, node.Key, consumed)
		case *ast.BinaryExpr:
			t.compared(info, node, consumed)
		case *ast.CallExpr:
			t.called(info, node, consumed)
			t.recordServe(info, node)
			if !scope.oneTime && callsBuiltin(info, node, "new") && len(node.Args) == 1 {
				t.instantiated(info.TypeOf(node.Args[0]))
			}
		}
		return true
	})
}

// instantiated marks a struct type made in code run repeatedly.
func (t *mapTracker) instantiated(typ types.Type) {
	if ptr, ok := types.Unalias(typ).(*types.Pointer); ok {
		typ = ptr.Elem()
	}
	if named, ok := types.Unalias(typ).(*types.Named); ok {
		t.perCall[named.Obj().Pos()] = true
	}
}

// recordServe notes a call that starts a server loop.
func (t *mapTracker) recordServe(info *types.Info, call *ast.CallExpr) {
	fn := typeutil.StaticCallee(info, call)
	if fn != nil && serveFunctions[fn.Name()] && (fn.Signature().Recv() != nil || (fn.Pkg() != nil && fn.Pkg().Path() == "net/http")) {
		t.serves = true
	}
}

// assigned handles a write: m[k] = v adds a key, m = … replaces the map.
func (t *mapTracker) assigned(info *types.Info, lhs ast.Expr, tok token.Token, scope mapScope, consumed map[*ast.Ident]bool) {
	lhs = ast.Unparen(lhs)
	if index, ok := lhs.(*ast.IndexExpr); ok {
		usage := t.consume(info, index.X, consumed)
		if usage == nil || scope.oneTime {
			return
		}
		if usage.insertFn == "" && externalKey(info, scope.body, index.Index) {
			usage.insertFn = scope.name
		}
		return
	}
	usage := t.consume(info, lhs, consumed)
	if usage != nil && !scope.oneTime && tok == token.ASSIGN {
		usage.bounded = true
	}
}

// compared handles len(m) checked against a cap and m compared with nil.
func (t *mapTracker) compared(info *types.Info, expr *ast.BinaryExpr, consumed map[*ast.Ident]bool) {
	for _, side := range []ast.Expr{expr.X, expr.Y} {
		side = ast.Unparen(side)
		if call, ok := side.(*ast.CallExpr); ok && callsBuiltin(info, call, "len") && len(call.Args) == 1 {
			usage := t.consume(info, call.Args[0], consumed)
			if usage != nil && (expr.Op == token.LSS || expr.Op == token.LEQ || expr.Op == token.GTR || expr.Op == token.GEQ) {
				usage.bounded = true
			}
			continue
		}
		if expr.Op == token.EQL || expr.Op == token.NEQ {
			t.consume(info, side, consumed)
		}
	}
}

// called handles delete, clear and len.
func (t *mapTracker) called(info *types.Info, call *ast.CallExpr, consumed map[*ast.Ident]bool) {
	if len(call.Args) == 0 {
		return
	}
	switch {
	case callsBuiltin(info, call, "delete"), callsBuiltin(info, call, "clear"):
		if usage := t.consume(info, call.Args[0], consumed); usage != nil {
			usage.bounded = true
		}
	case callsBuiltin(info, call, "len"):
		t.consume(info, call.Args[0], consumed)
	}
}

// consume resolves an expression naming a long-lived map, marks its use as
// accounted for and returns the map's record; nil for anything else.
func (t *mapTracker) consume(info *types.Info, expr ast.Expr, consumed map[*ast.Ident]bool) *mapUsage {
	var ident *ast.Ident
	switch node := ast.Unparen(expr).(type) {
	case *ast.Ident:
		ident = node
	case *ast.SelectorExpr:
		ident = node.Sel
	default:
		return nil
	}
	variable, ok := info.Uses[ident].(*types.Var)
	if !ok || !longLivedMap(variable) {
		return nil
	}
	consumed[ident] = true
	usage, ok := t.usages[variable.Pos()]
	if !ok {
		usage = &mapUsage{variable: variable}
		t.usages[variable.Pos()] = usage
	}
	return usage
}

// externalKeyWords name values that come from outside data and have no
// bound: hashes, addresses, queries, network identities, records of a
// payment flow. Names of clients, endpoints, chats, jobs and kinds come from
// the code or its configuration and are not among them.
var externalKeyWords = map[string]bool{
	"hash": true, "tx": true, "txid": true, "txn": true, "transaction": true,
	"query": true, "search": true, "domain": true, "email": true, "mail": true,
	"address": true, "addr": true, "url": true, "uri": true, "path": true, "host": true, "hostname": true,
	"token": true, "ip": true, "remote": true, "session": true, "nonce": true, "fingerprint": true,
	"referer": true, "referrer": true, "deposit": true, "withdrawal": true, "payment": true,
	"order": true, "invoice": true, "receipt": true,
}

// externalKeyPhrases are word pairs naming such values: requestID, userAgent.
var externalKeyPhrases = map[[2]string]bool{
	{"request", "id"}: true, {"session", "id"}: true, {"trace", "id"}: true,
	{"correlation", "id"}: true, {"user", "agent"}: true,
}

// externalKey reports a key drawn from outside data: some name it is built
// from — a parameter, a field, a called function, or a local variable it is
// assigned from, followed through the declaration's body — names such a
// value, or the key is read from the HTTP request.
func externalKey(info *types.Info, body *ast.BlockStmt, key ast.Expr) bool {
	seen := map[*types.Var]bool{}
	queue := []ast.Expr{key}
	for len(queue) > 0 {
		expr := queue[0]
		queue = queue[1:]
		found := false
		ast.Inspect(expr, func(n ast.Node) bool {
			ident, ok := n.(*ast.Ident)
			if found || !ok {
				return !found
			}
			if externalName(ident.Name) || requestData(info.TypeOf(ident)) {
				found = true
				return false
			}
			variable, ok := info.Uses[ident].(*types.Var)
			if ok && body != nil && !seen[variable] && variable.Pos() > body.Pos() && variable.Pos() < body.End() {
				seen[variable] = true
				queue = append(queue, localSources(info, body, variable)...)
			}
			return true
		})
		if found {
			return true
		}
	}
	return false
}

// externalName reports an identifier naming an unbounded outside value.
func externalName(name string) bool {
	words := identifierWords(name)
	for i, word := range words {
		if externalKeyWords[word] {
			return true
		}
		if i > 0 && externalKeyPhrases[[2]string{words[i-1], word}] {
			return true
		}
	}
	return false
}

// requestData reports the parts of an HTTP request a handler reads.
func requestData(t types.Type) bool {
	return isPointerToNamedType(t, "net/http", "Request") || isNamedType(t, "net/http", "Header") ||
		isNamedType(t, "net/url", "Values") || isPointerToNamedType(t, "net/url", "URL")
}

// localSources returns the expressions a local variable is assigned from in
// the body: assignments, declarations, and the collection a range variable
// walks.
func localSources(info *types.Info, body *ast.BlockStmt, variable *types.Var) []ast.Expr {
	names := func(ident *ast.Ident) bool { return info.Defs[ident] == variable || info.Uses[ident] == variable }
	var sources []ast.Expr
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			for i, lhs := range node.Lhs {
				if ident, ok := lhs.(*ast.Ident); ok && names(ident) {
					sources = append(sources, assignedValue(node.Rhs, len(node.Lhs), i))
				}
			}
		case *ast.ValueSpec:
			for i, name := range node.Names {
				if names(name) && len(node.Values) > 0 {
					sources = append(sources, assignedValue(node.Values, len(node.Names), i))
				}
			}
		case *ast.RangeStmt:
			for _, bound := range []ast.Expr{node.Key, node.Value} {
				if ident, ok := bound.(*ast.Ident); ok && names(ident) {
					sources = append(sources, node.X)
				}
			}
		}
		return true
	})
	return sources
}

// assignedValue returns the value assigned to the i-th of n targets: its own
// expression, or the single multi-value call they all come from.
func assignedValue(values []ast.Expr, n, i int) ast.Expr {
	if len(values) == n {
		return values[i]
	}
	return values[0]
}

// longLivedMap reports a map-typed struct field or package-level variable.
func longLivedMap(variable *types.Var) bool {
	if _, ok := variable.Type().Underlying().(*types.Map); !ok {
		return false
	}
	if variable.IsField() {
		return true
	}
	return variable.Pkg() != nil && variable.Parent() == variable.Pkg().Scope()
}

// callsBuiltin reports a call of the named builtin function.
func callsBuiltin(info *types.Info, call *ast.CallExpr, name string) bool {
	ident, ok := ast.Unparen(call.Fun).(*ast.Ident)
	return ok && ident.Name == name && isBuiltinCall(info, call)
}

// isOneTimeName reports a function that constructs or loads rather than
// serves.
func isOneTimeName(name string) bool {
	lower := strings.ToLower(name)
	for _, prefix := range oneTimePrefixes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

// violationFor renders the finding at the map's declaration.
func (r *UnboundedMapRule) violationFor(ctx *core.FileContext, line int, variable *types.Var, insertFn string) *core.Violation {
	kind := "Package-level map"
	if variable.IsField() {
		kind = "Map field"
	}
	v := r.CreateViolation(ctx.RelPath, line,
		kind+" '"+variable.Name()+"' only grows: "+insertFn+"() adds a key drawn from outside data (hash, address, query, request…) on every call, and no code deletes, clears or replaces entries — a slow leak in a long-running process")
	v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
	v.WithSuggestion("Evict entries (delete on expiry, a periodic sweep, an LRU with a size cap), or document why the key set is bounded and suppress")
	v.WithContext("variable", variable.Name())
	v.WithContext("insert_function", insertFn)
	return v
}
