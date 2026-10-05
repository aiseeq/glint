package patterns

import (
	"errors"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"strconv"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
	"github.com/aiseeq/glint/pkg/sqlschema"
)

func init() {
	rules.Register(NewRequestIDUnparsedForUUIDColumnRule())
}

// RequestIDUnparsedForUUIDColumnRule detects an id the client sent - a path
// variable, a query parameter, a field of the decoded body - that reaches a
// call unparsed while the migrations make the column of that name uuid:
//
//	id := mux.Vars(req)["id"]
//	rec, err := r.service.Get(ctx, id)   // "abc" -> invalid input syntax for type uuid -> 500
//
// The client's typo fails in the database, the client gets a 500 for its own
// mistake and the log an ERROR that hides real failures. An id parsed with
// uuid.Parse on the way - in the handler or in a function it is handed to -
// is fine.
type RequestIDUnparsedForUUIDColumnRule struct {
	*rules.BaseRule
}

// NewRequestIDUnparsedForUUIDColumnRule creates the rule
func NewRequestIDUnparsedForUUIDColumnRule() *RequestIDUnparsedForUUIDColumnRule {
	return &RequestIDUnparsedForUUIDColumnRule{BaseRule: rules.NewBaseRule(
		"request-id-unparsed-for-uuid-column",
		"security",
		"Detects an id from the request path, query or body that reaches a call unparsed while its column is uuid — a malformed id fails in the database and the client gets a 500",
		core.SeverityMedium,
	)}
}

// AnalyzeFile is a no-op: the check needs types and the migrations.
func (r *RequestIDUnparsedForUUIDColumnRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough.
func (r *RequestIDUnparsedForUUIDColumnRule) RequiresSSA() bool { return false }

// AnalyzeGoProject reports the request ids that reach a call unparsed.
func (r *RequestIDUnparsedForUUIDColumnRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	return analyzeAgainstSchema(ctx, r.BaseRule,
		"Parse the id with uuid.Parse where it is read (a shared helper such as pathUUID/queryUUID) and answer 400 on failure",
		unparsedRequestIDs)
}

// analyzeAgainstSchema runs a typed check of every function of a project
// that needs the schema of its migrations; a project without migrations, or
// with one that does not load (the schema rules report it), is not checked.
func analyzeAgainstSchema(ctx *core.GoProjectContext, rule *rules.BaseRule, suggestion string,
	check func(funcScope, *sqlschema.Schema, *ast.FuncDecl) []funcFinding) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%s: nil Go project context", rule.Name())
	}
	schema, err := sqlschema.LoadCached(ctx.ProjectRoot, migrationDirs(rule))
	var migrationErr *sqlschema.MigrationError
	if errors.As(err, &migrationErr) {
		return nil, nil // the schema rules report the migration; nothing to check against
	}
	if err != nil {
		return nil, fmt.Errorf("list migrations: %w", err)
	}
	if schema == nil {
		return nil, nil
	}
	inner := &typedFuncRule{
		BaseRule:   rule,
		suggestion: suggestion,
		check: func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
			return check(scope, schema, fn)
		},
	}
	return inner.AnalyzeGoProject(ctx)
}

// requestIDRead is a read of an id the client sent: the node and the column
// name it stands for.
type requestIDRead struct {
	node   ast.Expr
	column string
}

// unparsedRequestIDs returns the request id reads of a handler whose value
// reaches a call with no uuid parse on the way.
func unparsedRequestIDs(scope funcScope, schema *sqlschema.Schema, fn *ast.FuncDecl) []funcFinding {
	request := handlerRequestParam(typedFunc{info: scope.info, decl: fn})
	if request == nil {
		return nil
	}
	parents := helpers.ParentMap(fn.Body)
	var findings []funcFinding
	reported := map[string]bool{}
	for _, read := range requestIDReads(scope.info, fn, request) {
		if reported[read.column] || !schema.ColumnMostlyOfType(read.column, "uuid") {
			continue
		}
		uses := readUses(scope.info, fn, parents, read.node)
		if len(uses) == 0 || anyUseParsed(scope, parents, uses) || !anyUseReachesCall(scope, parents, uses) {
			continue
		}
		reported[read.column] = true
		findings = append(findings, funcFinding{node: read.node, message: "The client's " + read.column +
			" reaches a call unparsed, and the column is uuid — a malformed id fails in the database and the client gets a 500 instead of a 400"})
	}
	return findings
}

// requestIDReads returns the id-named values a handler reads off the
// request: mux.Vars(req)["id"], req.URL.Query().Get("account_id"),
// req.FormValue, req.PathValue and the *ID string fields of a body decoded
// from the request.
func requestIDReads(info *types.Info, fn *ast.FuncDecl, request *types.Var) []requestIDRead {
	src := newRequestSources(info, fn, request)
	var reads []requestIDRead
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if read, ok := src.idRead(n); ok {
			reads = append(reads, read)
		}
		return true
	})
	return reads
}

// requestSources are the request of a handler and the variables holding
// parts of it: the query values, the path variables, the decoded bodies.
type requestSources struct {
	info    *types.Info
	request *types.Var
	queries map[types.Object]bool
	vars    map[types.Object]bool
	decoded map[types.Object]bool
}

func newRequestSources(info *types.Info, fn *ast.FuncDecl, request *types.Var) *requestSources {
	src := &requestSources{info: info, request: request,
		queries: map[types.Object]bool{}, vars: map[types.Object]bool{}, decoded: map[types.Object]bool{}}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			src.noteAssign(node)
		case *ast.CallExpr:
			src.noteDecode(node)
		}
		return true
	})
	return src
}

// isRequest reports the request itself.
func (src *requestSources) isRequest(e ast.Expr) bool {
	ident, ok := ast.Unparen(e).(*ast.Ident)
	return ok && src.info.Uses[ident] == src.request
}

// fromRequest reports an expression rooted at the request: req.URL.Query().
func (src *requestSources) fromRequest(e ast.Node) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		if ident, ok := n.(*ast.Ident); ok && src.info.Uses[ident] == src.request {
			found = true
		}
		return !found
	})
	return found
}

// noteAssign records query := req.URL.Query() and vars := mux.Vars(req).
func (src *requestSources) noteAssign(node *ast.AssignStmt) {
	if len(node.Lhs) != len(node.Rhs) {
		return
	}
	for i, rhs := range node.Rhs {
		ident, ok := node.Lhs[i].(*ast.Ident)
		obj := src.info.ObjectOf(ident)
		if !ok || obj == nil || !src.fromRequest(rhs) {
			continue
		}
		switch {
		case isURLValues(src.info.TypeOf(rhs)):
			src.queries[obj] = true
		case isVarsCall(rhs, src.isRequest):
			src.vars[obj] = true
		}
	}
}

// noteDecode records json.NewDecoder(req.Body).Decode(&body) and
// decodeJSON(req, &body).
func (src *requestSources) noteDecode(call *ast.CallExpr) {
	if !src.fromRequest(call) {
		return
	}
	for _, arg := range call.Args {
		unary, ok := ast.Unparen(arg).(*ast.UnaryExpr)
		if !ok || unary.Op != token.AND {
			continue
		}
		if ident, ok := ast.Unparen(unary.X).(*ast.Ident); ok && src.info.ObjectOf(ident) != nil {
			src.decoded[src.info.ObjectOf(ident)] = true
		}
	}
}

// idRead returns the request id a node reads, if it reads one.
func (src *requestSources) idRead(n ast.Node) (requestIDRead, bool) {
	switch node := n.(type) {
	case *ast.IndexExpr:
		ident, isIdent := ast.Unparen(node.X).(*ast.Ident)
		if !isVarsCall(node.X, src.isRequest) && (!isIdent || !src.vars[src.info.ObjectOf(ident)]) {
			return requestIDRead{}, false
		}
		if key, ok := stringLiteral(node.Index); ok && idKey(key) {
			return requestIDRead{node: node, column: snakeCase(key)}, true
		}
	case *ast.CallExpr:
		return src.queryRead(node)
	case *ast.SelectorExpr:
		ident, ok := ast.Unparen(node.X).(*ast.Ident)
		if !ok || !src.decoded[src.info.ObjectOf(ident)] || !idKey(node.Sel.Name) {
			return requestIDRead{}, false
		}
		if basic, ok := src.info.TypeOf(node).(*types.Basic); ok && basic.Kind() == types.String {
			return requestIDRead{node: node, column: snakeCase(node.Sel.Name)}, true
		}
	}
	return requestIDRead{}, false
}

// queryRead returns the id a call reads off the query or the form:
// query.Get("account_id"), req.FormValue("id"), req.PathValue("id").
func (src *requestSources) queryRead(call *ast.CallExpr) (requestIDRead, bool) {
	sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok || len(call.Args) != 1 {
		return requestIDRead{}, false
	}
	key, ok := stringLiteral(call.Args[0])
	if !ok || !idKey(key) {
		return requestIDRead{}, false
	}
	receiver, isIdent := ast.Unparen(sel.X).(*ast.Ident)
	query := sel.Sel.Name == "Get" && isURLValues(src.info.TypeOf(sel.X)) && (src.fromRequest(sel.X) || isIdent && src.queries[src.info.ObjectOf(receiver)])
	form := (sel.Sel.Name == "FormValue" || sel.Sel.Name == "PathValue") && src.isRequest(sel.X)
	if !query && !form {
		return requestIDRead{}, false
	}
	return requestIDRead{node: call, column: snakeCase(key)}, true
}

// isVarsCall reports a call of a router's Vars handed the request:
// mux.Vars(req).
func isVarsCall(expr ast.Expr, isRequest func(ast.Expr) bool) bool {
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok || len(call.Args) != 1 || !isRequest(call.Args[0]) {
		return false
	}
	sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "Vars"
}

// stringLiteral returns the value of a string literal.
func stringLiteral(expr ast.Expr) (string, bool) {
	lit, ok := ast.Unparen(expr).(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	value, err := strconv.Unquote(lit.Value)
	return value, err == nil
}

// idKey reports a name of an identifier: id, account_id, accountId, EntryID.
func idKey(name string) bool {
	lower := strings.ToLower(name)
	return lower == "id" || strings.HasSuffix(lower, "_id") || strings.HasSuffix(name, "Id") || strings.HasSuffix(name, "ID")
}

// readUses returns where the value of a read is used: the read itself when it
// is used in place, or the uses of the variable it is assigned to (possibly
// through strings.TrimSpace).
func readUses(info *types.Info, fn *ast.FuncDecl, parents map[ast.Node]ast.Node, read ast.Expr) []ast.Expr {
	holder := ast.Node(read)
	if call, ok := parents[read].(*ast.CallExpr); ok && isTrimCall(info, call) {
		holder = call
	}
	assign, ok := parents[holder].(*ast.AssignStmt)
	if !ok {
		return []ast.Expr{read}
	}
	var target types.Object
	for i, rhs := range assign.Rhs {
		if rhs == holder && i < len(assign.Lhs) {
			if ident, ok := assign.Lhs[i].(*ast.Ident); ok {
				target = info.ObjectOf(ident)
			}
		}
	}
	if target == nil {
		return nil
	}
	var uses []ast.Expr
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if ident, ok := n.(*ast.Ident); ok && info.Uses[ident] == target {
			uses = append(uses, ident)
		}
		return true
	})
	return uses
}

// isTrimCall reports strings.TrimSpace and its kin, which keep the value.
func isTrimCall(info *types.Info, call *ast.CallExpr) bool {
	callee := staticFunc(info, call)
	return callee != nil && callee.Pkg() != nil && callee.Pkg().Path() == "strings" && strings.HasPrefix(callee.Name(), "Trim")
}

// anyUseParsed reports a use handed to uuid.Parse, or to a function that
// checks that parameter itself, or tested by a check that refuses it:
// if !client.Allows(id) { return }.
func anyUseParsed(scope funcScope, parents map[ast.Node]ast.Node, uses []ast.Expr) bool {
	for _, use := range uses {
		call, index, ok := argumentOf(parents, use)
		if ok && (callParsesArgument(scope.info, scope.decls, call, index, 0) || refusingCheck(scope.info, parents, call)) {
			return true
		}
	}
	return false
}

// refusingCheck reports a call answering bool that decides an if whose
// branch returns: the value it is handed is refused unless it passes.
func refusingCheck(info *types.Info, parents map[ast.Node]ast.Node, call *ast.CallExpr) bool {
	if basic, ok := info.TypeOf(call).(*types.Basic); !ok || basic.Kind() != types.Bool && basic.Kind() != types.UntypedBool {
		return false
	}
	node := ast.Node(call)
	for {
		parent := parents[node]
		switch p := parent.(type) {
		case *ast.ParenExpr, *ast.UnaryExpr, *ast.BinaryExpr:
			node = p
			continue
		case *ast.IfStmt:
			if p.Cond != node || len(p.Body.List) == 0 {
				return false
			}
			_, returns := p.Body.List[len(p.Body.List)-1].(*ast.ReturnStmt)
			return returns
		}
		return false
	}
}

// anyUseReachesCall reports a use handed to a call that acts on it: a method
// or a function of the project or a library, not a logger, a responder or the
// standard library.
func anyUseReachesCall(scope funcScope, parents map[ast.Node]ast.Node, uses []ast.Expr) bool {
	for _, use := range uses {
		call, _, ok := argumentOf(parents, use)
		if !ok || helpers.IsLoggerCall(call) {
			continue
		}
		callee := staticFunc(scope.info, call)
		if callee == nil {
			if _, method := ast.Unparen(call.Fun).(*ast.SelectorExpr); method {
				return true
			}
			continue
		}
		if callee.Pkg() == nil || isStandardLibraryPath(callee.Pkg().Path()) || responderName.MatchString(callee.Name()) {
			continue
		}
		return true
	}
	return false
}

// argumentOf returns the call a value is handed to directly and its position
// among the arguments.
func argumentOf(parents map[ast.Node]ast.Node, use ast.Expr) (*ast.CallExpr, int, bool) {
	call, ok := parents[use].(*ast.CallExpr)
	if !ok {
		return nil, 0, false
	}
	for i, arg := range call.Args {
		if ast.Unparen(arg) == use {
			return call, i, true
		}
	}
	return nil, 0, false
}

// maxUUIDParseDepth bounds how deep calls are followed to find the parse.
const maxUUIDParseDepth = 3

// callParsesArgument reports a call that parses its index-th argument as a
// UUID: uuid.Parse itself, or a function of the project that hands that
// parameter on to one.
func callParsesArgument(info *types.Info, decls map[*types.Func]typedFuncDecl, call *ast.CallExpr, index, depth int) bool {
	callee := staticFunc(info, call)
	if callee == nil || callee.Pkg() == nil {
		return false
	}
	if strings.HasSuffix(callee.Pkg().Path(), "/uuid") && (strings.HasPrefix(callee.Name(), "Parse") || callee.Name() == "MustParse" || callee.Name() == "Validate") {
		return true
	}
	decl, ok := decls[callee.Origin()]
	if !ok || depth >= maxUUIDParseDepth {
		return false
	}
	params := paramObjects(decl)
	if index >= len(params) || params[index] == nil {
		return false
	}
	param := params[index]
	parents := helpers.ParentMap(decl.decl.Body)
	parsed := false
	ast.Inspect(decl.decl.Body, func(n ast.Node) bool {
		inner, ok := n.(*ast.CallExpr)
		if !ok || parsed {
			return !parsed
		}
		for i, arg := range inner.Args {
			ident, ok := ast.Unparen(arg).(*ast.Ident)
			if ok && decl.info.Uses[ident] == param && (refusingCheck(decl.info, parents, inner) || callParsesArgument(decl.info, decls, inner, i, depth+1)) {
				parsed = true
			}
		}
		return !parsed
	})
	return parsed
}
