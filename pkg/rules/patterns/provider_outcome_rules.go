package patterns

import (
	"cmp"
	"go/ast"
	"go/token"
	"go/types"
	"slices"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewErrorStatusPersistedWithoutCauseRule())
	rules.Register(NewErrorPathSkipsFailureRecordingRule())
	rules.Register(NewUnsupportedValueSilentlyDroppedRule())
	rules.Register(NewProviderSuccessFlagIgnoredRule())
	rules.Register(NewAmbiguousSendFailureRecordedAsFailedRule())
}

// failureStatusWords name the value of a status enum that says an operation
// failed for good.
var failureStatusWords = wordSet("error", "failed", "failure", "fail", "rejected", "declined")

// statusTypeWords name the enum type of an entity's lifecycle.
var statusTypeWords = wordSet("status", "state")

// causeFieldSubjects and causeFieldDetails make up the name of a field that
// keeps why an entity failed: ErrorMessage, FailureReason, LastErrorCode.
var (
	causeFieldSubjects = wordSet("error", "err", "failure", "fail")
	causeFieldDetails  = wordSet("message", "msg", "code", "reason", "text", "detail", "description")
)

// ambiguityWords in an error branch show that it tells an outcome the
// provider may still have executed (a timeout, a lost connection) from a
// rejection.
var ambiguityWords = wordSet("timeout", "deadline", "transport", "network", "net", "unknown", "ambiguous",
	"temporary", "uncertain", "unconfirmed", "indeterminate")

// sendCommandMethods are the provider commands that move money and are not
// safe to repeat: their outcome after a transport failure is unknown.
var sendCommandMethods = map[string]bool{
	"SendTransaction": true, "ExecutePayment": true, "SubmitPayment": true, "CreatePayout": true,
	"SendPayout": true, "TransferFunds": true, "RefundPayment": true, "CreateRefund": true, "SendRefund": true,
	"Charge": true, "CreateCharge": true, "Transfer": true, "CreateTransfer": true, "Payout": true,
}

// failureStatusConst reports a constant of a status enum whose name says the
// operation failed (domain.StatusError, StateFailed).
func failureStatusConst(info *types.Info, expr ast.Expr) bool {
	var ident *ast.Ident
	switch node := ast.Unparen(expr).(type) {
	case *ast.Ident:
		ident = node
	case *ast.SelectorExpr:
		ident = node.Sel
	default:
		return false
	}
	constant, ok := info.Uses[ident].(*types.Const)
	if !ok {
		return false
	}
	named, ok := constant.Type().(*types.Named)
	if !ok || !hasTokenIn(named.Obj().Name(), statusTypeWords) {
		return false
	}
	return hasTokenIn(constant.Name(), failureStatusWords) && !hasTokenIn(constant.Name(), ambiguityWords)
}

// keepsFailureCause reports a struct type, or a pointer to one, with a field
// that stores why the entity failed.
func keepsFailureCause(t types.Type) bool {
	if t == nil {
		return false
	}
	if ptr, ok := t.Underlying().(*types.Pointer); ok {
		t = ptr.Elem()
	}
	st, ok := t.Underlying().(*types.Struct)
	if !ok {
		return false
	}
	for field := range st.Fields() {
		if hasTokenIn(field.Name(), causeFieldSubjects) && hasTokenIn(field.Name(), causeFieldDetails) {
			return true
		}
	}
	return false
}

// inspectFuncBody walks a function body without entering function literals.
func inspectFuncBody(body *ast.BlockStmt, visit func(ast.Node) bool) {
	ast.Inspect(body, func(n ast.Node) bool {
		if _, ok := n.(*ast.FuncLit); ok {
			return false
		}
		return visit(n)
	})
}

// NewErrorStatusPersistedWithoutCauseRule creates
// error-status-persisted-without-cause: a function that receives an error and
// stores a failure status on an entity that has error fields, while the error
// itself reaches only the log:
//
//	func (s *Service) recordError(o *Order, op string, err error) {
//		s.logger.Error("failed", "error", err)
//		s.repo.UpdateStatus(o.ID, StatusError, o.Version) // ErrorMessage stays empty
//	}
func NewErrorStatusPersistedWithoutCauseRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"error-status-persisted-without-cause",
			"patterns",
			"Detects a failure status stored on an entity that has error fields while the error reaches only the log — the record says it failed and never why",
			core.SeverityMedium,
		),
		suggestion: "Store the error's code and message in the entity's error fields together with the failure status",
	}
	r.check = func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		info := scope.info
		var errParams []types.Object
		for _, field := range fn.Type.Params.List {
			for _, name := range field.Names {
				if obj := info.Defs[name]; obj != nil && isErrorType(obj.Type()) {
					errParams = append(errParams, obj)
				}
			}
		}
		if len(errParams) == 0 || !errorsOnlyLogged(info, fn.Body, errParams) {
			return nil
		}
		var findings []funcFinding
		inspectFuncBody(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || helpers.IsLoggerCall(call) || !storesFailureOfEntity(info, call) {
				return true
			}
			findings = append(findings, funcFinding{node: call, message: "A failure status is stored on an entity with error fields while the error reaches only the log — the record says it failed and never why"})
			return true
		})
		return findings
	}
	return r
}

// errorsOnlyLogged reports a body where every read of the error parameters
// is an argument of a logger call.
func errorsOnlyLogged(info *types.Info, body *ast.BlockStmt, errParams []types.Object) bool {
	var logged []*ast.CallExpr
	inspectFuncBody(body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok && helpers.IsLoggerCall(call) {
			logged = append(logged, call)
		}
		return true
	})
	only := true
	ast.Inspect(body, func(n ast.Node) bool {
		ident, ok := n.(*ast.Ident)
		if !ok || !containsObject(errParams, info.Uses[ident]) {
			return only
		}
		inLog := false
		for _, call := range logged {
			if ident.Pos() >= call.Lparen && ident.End() <= call.Rparen {
				inLog = true
			}
		}
		only = only && inLog
		return only
	})
	return only
}

func containsObject(objects []types.Object, obj types.Object) bool {
	for _, candidate := range objects {
		if obj != nil && candidate == obj {
			return true
		}
	}
	return false
}

// storesFailureOfEntity reports a call passing a failure status together with
// a field of an entity that keeps the failure's cause (o.ID of an *Order with
// ErrorMessage).
func storesFailureOfEntity(info *types.Info, call *ast.CallExpr) bool {
	failure, entity := false, false
	for _, arg := range call.Args {
		if failureStatusConst(info, arg) {
			failure = true
		}
		if sel, ok := ast.Unparen(arg).(*ast.SelectorExpr); ok && keepsFailureCause(info.TypeOf(sel.X)) {
			entity = true
		}
	}
	return failure && entity
}

// errBranch is an `if err != nil` block of a function that returns.
type errBranch struct {
	stmt     *ast.IfStmt
	ret      *ast.ReturnStmt
	entities []types.Object
}

// NewErrorPathSkipsFailureRecordingRule creates
// error-path-skips-failure-recording: a function whose error returns record
// the failure on the entity (s.recordError(ctx, order, "op", err)) and where
// a later error return of the same function does not — on that path the
// entity keeps its old status and no cause.
func NewErrorPathSkipsFailureRecordingRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"error-path-skips-failure-recording",
			"patterns",
			"Detects an error return that skips the failure recording its sibling error returns make on the same entity — on that path the entity keeps its old status and no cause",
			core.SeverityMedium,
		),
		suggestion: "Record the failure on the entity on this error path as the other error paths of the function do",
	}
	r.check = func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		branches := errReturnBranches(scope.info, fn.Body)
		first := token.NoPos
		var entities []types.Object
		for _, branch := range branches {
			if len(branch.entities) == 0 {
				continue
			}
			if !first.IsValid() {
				first = branch.stmt.Pos()
			}
			entities = append(entities, branch.entities...)
		}
		if !first.IsValid() {
			return nil
		}
		sources := errSourceCalls(fn.Body)
		var findings []funcFinding
		for _, branch := range branches {
			if branch.stmt.Pos() <= first || len(branch.entities) > 0 || insideRecordingBranch(branches, branch) {
				continue
			}
			// The recorder's own failure, and a claim another worker won, are
			// not failures of the entity.
			if source := sources[branch.stmt]; source != nil && hasTokenIn(callName(source), recorderWords, claimWords) {
				continue
			}
			if !anyDeclaredBefore(entities, branch.stmt.Pos()) {
				continue
			}
			findings = append(findings, funcFinding{node: branch.ret, message: "This error return skips the failure recording the function's other error returns make on the same entity — on this path the entity keeps its old status and no cause"})
		}
		return findings
	}
	return r
}

// errReturnBranches returns the `if err != nil` blocks of a body that end in
// a return of a non-nil error, with the entities their failure recorders get.
func errReturnBranches(info *types.Info, body *ast.BlockStmt) []errBranch {
	var branches []errBranch
	inspectFuncBody(body, func(n ast.Node) bool {
		stmt, ok := n.(*ast.IfStmt)
		if !ok {
			return true
		}
		errIdent := errNotNilIdent(info, stmt.Cond)
		if errIdent == nil || len(stmt.Body.List) == 0 {
			return true
		}
		ret, ok := stmt.Body.List[len(stmt.Body.List)-1].(*ast.ReturnStmt)
		if !ok || len(ret.Results) == 0 || isNilIdent(ret.Results[len(ret.Results)-1]) {
			return true
		}
		branches = append(branches, errBranch{stmt: stmt, ret: ret, entities: recordedEntities(info, stmt.Body, info.Uses[errIdent])})
		return true
	})
	return branches
}

// recorderWords name a call that records a failure: recordError, markFailed.
var recorderWords = wordSet("record", "fail", "failed", "failure")

// recordedEntities returns the entities a block hands to a failure recorder
// together with the error: s.recordError(ctx, order, "op", err).
func recordedEntities(info *types.Info, block *ast.BlockStmt, errObj types.Object) []types.Object {
	var entities []types.Object
	inspectFuncBody(block, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || helpers.IsLoggerCall(call) || !hasTokenIn(callName(call), recorderWords) {
			return true
		}
		passesErr := false
		var candidates []types.Object
		for _, arg := range call.Args {
			ident, ok := ast.Unparen(arg).(*ast.Ident)
			if !ok {
				continue
			}
			obj := info.Uses[ident]
			if obj == nil {
				continue
			}
			if obj == errObj {
				passesErr = true
				continue
			}
			if _, isVar := obj.(*types.Var); isVar && isProjectEntity(obj.Type()) {
				candidates = append(candidates, obj)
			}
		}
		if passesErr {
			entities = append(entities, candidates...)
		}
		return true
	})
	return entities
}

// claimWords name a call that takes a row for this worker: its failure means
// another one holds it.
var claimWords = wordSet("claim", "acquire", "lock", "lease")

// isProjectEntity reports a pointer to a struct of a module package (not the
// standard library: *http.Request is no entity) with a status or a failure
// cause field.
func isProjectEntity(t types.Type) bool {
	ptr, ok := t.Underlying().(*types.Pointer)
	if !ok {
		return false
	}
	named, ok := types.Unalias(ptr.Elem()).(*types.Named)
	if !ok || named.Obj().Pkg() == nil || !strings.Contains(strings.Split(named.Obj().Pkg().Path(), "/")[0], ".") {
		return false
	}
	st, ok := named.Underlying().(*types.Struct)
	if !ok {
		return false
	}
	for field := range st.Fields() {
		if hasTokenIn(field.Name(), statusTypeWords) {
			return true
		}
	}
	return keepsFailureCause(named)
}

// errSourceCalls maps the if statements of a body to the call whose error
// they check: the call of the if's init, or of the statement before it.
func errSourceCalls(body *ast.BlockStmt) map[*ast.IfStmt]*ast.CallExpr {
	sources := make(map[*ast.IfStmt]*ast.CallExpr)
	inspectFuncBody(body, func(n ast.Node) bool {
		block, ok := n.(*ast.BlockStmt)
		if !ok {
			return true
		}
		for i, stmt := range block.List {
			ifStmt, ok := stmt.(*ast.IfStmt)
			if !ok {
				continue
			}
			if call := statementCall(ifStmt); call != nil {
				sources[ifStmt] = call
			} else if i > 0 {
				sources[ifStmt] = statementCall(block.List[i-1])
			}
		}
		return true
	})
	return sources
}

func insideRecordingBranch(branches []errBranch, branch errBranch) bool {
	for _, other := range branches {
		if len(other.entities) > 0 && other.stmt != branch.stmt &&
			branch.stmt.Pos() >= other.stmt.Pos() && branch.stmt.End() <= other.stmt.End() {
			return true
		}
	}
	return false
}

func anyDeclaredBefore(objects []types.Object, pos token.Pos) bool {
	for _, obj := range objects {
		if obj.Pos() < pos {
			return true
		}
	}
	return false
}

// NewUnsupportedValueSilentlyDroppedRule creates
// unsupported-value-silently-dropped: a mapper without an error result that
// returns a field of its input and answers "" in several guards, one of them
// on that field's own value:
//
//	func walletCurrency(p *Payout) string {
//		if p.Country != "CN" { return "" }
//		if p.WalletCurrency != "CNY" { return "" }
//		return p.WalletCurrency
//	}
//
// A value the client set but the mapper does not support disappears from the
// outgoing request instead of being rejected.
func NewUnsupportedValueSilentlyDroppedRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"unsupported-value-silently-dropped",
			"patterns",
			"Detects a mapper without an error result that returns an input field and answers an empty value for the field's unsupported values — a value the client set disappears instead of being rejected",
			core.SeverityMedium,
		),
		suggestion: "Return an error for a set value the mapper does not support, and the empty value only when the input is empty",
	}
	r.check = func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		info := scope.info
		if fn.Type.Results == nil || len(fn.Type.Results.List) != 1 || len(fn.Type.Results.List[0].Names) > 1 {
			return nil
		}
		if basic, ok := info.TypeOf(fn.Type.Results.List[0].Type).(*types.Basic); !ok || basic.Kind() != types.String {
			return nil
		}
		list := fn.Body.List
		if len(list) < 3 {
			return nil
		}
		ret, ok := list[len(list)-1].(*ast.ReturnStmt)
		if !ok || len(ret.Results) != 1 {
			return nil
		}
		field := inputField(info, fn, ret.Results[0])
		if field == nil {
			return nil
		}
		guards, onField := 0, false
		for _, stmt := range list[:len(list)-1] {
			ifStmt, ok := stmt.(*ast.IfStmt)
			if !ok || ifStmt.Init != nil || ifStmt.Else != nil || !returnsEmptyString(ifStmt.Body) {
				continue
			}
			guards++
			if comparesFieldToValue(info, ifStmt.Cond, field) {
				onField = true
			}
		}
		if guards < 2 || !onField {
			return nil
		}
		return []funcFinding{{node: ret, message: "The mapper answers an empty value for every unsupported " + field.Name() + " and has no error result — a value the client set disappears from the result instead of being rejected"}}
	}
	return r
}

// inputField returns the field of a parameter an expression selects (p.F).
func inputField(info *types.Info, fn *ast.FuncDecl, expr ast.Expr) *types.Var {
	sel, ok := ast.Unparen(expr).(*ast.SelectorExpr)
	if !ok {
		return nil
	}
	base, ok := sel.X.(*ast.Ident)
	if !ok {
		return nil
	}
	param, ok := info.Uses[base].(*types.Var)
	if !ok || param.Parent() == nil || param.Parent().Parent() == nil || param.Pos() < fn.Type.Pos() || param.Pos() > fn.Type.End() {
		return nil
	}
	field, ok := info.Uses[sel.Sel].(*types.Var)
	if !ok || !field.IsField() {
		return nil
	}
	return field
}

func returnsEmptyString(body *ast.BlockStmt) bool {
	if len(body.List) != 1 {
		return false
	}
	ret, ok := body.List[0].(*ast.ReturnStmt)
	if !ok || len(ret.Results) != 1 {
		return false
	}
	lit, ok := ast.Unparen(ret.Results[0]).(*ast.BasicLit)
	return ok && lit.Kind == token.STRING && (lit.Value == `""` || lit.Value == "``")
}

// comparesFieldToValue reports a condition `x.F != <value>` whose value is
// not the empty string: the guard drops a set value.
func comparesFieldToValue(info *types.Info, cond ast.Expr, field *types.Var) bool {
	found := false
	ast.Inspect(cond, func(n ast.Node) bool {
		bin, ok := n.(*ast.BinaryExpr)
		if !ok || bin.Op != token.NEQ {
			return !found
		}
		for _, pair := range [][2]ast.Expr{{bin.X, bin.Y}, {bin.Y, bin.X}} {
			sel, ok := ast.Unparen(pair[0]).(*ast.SelectorExpr)
			if !ok || info.Uses[sel.Sel] != field {
				continue
			}
			if lit, ok := ast.Unparen(pair[1]).(*ast.BasicLit); ok && (lit.Value == `""` || lit.Value == "``") {
				continue
			}
			found = true
		}
		return !found
	})
	return found
}

// NewProviderSuccessFlagIgnoredRule creates provider-success-flag-ignored: a
// bool a call decodes a response into (var ok bool; c.post(path, body, &ok))
// that nothing reads — the provider answering false is taken for success.
func NewProviderSuccessFlagIgnoredRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"provider-success-flag-ignored",
			"patterns",
			"Detects a bool a response is decoded into that nothing reads — the remote side answering false is taken for success",
			core.SeverityHigh,
		),
		suggestion: "Check the decoded flag and return an error when the remote side did not confirm the operation",
	}
	r.check = func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		info := scope.info
		var findings []funcFinding
		for _, flag := range declaredBools(info, fn.Body) {
			if call := onlyDecodedInto(info, fn.Body, flag); call != nil {
				findings = append(findings, funcFinding{node: call, message: "The response is decoded into " + flag.Name() + " and nothing reads it — the remote side answering false is taken for success"})
			}
		}
		return findings
	}
	return r
}

// declaredBools returns the variables a body declares as `var x bool`.
func declaredBools(info *types.Info, body *ast.BlockStmt) []types.Object {
	var flags []types.Object
	inspectFuncBody(body, func(n ast.Node) bool {
		decl, ok := n.(*ast.GenDecl)
		if !ok || decl.Tok != token.VAR {
			return true
		}
		for _, spec := range decl.Specs {
			value, ok := spec.(*ast.ValueSpec)
			if !ok || len(value.Values) > 0 {
				continue
			}
			for _, name := range value.Names {
				obj := info.Defs[name]
				if obj != nil && types.Identical(obj.Type(), types.Typ[types.Bool]) {
					flags = append(flags, obj)
				}
			}
		}
		return true
	})
	return flags
}

// onlyDecodedInto returns the call a variable's address is passed to when
// that is the variable's only use.
func onlyDecodedInto(info *types.Info, body *ast.BlockStmt, obj types.Object) *ast.CallExpr {
	var target *ast.CallExpr
	addressed := make(map[*ast.Ident]bool)
	inspectFuncBody(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		for _, arg := range call.Args {
			unary, ok := ast.Unparen(arg).(*ast.UnaryExpr)
			if !ok || unary.Op != token.AND {
				continue
			}
			if ident, ok := ast.Unparen(unary.X).(*ast.Ident); ok && info.Uses[ident] == obj {
				addressed[ident] = true
				if target == nil {
					target = call
				}
			}
		}
		return true
	})
	if target == nil {
		return nil
	}
	other := false
	ast.Inspect(body, func(n ast.Node) bool {
		if ident, ok := n.(*ast.Ident); ok && info.Uses[ident] == obj && !addressed[ident] {
			other = true
		}
		return !other
	})
	if other {
		return nil
	}
	return target
}

// NewAmbiguousSendFailureRecordedAsFailedRule creates
// ambiguous-send-failure-recorded-as-failed: the error branch of a provider
// command that moves money (SendTransaction, CreatePayout) stores a
// definitive failure status, directly or through a recorder, without telling
// a timeout or a lost connection from a rejection. A transport failure after
// the provider accepted the command marks a live payment failed, and it can
// be sent again.
func NewAmbiguousSendFailureRecordedAsFailedRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"ambiguous-send-failure-recorded-as-failed",
			"patterns",
			"Detects a failed money-moving provider command recorded as a definitive failure whatever the error — a timeout after the provider accepted it marks a live payment failed",
			core.SeverityHigh,
		),
		suggestion: "Tell transport and timeout errors from a provider rejection and store an unknown-outcome status for them, resolved by a status check",
	}
	r.check = func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		info := scope.info
		var findings []funcFinding
		for ifStmt, source := range errSourceCalls(fn.Body) {
			if errNotNilIdent(info, ifStmt.Cond) == nil || !isForeignSendCommand(info, fn, source) || mentionsAmbiguity(ifStmt.Body) {
				continue
			}
			if call := failureRecording(scope, ifStmt.Body, 2); call != nil {
				findings = append(findings, funcFinding{node: call, message: "The failed provider command is recorded as a definitive failure whatever the error — a timeout after the provider accepted it marks a live payment failed"})
			}
		}
		slices.SortFunc(findings, func(a, b funcFinding) int { return cmp.Compare(a.node.Pos(), b.node.Pos()) })
		return findings
	}
	return r
}

// isForeignSendCommand reports a money-moving command called on a client of
// another package.
func isForeignSendCommand(info *types.Info, fn *ast.FuncDecl, call *ast.CallExpr) bool {
	if call == nil {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || !sendCommandMethods[sel.Sel.Name] {
		return false
	}
	method, ok := info.Uses[sel.Sel].(*types.Func)
	own := info.Defs[fn.Name]
	return ok && method.Pkg() != nil && own != nil && method.Pkg() != own.Pkg()
}

func mentionsAmbiguity(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if ident, ok := n.(*ast.Ident); ok && hasTokenIn(ident.Name, ambiguityWords) {
			found = true
		}
		return !found
	})
	return found
}

// failureRecording returns the call of a block that stores a failure status:
// directly, or through a function of the project that does (depth levels).
func failureRecording(scope funcScope, block *ast.BlockStmt, depth int) *ast.CallExpr {
	var found *ast.CallExpr
	inspectFuncBody(block, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || found != nil {
			return found == nil
		}
		for _, arg := range call.Args {
			if failureStatusConst(scope.info, arg) {
				found = call
				return false
			}
		}
		if depth > 0 {
			if decl, ok := scope.callee(call); ok && decl.decl.Body != nil {
				inner := funcScope{info: decl.info, decls: scope.decls, callers: scope.callers}
				if failureRecording(inner, decl.decl.Body, depth-1) != nil {
					found = call
					return false
				}
			}
		}
		return true
	})
	return found
}
