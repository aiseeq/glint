package gorules

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"sort"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
)

func init() { rules.Register(NewFieldNilCheckInconsistentRule()) }

// FieldNilCheckInconsistentRule detects a receiver field checked for nil in
// one method and dereferenced without a nil check in another. For example, if
// positions checks r.portfolio for nil, report flags an unguarded
// r.portfolio.Valuation call in report. Not flagged: checks only in Close,
// Stop, or Shutdown, tests, map reads, or uses guarded in the same method.
// Empty returns in methods without results and nil-only returns from
// error-only methods are not treated as optionality signals. Refusal branches
// that report an HTTP or logged error, or return false from a bool result, are
// not treated as optionality signals either. Nil checks that initialize the
// field are also not treated as optionality signals. Not flagged: an
// unexported helper whose every package-local call is reached after a nil
// check for the same receiver field, including through protected helpers;
// exported helpers and helpers with an unprotected or unknown caller remain
// checked.
type FieldNilCheckInconsistentRule struct{ *rules.BaseRule }

// NewFieldNilCheckInconsistentRule creates the field nil check rule. Medium:
// a field set by construction on every path that reaches the dereference is
// an invariant the rule does not see, so a finding asks for a look, not a stop.
func NewFieldNilCheckInconsistentRule() *FieldNilCheckInconsistentRule {
	return &FieldNilCheckInconsistentRule{BaseRule: rules.NewBaseRule(
		"field-nil-check-inconsistent", "patterns",
		"Detects a receiver field checked for nil in one method and dereferenced without a nil check in another",
		core.SeverityMedium,
	)}
}

// AnalyzeFile is unused because the rule needs project-wide method information.
func (*FieldNilCheckInconsistentRule) AnalyzeFile(*core.FileContext) []*core.Violation { return nil }

// RequiresSSA reports that the rule uses typed syntax without SSA.
func (*FieldNilCheckInconsistentRule) RequiresSSA() bool { return false }

// AnalyzeGoProject checks receiver fields across the project's methods.
func (r *FieldNilCheckInconsistentRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%s: nil Go project context", r.Name())
	}
	var methods []fieldNilMethod
	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil || pkg.Package.TypesInfo == nil {
			continue
		}
		for _, file := range pkg.Files {
			if file == nil || file.IsTestFile() || file.GoAST == nil {
				continue
			}
			methods = append(methods, collectFieldNilMethods(file, pkg.Package.TypesInfo)...)
		}
	}
	return r.analyzeMethods(methods), nil
}

type fieldNilMethod struct {
	decl *ast.FuncDecl
	info *types.Info
	recv *types.Named
	file *core.FileContext
}

func collectFieldNilMethods(file *core.FileContext, info *types.Info) []fieldNilMethod {
	var methods []fieldNilMethod
	for _, decl := range file.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || fn.Recv == nil || len(fn.Recv.List) == 0 {
			continue
		}
		t := info.TypeOf(fn.Recv.List[0].Type)
		if t == nil {
			continue
		}
		if ptr, ok := t.Underlying().(*types.Pointer); ok {
			t = ptr.Elem()
		}
		recv, ok := t.(*types.Named)
		if ok {
			methods = append(methods, fieldNilMethod{decl: fn, info: info, recv: recv, file: file})
		}
	}
	return methods
}

func (r *FieldNilCheckInconsistentRule) analyzeMethods(methods []fieldNilMethod) []*core.Violation {
	optional, softMethods, checkedMethods := fieldNilOptionalFields(methods)
	var violations []*core.Violation
	fields := make([]*types.Var, 0, len(optional))
	for field := range optional {
		fields = append(fields, field)
	}
	sort.Slice(fields, func(i, j int) bool { return fields[i].Pos() < fields[j].Pos() })
	for _, field := range fields {
		violations = append(violations, r.analyzeField(methods, field, optional[field], softMethods[field], checkedMethods[field])...)
	}
	sort.SliceStable(violations, func(i, j int) bool {
		if violations[i].File != violations[j].File {
			return violations[i].File < violations[j].File
		}
		return violations[i].Line < violations[j].Line
	})
	return violations
}

func fieldNilOptionalFields(methods []fieldNilMethod) (map[*types.Var]fieldNilMethod, map[*types.Var]map[*ast.FuncDecl]bool, map[*types.Var]map[*ast.FuncDecl]bool) {
	optional := make(map[*types.Var]fieldNilMethod)
	softMethods := make(map[*types.Var]map[*ast.FuncDecl]bool)
	checkedMethods := make(map[*types.Var]map[*ast.FuncDecl]bool)
	setupManaged := make(map[*types.TypeName]bool)
	for _, method := range methods {
		if method.decl.Name.Name == "CheckTools" {
			setupManaged[method.recv.Obj()] = true
		}
	}
	for _, method := range methods {
		if fieldNilLifecycle(method.decl.Name.Name) {
			continue
		}
		ast.Inspect(method.decl.Body, func(n ast.Node) bool {
			bin, ok := n.(*ast.BinaryExpr)
			if !ok || (bin.Op != token.EQL && bin.Op != token.NEQ) {
				return true
			}
			field := fieldNilCompared(method.info, method.recv, bin)
			if field == nil || !fieldNilType(field.Type()) {
				return true
			}
			if fieldNilInDeferredFunc(method.decl.Body, bin) {
				return true
			}
			if setupManaged[method.recv.Obj()] {
				return true
			}
			if fieldNilSoftComparison(method, bin, field) {
				if _, exists := optional[field]; !exists {
					optional[field] = method
				}
				if softMethods[field] == nil {
					softMethods[field] = make(map[*ast.FuncDecl]bool)
				}
				softMethods[field][method.decl] = true
			}
			if checkedMethods[field] == nil {
				checkedMethods[field] = make(map[*ast.FuncDecl]bool)
			}
			checkedMethods[field][method.decl] = true
			return true
		})
	}
	return optional, softMethods, checkedMethods
}

func (r *FieldNilCheckInconsistentRule) analyzeField(methods []fieldNilMethod, field *types.Var, checkedIn fieldNilMethod, softMethods, checkedMethods map[*ast.FuncDecl]bool) []*core.Violation {
	unguarded := make(map[*ast.FuncDecl]ast.Node)
	methodCalls := make(map[*ast.FuncDecl][]fieldNilCall)
	boolGuards := fieldNilBoolGuardMethods(methods, field)
	for _, method := range methods {
		if method.recv.Obj() != checkedIn.recv.Obj() {
			continue
		}
		flow := &fieldNilFlow{
			info: method.info, recv: method.recv, field: field,
			decl:        method.decl,
			guardErrors: fieldNilGuardErrors(method, methods, field),
			boolGuards:  boolGuards,
		}
		(&patternkit.FlowWalker[fieldNilState, struct{}]{Rule: flow}).Walk(method.decl.Body, fieldNilState{live: true}, struct{}{})
		methodCalls[method.decl] = flow.calls
		if !checkedMethods[method.decl] && flow.deref != nil && !fieldNilInDeferredFunc(method.decl.Body, flow.deref) {
			unguarded[method.decl] = flow.deref
		}
	}
	protected := fieldNilProtectedMethods(methods, field, methodCalls)
	limit := max(len(softMethods), 2)
	if len(unguarded) > limit {
		return nil
	}
	var violations []*core.Violation
	for _, method := range methods {
		deref := unguarded[method.decl]
		if deref == nil || fieldNilLifecycle(method.decl.Name.Name) || protected[method.decl] {
			continue
		}
		file := method.file
		line := file.LineFor(deref)
		if file.IsSuppressed(line, r.Name()) {
			continue
		}
		pos := checkedIn.file.GoFileSet.Position(checkedIn.decl.Pos())
		v := r.CreateViolation(file.RelPath, line, fmt.Sprintf("%s.%s is dereferenced without a nil check; %s checked it at %s:%d", checkedIn.recv.Obj().Name(), field.Name(), checkedIn.decl.Name.Name, checkedIn.file.RelPath, pos.Line))
		v.WithCode(strings.TrimSpace(file.GetLine(line)))
		v.WithSuggestion("Check the field for nil in this method before using it")
		violations = append(violations, v)
	}
	return violations
}

func fieldNilBoolGuardMethods(methods []fieldNilMethod, field *types.Var) map[*types.Func]bool {
	guards := make(map[*types.Func]bool)
	owner := fieldNilFieldOwner(methods, field)
	for _, method := range methods {
		if method.recv.Obj() != owner {
			continue
		}
		obj, _ := method.info.Defs[method.decl.Name].(*types.Func)
		if obj == nil {
			continue
		}
		sig, ok := obj.Type().(*types.Signature)
		if !ok || sig.Results() == nil || sig.Results().Len() != 1 || !types.Identical(sig.Results().At(0).Type(), types.Typ[types.Bool]) {
			continue
		}
		seen := false
		valid := true
		ast.Inspect(method.decl.Body, func(node ast.Node) bool {
			ret, ok := node.(*ast.ReturnStmt)
			if !ok {
				return true
			}
			if len(ret.Results) != 1 {
				valid = false
				return false
			}
			if fieldNilIsFalse(ret.Results[0]) {
				return true
			}
			if !fieldNilBoolExprEnsuresNonNil(method, ret.Results[0], field) {
				valid = false
				return false
			}
			seen = true
			return true
		})
		if valid && seen {
			guards[obj] = true
		}
	}
	return guards
}

func fieldNilBoolExprEnsuresNonNil(method fieldNilMethod, expr ast.Expr, field *types.Var) bool {
	switch expr := ast.Unparen(expr).(type) {
	case *ast.BinaryExpr:
		if expr.Op == token.LAND {
			return fieldNilBoolExprEnsuresNonNil(method, expr.X, field) || fieldNilBoolExprEnsuresNonNil(method, expr.Y, field)
		}
		return expr.Op == token.NEQ && fieldNilCompared(method.info, method.recv, expr) == field
	default:
		return false
	}
}

type fieldNilCall struct {
	target  *types.Func
	guarded bool
}

func fieldNilProtectedMethods(methods []fieldNilMethod, field *types.Var, calls map[*ast.FuncDecl][]fieldNilCall) map[*ast.FuncDecl]bool {
	callers := make(map[*types.Func][]struct {
		caller  *ast.FuncDecl
		guarded bool
	})
	methodByObject := make(map[*types.Func]fieldNilMethod)
	for _, method := range methods {
		if method.recv.Obj() != fieldNilFieldOwner(methods, field) {
			continue
		}
		obj, _ := method.info.Defs[method.decl.Name].(*types.Func)
		if obj == nil {
			continue
		}
		methodByObject[obj] = method
	}
	for caller, methodCalls := range calls {
		for _, call := range methodCalls {
			if _, ok := methodByObject[call.target]; !ok {
				continue
			}
			callers[call.target] = append(callers[call.target], struct {
				caller  *ast.FuncDecl
				guarded bool
			}{caller: caller, guarded: call.guarded})
		}
	}
	protected := make(map[*ast.FuncDecl]bool)
	for changed := true; changed; {
		changed = false
		for obj, method := range methodByObject {
			if method.decl.Name.IsExported() || protected[method.decl] || len(callers[obj]) == 0 {
				continue
			}
			safe := true
			for _, call := range callers[obj] {
				if !call.guarded && !protected[call.caller] {
					safe = false
					break
				}
			}
			if safe {
				protected[method.decl] = true
				changed = true
			}
		}
	}
	return protected
}

func fieldNilFieldOwner(methods []fieldNilMethod, field *types.Var) *types.TypeName {
	for _, method := range methods {
		if fieldNilReceiverField(method.recv, field) != nil {
			return method.recv.Obj()
		}
	}
	return nil
}

func fieldNilInDeferredFunc(body *ast.BlockStmt, target ast.Node) bool {
	found := false
	ast.Inspect(body, func(node ast.Node) bool {
		deferred, ok := node.(*ast.DeferStmt)
		if !ok {
			return true
		}
		literal, ok := ast.Unparen(deferred.Call.Fun).(*ast.FuncLit)
		if !ok {
			return true
		}
		ast.Inspect(literal.Body, func(n ast.Node) bool {
			if n == target {
				found = true
				return false
			}
			return !found
		})
		return !found
	})
	return found
}

func fieldNilLifecycle(name string) bool {
	return name == "Close" || name == "Stop" || name == "Shutdown"
}

func fieldNilType(t types.Type) bool {
	switch t.Underlying().(type) {
	case *types.Pointer, *types.Interface, *types.Signature, *types.Map:
		return true
	default:
		return false
	}
}

func fieldNilCompared(info *types.Info, recv *types.Named, bin *ast.BinaryExpr) *types.Var {
	var expr ast.Expr
	if fieldNilIsNil(bin.X) {
		expr = bin.Y
	} else if fieldNilIsNil(bin.Y) {
		expr = bin.X
	} else {
		return nil
	}
	sel, ok := ast.Unparen(expr).(*ast.SelectorExpr)
	if !ok {
		return nil
	}
	selection := info.Selections[sel]
	if selection == nil || selection.Kind() != types.FieldVal {
		return nil
	}
	field, ok := selection.Obj().(*types.Var)
	if !ok || !field.IsField() {
		return nil
	}
	return fieldNilReceiverField(recv, field)
}

func fieldNilReceiverField(recv *types.Named, field *types.Var) *types.Var {
	st, ok := recv.Underlying().(*types.Struct)
	if !ok {
		return nil
	}
	for candidate := range st.Fields() {
		if candidate == field || candidate.Origin() == field.Origin() {
			return candidate
		}
	}
	return nil
}

func fieldNilIsNil(expr ast.Expr) bool {
	id, ok := ast.Unparen(expr).(*ast.Ident)
	return ok && id.Name == "nil"
}

func fieldNilSoftComparison(method fieldNilMethod, comparison *ast.BinaryExpr, field *types.Var) bool {
	if comparison.Op != token.EQL && comparison.Op != token.NEQ {
		return false
	}
	soft := false
	ast.Inspect(method.decl.Body, func(node ast.Node) bool {
		stmt, ok := node.(*ast.IfStmt)
		if !ok || ast.Unparen(stmt.Cond) != comparison || fieldNilCompared(method.info, method.recv, comparison) != field {
			return true
		}
		var nilBranch ast.Stmt = stmt.Body
		if comparison.Op == token.NEQ {
			nilBranch = stmt.Else
		}
		if nilBranch == nil {
			soft = comparison.Op == token.NEQ &&
				!fieldNilFollowingBranchRefuses(method, stmt) &&
				!fieldNilFollowingBranchInitializes(method, stmt, field)
			return false
		}
		soft = !fieldNilBranchInitializes(method, nilBranch, field) && fieldNilBranchSoftReturn(method, nilBranch)
		return false
	})
	return soft
}

func fieldNilFollowingBranchInitializes(method fieldNilMethod, target *ast.IfStmt, field *types.Var) bool {
	initialized := false
	ast.Inspect(method.decl.Body, func(node ast.Node) bool {
		block, ok := node.(*ast.BlockStmt)
		if !ok {
			return true
		}
		for i, stmt := range block.List {
			if stmt != target {
				continue
			}
			tail := &ast.BlockStmt{List: block.List[i+1:]}
			initialized = fieldNilBranchInitializes(method, tail, field)
			return false
		}
		return !initialized
	})
	return initialized
}

func fieldNilBranchInitializes(method fieldNilMethod, branch ast.Stmt, field *types.Var) bool {
	block, ok := branch.(*ast.BlockStmt)
	if !ok {
		block = &ast.BlockStmt{List: []ast.Stmt{branch}}
	}
	for _, stmt := range block.List {
		assign, ok := stmt.(*ast.AssignStmt)
		if !ok {
			return false
		}
		for i, lhs := range assign.Lhs {
			if fieldNilAssignedField(method.info, method.recv, lhs) != field {
				continue
			}
			rhsIndex := min(i, len(assign.Rhs)-1)
			if rhsIndex >= 0 && fieldNilKnownNonNil(assign.Rhs[rhsIndex]) {
				return true
			}
		}
	}
	return false
}

func fieldNilAssignedField(info *types.Info, recv *types.Named, expr ast.Expr) *types.Var {
	sel, ok := ast.Unparen(expr).(*ast.SelectorExpr)
	if !ok {
		return nil
	}
	selection := info.Selections[sel]
	if selection == nil || selection.Kind() != types.FieldVal {
		return nil
	}
	field, ok := selection.Obj().(*types.Var)
	if !ok || !field.IsField() {
		return nil
	}
	return fieldNilReceiverField(recv, field)
}

func fieldNilKnownNonNil(expr ast.Expr) bool {
	switch value := ast.Unparen(expr).(type) {
	case *ast.UnaryExpr:
		return value.Op == token.AND
	case *ast.CompositeLit:
		return true
	case *ast.CallExpr:
		id, ok := ast.Unparen(value.Fun).(*ast.Ident)
		return ok && (id.Name == "make" || id.Name == "new")
	default:
		return false
	}
}

func fieldNilFollowingBranchRefuses(method fieldNilMethod, target *ast.IfStmt) bool {
	refuses := false
	ast.Inspect(method.decl.Body, func(node ast.Node) bool {
		block, ok := node.(*ast.BlockStmt)
		if !ok {
			return true
		}
		for i, stmt := range block.List {
			if stmt != target {
				continue
			}
			tail := &ast.BlockStmt{List: block.List[i+1:]}
			if fieldNilBranchFails(method, tail) || fieldNilBranchRefuses(method, tail, fieldNilLastStatement(tail)) {
				refuses = true
			}
			return false
		}
		return !refuses
	})
	return refuses
}

func fieldNilLastStatement(block *ast.BlockStmt) ast.Stmt {
	if block == nil || len(block.List) == 0 {
		return nil
	}
	return block.List[len(block.List)-1]
}

func fieldNilBranchSoftReturn(method fieldNilMethod, stmt ast.Stmt) bool {
	original := stmt
	for {
		block, ok := stmt.(*ast.BlockStmt)
		if !ok {
			break
		}
		if len(block.List) == 0 {
			return false
		}
		stmt = block.List[len(block.List)-1]
	}
	ret, ok := stmt.(*ast.ReturnStmt)
	if !ok {
		return false
	}
	if fieldNilBranchRefuses(method, original, stmt) {
		return false
	}
	obj := method.info.Defs[method.decl.Name]
	if obj != nil {
		if sig, ok := obj.Type().(*types.Signature); ok && !fieldNilBranchReportsDegradation(original) {
			noResult := (sig.Results() == nil || sig.Results().Len() == 0) && len(ret.Results) == 0
			nilErrorOnly := sig.Results() != nil && sig.Results().Len() == 1 && len(ret.Results) == 1 && types.AssignableTo(sig.Results().At(0).Type(), types.Universe.Lookup("error").Type()) && fieldNilIsNil(ret.Results[0])
			if noResult || nilErrorOnly {
				return false
			}
		}
	}
	return !fieldNilBranchFails(method, stmt)
}

func fieldNilBranchRefuses(method fieldNilMethod, branch, final ast.Stmt) bool {
	if fieldNilReturnsFalse(method, final) || fieldNilReportsHTTPError(method, branch) {
		return true
	}
	hasResponseWriter := fieldNilHasResponseWriter(method)
	refuses := false
	ast.Inspect(branch, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		if hasResponseWriter && fieldNilWritesErrorResponse(method, call) {
			refuses = true
			return false
		}
		if fieldNilErrorLogCall(call) {
			refuses = true
			return false
		}
		return true
	})
	return refuses
}

func fieldNilReturnsFalse(method fieldNilMethod, stmt ast.Stmt) bool {
	ret, ok := stmt.(*ast.ReturnStmt)
	if !ok || len(ret.Results) == 0 {
		return false
	}
	obj := method.info.Defs[method.decl.Name]
	if obj == nil {
		return false
	}
	sig, ok := obj.Type().(*types.Signature)
	if !ok || sig.Results() == nil || sig.Results().Len() == 0 || len(ret.Results) < sig.Results().Len() {
		return false
	}
	last := sig.Results().At(sig.Results().Len() - 1).Type()
	return types.Identical(last, types.Typ[types.Bool]) && fieldNilIsFalse(ret.Results[len(ret.Results)-1])
}

func fieldNilIsFalse(expr ast.Expr) bool {
	id, ok := ast.Unparen(expr).(*ast.Ident)
	return ok && id.Name == "false"
}

func fieldNilReportsHTTPError(method fieldNilMethod, branch ast.Stmt) bool {
	found := false
	ast.Inspect(branch, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		for _, arg := range call.Args {
			if fieldNilHTTPErrorStatus(method.info, arg) {
				found = true
				return false
			}
		}
		return !found
	})
	return found
}

func fieldNilHTTPErrorStatus(info *types.Info, expr ast.Expr) bool {
	tv, ok := info.Types[ast.Unparen(expr)]
	if !ok || tv.Value == nil || tv.Value.Kind() != constant.Int {
		return false
	}
	status, ok := constant.Int64Val(tv.Value)
	return ok && status >= 400 && status <= 599
}

func fieldNilHasResponseWriter(method fieldNilMethod) bool {
	if method.decl.Type.Params == nil {
		return false
	}
	for _, param := range method.decl.Type.Params.List {
		typ := method.info.TypeOf(param.Type)
		named, ok := typ.(*types.Named)
		if !ok || named.Obj().Name() != "ResponseWriter" || named.Obj().Pkg() == nil || named.Obj().Pkg().Path() != "net/http" {
			continue
		}
		return true
	}
	return false
}

func fieldNilWritesErrorResponse(method fieldNilMethod, call *ast.CallExpr) bool {
	writerNames := make(map[string]bool)
	if method.decl.Type.Params != nil {
		for _, param := range method.decl.Type.Params.List {
			typ := method.info.TypeOf(param.Type)
			named, ok := typ.(*types.Named)
			if !ok || named.Obj().Name() != "ResponseWriter" || named.Obj().Pkg() == nil || named.Obj().Pkg().Path() != "net/http" {
				continue
			}
			for _, name := range param.Names {
				writerNames[name.Name] = true
			}
		}
	}
	hasWriter, hasErrorOrText := false, false
	for _, arg := range call.Args {
		if id, ok := ast.Unparen(arg).(*ast.Ident); ok && writerNames[id.Name] {
			hasWriter = true
		}
		typ := method.info.TypeOf(arg)
		if typ == nil {
			continue
		}
		if types.AssignableTo(typ, types.Universe.Lookup("error").Type()) || types.AssignableTo(typ, types.Typ[types.String]) {
			hasErrorOrText = true
		}
	}
	return hasWriter && hasErrorOrText
}

func fieldNilErrorLogCall(call *ast.CallExpr) bool {
	selector, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	return ok && strings.HasPrefix(selector.Sel.Name, "Error")
}

func fieldNilBranchReportsDegradation(stmt ast.Stmt) bool {
	reports := false
	ast.Inspect(stmt, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
		if !ok {
			return true
		}
		switch selector.Sel.Name {
		case "Warn", "Warning", "Error", "Info", "Debug", "Printf", "Println":
			reports = true
		}
		return !reports
	})
	return reports
}

func fieldNilBranchFails(method fieldNilMethod, stmt ast.Stmt) bool {
	switch branch := stmt.(type) {
	case *ast.BlockStmt:
		if len(branch.List) == 0 {
			return false
		}
		return fieldNilBranchFails(method, branch.List[len(branch.List)-1])
	case *ast.ReturnStmt:
		return fieldNilBranchReturnsError(method, branch)
	case *ast.ExprStmt:
		call, ok := branch.X.(*ast.CallExpr)
		if !ok {
			return false
		}
		switch fun := ast.Unparen(call.Fun).(type) {
		case *ast.Ident:
			return fun.Name == "panic"
		case *ast.SelectorExpr:
			return strings.HasPrefix(fun.Sel.Name, "Fatal")
		}
	case *ast.IfStmt:
		return branch.Else != nil && fieldNilBranchFails(method, branch.Body) && fieldNilBranchFails(method, branch.Else)
	}
	return false
}

func fieldNilHasHardCheck(method fieldNilMethod, field *types.Var) bool {
	found := false
	ast.Inspect(method.decl.Body, func(node ast.Node) bool {
		stmt, ok := node.(*ast.IfStmt)
		if !ok {
			return true
		}
		comparison, ok := ast.Unparen(stmt.Cond).(*ast.BinaryExpr)
		if !ok || fieldNilCompared(method.info, method.recv, comparison) != field {
			return true
		}
		nilBranch := ast.Stmt(stmt.Body)
		if comparison.Op == token.NEQ {
			nilBranch = stmt.Else
		}
		if fieldNilBranchReturnsError(method, nilBranch) {
			found = true
			return false
		}
		return true
	})
	return found
}

func fieldNilBranchReturnsError(method fieldNilMethod, stmt ast.Stmt) bool {
	switch branch := stmt.(type) {
	case *ast.BlockStmt:
		if len(branch.List) == 0 {
			return false
		}
		return fieldNilBranchReturnsError(method, branch.List[len(branch.List)-1])
	case *ast.ReturnStmt:
		obj := method.info.Defs[method.decl.Name]
		if obj == nil {
			return false
		}
		sig, ok := obj.Type().(*types.Signature)
		if !ok || sig.Results() == nil {
			return false
		}
		errType := types.Universe.Lookup("error").Type()
		for i := 0; i < sig.Results().Len() && i < len(branch.Results); i++ {
			if types.AssignableTo(sig.Results().At(i).Type(), errType) && !fieldNilIsNil(branch.Results[i]) {
				return true
			}
		}
	}
	return false
}

func fieldNilGuardErrors(method fieldNilMethod, methods []fieldNilMethod, field *types.Var) map[types.Object]bool {
	guards := make(map[types.Object]bool)
	recvName := fieldNilReceiverName(method.decl)
	if recvName == "" {
		return guards
	}
	for _, candidate := range methods {
		if candidate.recv.Obj() != method.recv.Obj() || !fieldNilHasHardCheck(candidate, field) {
			continue
		}
		sigObj := candidate.info.Defs[candidate.decl.Name]
		if sigObj == nil {
			continue
		}
		sig, ok := sigObj.Type().(*types.Signature)
		if !ok || sig.Results() == nil {
			continue
		}
		errType := types.Universe.Lookup("error").Type()
		errIndex := -1
		for i := 0; i < sig.Results().Len(); i++ {
			if types.AssignableTo(sig.Results().At(i).Type(), errType) {
				errIndex = i
			}
		}
		if errIndex < 0 {
			continue
		}
		ast.Inspect(method.decl.Body, func(node ast.Node) bool {
			assign, ok := node.(*ast.AssignStmt)
			if !ok || errIndex >= len(assign.Lhs) {
				return true
			}
			for _, rhs := range assign.Rhs {
				call, ok := rhs.(*ast.CallExpr)
				if !ok {
					continue
				}
				selector, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
				if !ok || selector.Sel.Name != candidate.decl.Name.Name {
					continue
				}
				id, ok := selector.X.(*ast.Ident)
				if !ok || id.Name != recvName {
					continue
				}
				selection := method.info.Selections[selector]
				if selection == nil || selection.Obj() != sigObj {
					continue
				}
				lhs, ok := assign.Lhs[errIndex].(*ast.Ident)
				if !ok {
					continue
				}
				if obj := method.info.ObjectOf(lhs); obj != nil {
					guards[obj] = true
				}
			}
			return true
		})
	}
	return guards
}

func fieldNilReceiverName(method *ast.FuncDecl) string {
	if method.Recv == nil || len(method.Recv.List) == 0 || len(method.Recv.List[0].Names) == 0 {
		return ""
	}
	return method.Recv.List[0].Names[0].Name
}

func fieldNilGuardError(info *types.Info, guards map[types.Object]bool, comparison *ast.BinaryExpr) bool {
	if len(guards) == 0 || (comparison.Op != token.EQL && comparison.Op != token.NEQ) {
		return false
	}
	var id *ast.Ident
	if fieldNilIsNil(comparison.X) {
		id, _ = ast.Unparen(comparison.Y).(*ast.Ident)
	} else if fieldNilIsNil(comparison.Y) {
		id, _ = ast.Unparen(comparison.X).(*ast.Ident)
	}
	return id != nil && guards[info.ObjectOf(id)]
}

type fieldNilState struct {
	live    bool
	checked bool
}

type fieldNilFlow struct {
	info        *types.Info
	recv        *types.Named
	field       *types.Var
	decl        *ast.FuncDecl
	deref       ast.Node
	calls       []fieldNilCall
	guardErrors map[types.Object]bool
	boolGuards  map[*types.Func]bool
}

func (*fieldNilFlow) CloneState(s fieldNilState) fieldNilState { return s }
func (*fieldNilFlow) JoinStates(a, b fieldNilState) fieldNilState {
	return fieldNilState{live: true, checked: a.checked && b.checked}
}
func (*fieldNilFlow) LiveState(s fieldNilState) bool { return s.live }
func (*fieldNilFlow) DeadState() fieldNilState       { return fieldNilState{} }
func (*fieldNilFlow) EnterScope(_ patternkit.FlowScopeKind, _ ast.Node, scope struct{}, state fieldNilState) (struct{}, fieldNilState) {
	return scope, state
}
func (*fieldNilFlow) LeaveScope(patternkit.FlowScopeKind, struct{}, *patternkit.FlowEdges[fieldNilState]) {
}
func (a *fieldNilFlow) SimpleStmt(stmt ast.Stmt, state fieldNilState, _ struct{}) (fieldNilState, bool) {
	a.inspectUses(stmt, state.checked)
	_, ret := stmt.(*ast.ReturnStmt)
	return state, ret
}
func (a *fieldNilFlow) IfCondition(stmt *ast.IfStmt, state fieldNilState, _ struct{}) (fieldNilState, fieldNilState) {
	a.inspectUses(stmt.Cond, state.checked)
	thenState, elseState := state, state
	thenState.checked = a.when(stmt.Cond, true, state.checked)
	elseState.checked = a.when(stmt.Cond, false, state.checked)
	return thenState, elseState
}
func (a *fieldNilFlow) FlowExpr(expr ast.Expr, state fieldNilState, _ struct{}) fieldNilState {
	a.inspectUses(expr, state.checked)
	return state
}
func (*fieldNilFlow) RangeVars(_ *ast.RangeStmt, state fieldNilState, _ struct{}) fieldNilState {
	return state
}
func (a *fieldNilFlow) TypeSwitchGuard(stmt ast.Stmt, state fieldNilState, scope struct{}) fieldNilState {
	next, _ := a.SimpleStmt(stmt, state, scope)
	return next
}
func (a *fieldNilFlow) CaseClause(_ ast.Stmt, clause *ast.CaseClause, state fieldNilState, scope struct{}) (fieldNilState, struct{}) {
	for _, expr := range clause.List {
		a.inspectUses(expr, state.checked)
	}
	return state, scope
}
func (*fieldNilFlow) CommClause(_ *ast.CommClause, state fieldNilState, scope struct{}) (fieldNilState, struct{}) {
	return state, scope
}
func (*fieldNilFlow) Normalize(*patternkit.FlowEdges[fieldNilState]) {}

func (a *fieldNilFlow) when(expr ast.Expr, truth, checked bool) bool {
	expr = ast.Unparen(expr)
	if unary, ok := expr.(*ast.UnaryExpr); ok && unary.Op == token.NOT {
		return a.when(unary.X, !truth, checked)
	}
	if call, ok := expr.(*ast.CallExpr); ok {
		selector, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
		if ok {
			selection := a.info.Selections[selector]
			id, sameReceiver := ast.Unparen(selector.X).(*ast.Ident)
			if selection != nil && selection.Kind() == types.MethodVal && sameReceiver && a.info.ObjectOf(id) == fieldNilReceiverObject(a.info, a.decl) {
				if guard, ok := selection.Obj().(*types.Func); ok && a.boolGuards[guard] && truth {
					return true
				}
			}
		}
	}
	bin, ok := expr.(*ast.BinaryExpr)
	if !ok {
		return checked
	}
	if fieldNilGuardError(a.info, a.guardErrors, bin) {
		return checked || truth == (bin.Op == token.EQL)
	}
	if fieldNilCompared(a.info, a.recv, bin) == a.field && (bin.Op == token.EQL || bin.Op == token.NEQ) {
		if truth == (bin.Op == token.NEQ) {
			return true
		}
		return checked
	}
	switch bin.Op {
	case token.LAND:
		if truth {
			return a.when(bin.Y, true, a.when(bin.X, true, checked))
		}
	case token.LOR:
		if !truth {
			return a.when(bin.Y, false, a.when(bin.X, false, checked))
		}
	}
	return checked
}

func (a *fieldNilFlow) inspectUses(node ast.Node, checked bool) {
	if node == nil {
		return
	}
	var stack []ast.Node
	ast.Inspect(node, func(n ast.Node) bool {
		if n == nil {
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			return false
		}
		if sel, ok := n.(*ast.SelectorExpr); ok && len(stack) > 0 {
			s := a.info.Selections[sel]
			if !checked && a.deref == nil && s != nil && s.Kind() == types.FieldVal && s.Obj() == a.field && fieldNilDereference(sel, stack) {
				a.deref = sel
			}
			if call, ok := stack[len(stack)-1].(*ast.CallExpr); ok && call.Fun == sel && s != nil && s.Kind() == types.MethodVal {
				if id, ok := ast.Unparen(sel.X).(*ast.Ident); ok && a.info.ObjectOf(id) == fieldNilReceiverObject(a.info, a.decl) {
					if target, ok := s.Obj().(*types.Func); ok {
						a.calls = append(a.calls, fieldNilCall{target: target, guarded: checked})
					}
				}
			}
		}
		stack = append(stack, n)
		return true
	})
}

func fieldNilReceiverObject(info *types.Info, decl *ast.FuncDecl) types.Object {
	if decl.Recv == nil || len(decl.Recv.List) == 0 || len(decl.Recv.List[0].Names) == 0 {
		return nil
	}
	return info.ObjectOf(decl.Recv.List[0].Names[0])
}

func fieldNilDereference(field *ast.SelectorExpr, stack []ast.Node) bool {
	if len(stack) == 0 {
		return false
	}
	parent := stack[len(stack)-1]
	switch p := parent.(type) {
	case *ast.SelectorExpr:
		return p.X == field
	case *ast.CallExpr:
		return p.Fun == field
	case *ast.StarExpr:
		return p.X == field
	case *ast.IndexExpr:
		return p.X == field && len(stack) > 1 && fieldNilIndexWrite(p, stack[len(stack)-2])
	}
	return false
}

func fieldNilIndexWrite(index *ast.IndexExpr, parent ast.Node) bool {
	assign, ok := parent.(*ast.AssignStmt)
	if !ok {
		return false
	}
	for _, lhs := range assign.Lhs {
		if lhs == index {
			return true
		}
	}
	return false
}
