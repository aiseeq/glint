package patterns

import (
	"go/ast"
	"go/types"
	"regexp"
	"slices"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewReadMethodSkipsAccessFilterRule())
	rules.Register(NewScopedResultIncludesGlobalListRule())
}

// accessTypeName names a type that carries what a viewer may see:
// StaffAccess, Permissions, Visibility.
var accessTypeName = regexp.MustCompile(`(?:Access|Permissions?|Visibility|Viewer)$`)

// readMethodName opens the names of methods that hand out records.
var readMethodName = regexp.MustCompile(`^(?:Get|List|Find|Search|Load|Fetch)`)

// NewReadMethodSkipsAccessFilterRule creates read-method-skips-access-filter:
// a reader an HTTP handler serves with no access argument, while the other
// methods of its type take the viewer's access and filter by it:
//
//	func (s *IssueService) ListFor(ctx, access StaffAccess) []Issue           // filtered
//	func (s *IssueService) Acknowledge(ctx, key string, access StaffAccess) error
//	func (s *IssueService) GetHistory(ctx, since time.Time, limit int) []Event // everything
//
// The page served by GetHistory shows what the rest of the section hides
// from the same viewer. A reader with a filtered twin (List and ListFor) is
// left out: the twin is what handlers are meant to call.
func NewReadMethodSkipsAccessFilterRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"read-method-skips-access-filter",
			"security",
			"Detects a reader served by an HTTP handler with no access argument while the other methods of its type filter by the viewer's access — it shows what the rest of the section hides",
			core.SeverityMedium,
		),
		suggestion: "Take the viewer's access like the sibling methods and filter by it before the limit, or name a filtered twin and call it from the handler",
	}
	r.check = func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		obj, ok := scope.info.Defs[fn.Name].(*types.Func)
		if !ok || !obj.Exported() || !readMethodName.MatchString(obj.Name()) || !returnsRecords(obj) {
			return nil
		}
		recv := receiverType(obj)
		if recv == nil {
			return nil
		}
		access := siblingAccessType(recv, obj)
		if access == nil || takesType(obj, access) || hasFilteredTwin(recv, obj, access) || !servedByHandler(scope, obj) {
			return nil
		}
		return []funcFinding{{node: fn.Name, message: obj.Name() + " takes no " + access.Obj().Name() + " while the other methods of " + recv.Obj().Name() +
			" filter by it, and a handler serves it — the viewer sees records the rest of the section hides"}}
	}
	return r
}

// returnsRecords reports a function whose first result is a slice, a map or
// a pointer: records, not a count.
func returnsRecords(fn *types.Func) bool {
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Results().Len() == 0 {
		return false
	}
	switch sig.Results().At(0).Type().Underlying().(type) {
	case *types.Slice, *types.Map, *types.Pointer:
		return true
	}
	return false
}

// receiverType returns the named type a method is declared on.
func receiverType(fn *types.Func) *types.Named {
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return nil
	}
	typ := sig.Recv().Type()
	if ptr, ok := typ.(*types.Pointer); ok {
		typ = ptr.Elem()
	}
	named, _ := types.Unalias(typ).(*types.Named)
	return named
}

// siblingAccessType returns the access type that at least two other exported
// methods of recv take.
func siblingAccessType(recv *types.Named, self *types.Func) *types.Named {
	counts := map[*types.Named]int{}
	for i := range recv.NumMethods() {
		method := recv.Method(i)
		if method == self || !method.Exported() {
			continue
		}
		for _, param := range paramNamedTypes(method) {
			if accessTypeName.MatchString(param.Obj().Name()) {
				counts[param]++
			}
		}
	}
	var best *types.Named
	for typ, count := range counts {
		if count >= 2 && (best == nil || count > counts[best] || count == counts[best] && typ.Obj().Name() < best.Obj().Name()) {
			best = typ
		}
	}
	return best
}

// paramNamedTypes returns the named types of a function's parameters,
// pointers looked through.
func paramNamedTypes(fn *types.Func) []*types.Named {
	sig, ok := fn.Type().(*types.Signature)
	if !ok {
		return nil
	}
	var named []*types.Named
	for i := range sig.Params().Len() {
		typ := sig.Params().At(i).Type()
		if ptr, ok := typ.(*types.Pointer); ok {
			typ = ptr.Elem()
		}
		if n, ok := types.Unalias(typ).(*types.Named); ok {
			named = append(named, n)
		}
	}
	return named
}

// takesType reports a function with a parameter of the named type.
func takesType(fn *types.Func, typ *types.Named) bool {
	return slices.Contains(paramNamedTypes(fn), typ)
}

// hasFilteredTwin reports a sibling named after the reader that takes the
// access: List and ListFor.
func hasFilteredTwin(recv *types.Named, fn *types.Func, access *types.Named) bool {
	for i := range recv.NumMethods() {
		method := recv.Method(i)
		if method != fn && strings.HasPrefix(method.Name(), fn.Name()) && takesType(method, access) {
			return true
		}
	}
	return false
}

// servedByHandler reports a function an HTTP handler calls directly.
func servedByHandler(scope funcScope, fn *types.Func) bool {
	for _, site := range scope.callers[fn.Origin()] {
		if handlerRequestParam(typedFunc{info: site.caller.info, decl: site.caller.decl}) != nil {
			return true
		}
	}
	return false
}

// NewScopedResultIncludesGlobalListRule creates
// scoped-result-includes-global-list: a result built for one scope (the
// literal sets PortfolioID: portfolioID) that carries a list of records read
// from a source not handed that scope:
//
//	alerts, _ := s.healthMonitor.GetLastAlerts()      // every portfolio's alerts
//	return &RiskReport{PortfolioID: portfolioID, HealthAlerts: alerts}
//
// Each portfolio's page shows the records of all of them. A list read with
// the scope (AlertsOf(portfolioID)) or of records with no identity of their
// own (a list of chain names) is fine.
func NewScopedResultIncludesGlobalListRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"scoped-result-includes-global-list",
			"security",
			"Detects a result built for one scope (PortfolioID: portfolioID) that carries records read from a source not handed that scope — every scope shows the records of all",
			core.SeverityMedium,
		),
		suggestion: "Hand the scope to the source, or filter its records by the scope's id before putting them into the result",
	}
	r.check = func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		var findings []funcFinding
		seen := map[*ast.CallExpr]bool{}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			scoped := scopeField(scope.info, fn, lit)
			if scoped == "" {
				return true
			}
			for _, elt := range lit.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				for _, call := range valueSources(scope.info, fn, kv.Value, 2) {
					if !seen[call] && globalRecordList(scope.info, call) {
						seen[call] = true
						findings = append(findings, funcFinding{node: call, message: "The result is built for one " + scoped +
							", and this list comes from a source not handed it — every " + scoped + " shows the records of all"})
					}
				}
			}
			return true
		})
		return findings
	}
	return r
}

// scopeField returns the key of a literal field set to an id parameter of
// the same name (PortfolioID: portfolioID), "" for a literal with none.
func scopeField(info *types.Info, fn *ast.FuncDecl, lit *ast.CompositeLit) string {
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, keyOK := kv.Key.(*ast.Ident)
		value, valueOK := ast.Unparen(kv.Value).(*ast.Ident)
		if !keyOK || !valueOK || !strings.HasSuffix(key.Name, "ID") || !strings.EqualFold(key.Name, value.Name) {
			continue
		}
		if param, ok := info.Uses[value].(*types.Var); ok && isParamOf(info, fn, param) {
			return key.Name
		}
	}
	return ""
}

// isParamOf reports a parameter of the function.
func isParamOf(info *types.Info, fn *ast.FuncDecl, v *types.Var) bool {
	for _, field := range fn.Type.Params.List {
		for _, name := range field.Names {
			if info.Defs[name] == v {
				return true
			}
		}
	}
	return false
}

// valueSources returns the calls a value comes from: the call itself, or the
// calls assigned to the local variable it names, followed depth assignments
// back (alerts = last; last, _ := monitor.LastAlerts()).
func valueSources(info *types.Info, fn *ast.FuncDecl, value ast.Expr, depth int) []*ast.CallExpr {
	switch v := ast.Unparen(value).(type) {
	case *ast.CallExpr:
		return []*ast.CallExpr{v}
	case *ast.Ident:
		target, ok := info.Uses[v].(*types.Var)
		if !ok || depth == 0 {
			return nil
		}
		var calls []*ast.CallExpr
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			assign, ok := n.(*ast.AssignStmt)
			if !ok {
				return true
			}
			for i, lhs := range assign.Lhs {
				ident, ok := lhs.(*ast.Ident)
				if !ok || info.ObjectOf(ident) != target {
					continue
				}
				switch {
				case len(assign.Rhs) == len(assign.Lhs):
					calls = append(calls, valueSources(info, fn, assign.Rhs[i], depth-1)...)
				case len(assign.Rhs) == 1 && i == 0:
					if call, ok := ast.Unparen(assign.Rhs[0]).(*ast.CallExpr); ok {
						calls = append(calls, call)
					}
				}
			}
			return true
		})
		return calls
	}
	return nil
}

// globalRecordList reports a method call handed nothing but a context that
// answers a list of records with ids of their own: a process-wide source.
func globalRecordList(info *types.Info, call *ast.CallExpr) bool {
	if _, method := ast.Unparen(call.Fun).(*ast.SelectorExpr); !method {
		return false
	}
	for _, arg := range call.Args {
		if types.TypeString(info.TypeOf(arg), nil) != "context.Context" {
			return false
		}
	}
	var first types.Type
	switch typ := info.TypeOf(call).(type) {
	case *types.Tuple:
		if typ.Len() == 0 {
			return false
		}
		first = typ.At(0).Type()
	default:
		first = typ
	}
	slice, ok := first.Underlying().(*types.Slice)
	if !ok {
		return false
	}
	elem := slice.Elem()
	if ptr, ok := elem.(*types.Pointer); ok {
		elem = ptr.Elem()
	}
	st, ok := elem.Underlying().(*types.Struct)
	if !ok {
		return false
	}
	for i := range st.NumFields() {
		if strings.HasSuffix(st.Field(i).Name(), "ID") {
			return true
		}
	}
	return false
}
