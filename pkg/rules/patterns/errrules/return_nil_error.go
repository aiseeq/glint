package errrules

import (
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
)

func init() {
	rules.Register(NewReturnNilErrorRule())
}

// ReturnNilErrorRule detects functions returning (nil, nil) which is often a bug
type ReturnNilErrorRule struct {
	*rules.BaseRule
}

// NewReturnNilErrorRule creates the rule
func NewReturnNilErrorRule() *ReturnNilErrorRule {
	return &ReturnNilErrorRule{
		BaseRule: rules.NewBaseRule(
			"return-nil-error",
			"patterns",
			"Detects (nil, nil) returns which often indicate missing error handling",
			core.SeverityMedium,
		),
	}
}

// AnalyzeFile checks one file without type information: the fallback the
// project analysis uses for files no type-checked package covers.
func (r *ReturnNilErrorRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	return r.analyze(ctx, nil, nil)
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *ReturnNilErrorRule) RequiresSSA() bool { return false }

// AnalyzeGoProject checks every file; a first result declared through a named
// type is judged by its underlying type, and a function every caller of which
// tests the record for nil is left out.
func (r *ReturnNilErrorRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	decls, err := patternkit.FuncDeclsByObject(ctx)
	if err != nil {
		return nil, err
	}
	sites, err := patternkit.FuncCallSites(ctx, decls)
	if err != nil {
		return nil, err
	}
	checked := nilCheckedByCallers(decls, sites)
	return rules.AnalyzeGoFiles(ctx, r.Name(), func(fileCtx *core.FileContext, info *types.Info) []*core.Violation {
		return r.analyze(fileCtx, info, checked)
	})
}

// nilCheckedByCallers returns the functions called in the module, and only
// called, whose every caller assigns the first result to a variable it tests
// for nil (b, err := briefOf(id); if b == nil): (nil, nil) there is the answer
// "there is none", and no caller counts the missing record as zero.
func nilCheckedByCallers(decls map[*types.Func]patternkit.TypedFuncDecl, sites map[*types.Func][]patternkit.FuncCallSite) map[*types.Func]bool {
	// A function used as a value is called where the module cannot see.
	asValue := map[*types.Func]bool{}
	for _, d := range decls {
		called := map[*ast.Ident]bool{}
		ast.Inspect(d.Decl.Body, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.CallExpr:
				switch fun := ast.Unparen(node.Fun).(type) {
				case *ast.Ident:
					called[fun] = true
				case *ast.SelectorExpr:
					called[fun.Sel] = true
				}
			case *ast.Ident:
				if fn, ok := d.Info.Uses[node].(*types.Func); ok && !called[node] {
					asValue[fn.Origin()] = true
				}
			}
			return true
		})
	}
	checked := map[*types.Func]bool{}
	for fn, calls := range sites {
		if asValue[fn] {
			continue
		}
		all := len(calls) > 0
		for _, site := range calls {
			all = all && resultTestedForNil(decls, site)
		}
		if all {
			checked[fn] = true
		}
	}
	return checked
}

// resultTestedForNil reports a call site whose first result is assigned to a
// variable that the caller tests for nil (see nilHandled).
func resultTestedForNil(decls map[*types.Func]patternkit.TypedFuncDecl, site patternkit.FuncCallSite) bool {
	info, body := site.Caller.Info, site.Caller.Decl.Body
	var record types.Object
	ast.Inspect(body, func(n ast.Node) bool {
		if assign, ok := n.(*ast.AssignStmt); ok && len(assign.Rhs) == 1 && ast.Unparen(assign.Rhs[0]) == site.Call && len(assign.Lhs) > 0 {
			if ident, ok := assign.Lhs[0].(*ast.Ident); ok && ident.Name != "_" {
				record = info.ObjectOf(ident)
			}
		}
		return record == nil
	})
	return record != nil && nilHandled(decls, patternkit.TypedFuncDecl{Decl: site.Caller.Decl, Info: info}, record, 2)
}

// nilHandled reports a pointer variable of a function whose nil is handled
// there: compared with nil (if b == nil), handed to a function of the module
// that does so with its parameter, depth calls down, or only stored in fields
// (req.TemplateID = id), where nil stays the absence it says.
func nilHandled(decls map[*types.Func]patternkit.TypedFuncDecl, fn patternkit.TypedFuncDecl, record types.Object, depth int) bool {
	info := fn.Info
	handled := false
	storedOnly := true
	stored := map[*ast.Ident]bool{}
	ast.Inspect(fn.Decl.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.BinaryExpr:
			if node.Op == token.EQL || node.Op == token.NEQ {
				handled = handled || helpers.IsNilIdent(node.Y) && isObject(info, node.X, record) || helpers.IsNilIdent(node.X) && isObject(info, node.Y, record)
			}
		case *ast.AssignStmt:
			for i, rhs := range node.Rhs {
				if _, field := node.Lhs[min(i, len(node.Lhs)-1)].(*ast.SelectorExpr); field {
					if ident := objectIdent(info, rhs, record); ident != nil {
						stored[ident] = true
					}
				}
			}
		case *ast.KeyValueExpr:
			if ident := objectIdent(info, node.Value, record); ident != nil {
				stored[ident] = true
			}
		case *ast.CallExpr:
			if depth > 0 {
				handled = handled || argNilHandled(decls, info, node, record, depth)
			}
		case *ast.Ident:
			// The declaration and the assignment of the call's result name
			// the variable too; a use is a read of it.
			if info.Uses[node] == record && !stored[node] && !onAssignLeft(fn.Decl.Body, node) {
				storedOnly = false
			}
		}
		return !handled
	})
	return handled || storedOnly
}

// argNilHandled reports a call handing the variable to a parameter of a
// function of the module that handles its nil.
func argNilHandled(decls map[*types.Func]patternkit.TypedFuncDecl, info *types.Info, call *ast.CallExpr, record types.Object, depth int) bool {
	callee := patternkit.StaticFunc(info, call)
	if callee == nil {
		return false
	}
	decl, ok := decls[callee.Origin()]
	if !ok {
		return false
	}
	var params []*ast.Ident
	for _, field := range decl.Decl.Type.Params.List {
		params = append(params, field.Names...)
	}
	for i, arg := range call.Args {
		if i < len(params) && isObject(info, arg, record) {
			if param := decl.Info.Defs[params[i]]; param != nil && nilHandled(decls, decl, param, depth-1) {
				return true
			}
		}
	}
	return false
}

// onAssignLeft reports an identifier on the left of an assignment.
func onAssignLeft(body *ast.BlockStmt, ident *ast.Ident) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if assign, ok := n.(*ast.AssignStmt); ok {
			for _, lhs := range assign.Lhs {
				found = found || lhs == ident
			}
		}
		return !found
	})
	return found
}

// isObject reports an identifier of the object.
func isObject(info *types.Info, expr ast.Expr, obj types.Object) bool {
	return objectIdent(info, expr, obj) != nil
}

// objectIdent returns expr as the identifier of obj, or nil for any other
// expression.
func objectIdent(info *types.Info, expr ast.Expr, obj types.Object) *ast.Ident {
	if ident, ok := ast.Unparen(expr).(*ast.Ident); ok && info.ObjectOf(ident) == obj {
		return ident
	}
	return nil
}

// analyze checks for (nil, nil) returns. info is nil for a file without type
// information, checked the functions whose callers all test for nil.
func (r *ReturnNilErrorRule) analyze(ctx *core.FileContext, info *types.Info, checked map[*types.Func]bool) []*core.Violation {
	return patternkit.AnalyzeGoFunctions(ctx, func(fn *ast.FuncDecl) []*core.Violation {
		if !r.hasErrorReturn(fn) || nilIsEmptyFirstResult(fn, info) {
			return nil
		}
		if info != nil {
			if obj, ok := info.Defs[fn.Name].(*types.Func); ok && checked[obj] {
				return nil
			}
		}
		notFound := noRowsReturns(fn)
		conventional := r.isValidNilNilPattern(fn)

		var violations []*core.Violation
		patternkit.ForEachOwnStatement(fn.Body, func(stmt ast.Stmt) {
			ret, ok := stmt.(*ast.ReturnStmt)
			if !ok || !r.isNilNilReturn(ret) || (conventional && !notFound[ret]) {
				return
			}
			line := ctx.LineFor(ret)
			if ctx.IsSuppressed(line, r.Name()) {
				return
			}
			violations = append(violations, r.report(ctx, line, notFound[ret]))
		})
		return violations
	})
}

func (r *ReturnNilErrorRule) report(ctx *core.FileContext, line int, notFound bool) *core.Violation {
	if notFound {
		v := r.CreateViolation(ctx.RelPath, line, "Missing row answered with (nil, nil) — not found passes for success, and a caller that does not check for nil counts the record as zero")
		v.WithCode(ctx.GetLine(line))
		v.WithSuggestion("Return a not-found error (wrapping the project's ErrNotFound) and let the caller decide what an absent record means")
		v.WithContext("pattern", "not_found_as_success")
		return v
	}
	v := r.CreateViolation(ctx.RelPath, line, "Returning (nil, nil) - possible missing error")
	v.WithCode(ctx.GetLine(line))
	v.WithSuggestion("Return an error or a valid value, not both nil")
	v.WithContext("pattern", "nil_nil_return")
	return v
}

// noRowsReturns returns the return statements of branches taken when a query
// found no row: if errors.Is(err, sql.ErrNoRows) { ... } or err == pgx.ErrNoRows.
// The name-based exemption of lookups does not cover them: answering a
// missing row with (nil, nil) is the ambiguity the rule exists for.
func noRowsReturns(fn *ast.FuncDecl) map[*ast.ReturnStmt]bool {
	returns := make(map[*ast.ReturnStmt]bool)
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if _, ok := n.(*ast.FuncLit); ok {
			return false
		}
		branch, ok := n.(*ast.IfStmt)
		if !ok || !patternkit.TestsNoRows(branch.Cond) {
			return true
		}
		for _, stmt := range branch.Body.List {
			if ret, ok := stmt.(*ast.ReturnStmt); ok {
				returns[ret] = true
			}
		}
		return true
	})
	return returns
}

// nilIsEmptyFirstResult reports whether nil is the empty value of the first
// result: a slice, a map, a channel or a function. (nil, nil) from such a
// function says "nothing", not "an error went missing". Without type
// information only a type spelled out in the signature is known; a named type
// stays unknown and the return is still reported.
func nilIsEmptyFirstResult(fn *ast.FuncDecl, info *types.Info) bool {
	first := fn.Type.Results.List[0].Type
	if info != nil {
		if typ := info.TypeOf(first); typ != nil {
			switch typ.Underlying().(type) {
			case *types.Slice, *types.Map, *types.Chan, *types.Signature:
				return true
			}
			return false
		}
	}
	switch t := first.(type) {
	case *ast.ArrayType:
		return t.Len == nil
	case *ast.MapType, *ast.ChanType, *ast.FuncType:
		return true
	}
	return false
}

// isValidNilNilPattern checks if (nil, nil) return is a valid Go pattern
func (r *ReturnNilErrorRule) isValidNilNilPattern(fn *ast.FuncDecl) bool {
	funcName := fn.Name.Name
	funcNameLower := strings.ToLower(funcName)

	// 1. driver.Valuer interface: Value() returns (nil, nil) for SQL NULL
	// This is the standard Go database pattern
	if funcName == "Value" && r.hasDriverValueReturn(fn) {
		return true
	}

	// 2. "not found" semantics: Get*, Find*, Lookup*, Search*, Existing*
	// Return (nil, nil) when item doesn't exist (vs error for actual failures)
	// Also includes Check*, Validate* - return (nil, nil) for "no issue found"
	notFoundPrefixes := []string{"get", "find", "lookup", "search", "fetch", "load", "existing", "check", "validate"}
	for _, prefix := range notFoundPrefixes {
		if strings.HasPrefix(funcNameLower, prefix) {
			return true
		}
	}

	// 3. "no data, no error" semantics for processing functions
	// Return (nil, nil) when input is nil/empty (no data to process, not an error)
	noDataPrefixes := []string{"parse", "convert", "transform", "serialize", "deserialize", "decode", "encode", "marshal", "unmarshal"}
	for _, prefix := range noDataPrefixes {
		if strings.HasPrefix(funcNameLower, prefix) {
			return true
		}
	}

	// 4. Functions ending with "FromString", "FromBytes", etc.
	// These commonly return (nil, nil) for empty input
	fromSuffixes := []string{"fromstring", "frombytes", "fromjson", "fromxml"}
	for _, suffix := range fromSuffixes {
		if strings.HasSuffix(funcNameLower, suffix) {
			return true
		}
	}

	return false
}

// hasDriverValueReturn checks if function returns (driver.Value, error)
func (r *ReturnNilErrorRule) hasDriverValueReturn(fn *ast.FuncDecl) bool {
	if fn.Type.Results == nil || len(fn.Type.Results.List) != 2 {
		return false
	}

	// Check first return type is driver.Value
	firstResult := fn.Type.Results.List[0]
	sel, ok := firstResult.Type.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	ident, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	return ident.Name == "driver" && sel.Sel.Name == "Value"
}

// hasErrorReturn checks if function has error as last return type
func (r *ReturnNilErrorRule) hasErrorReturn(fn *ast.FuncDecl) bool {
	if fn.Type.Results == nil || len(fn.Type.Results.List) < 2 {
		return false
	}

	// Check last return type is error
	lastResult := fn.Type.Results.List[len(fn.Type.Results.List)-1]
	ident, ok := lastResult.Type.(*ast.Ident)
	if !ok {
		return false
	}

	return ident.Name == "error"
}

// isNilNilReturn checks if return statement returns (nil, nil)
func (r *ReturnNilErrorRule) isNilNilReturn(ret *ast.ReturnStmt) bool {
	return len(ret.Results) == 2 && helpers.IsNilIdent(ret.Results[0]) && helpers.IsNilIdent(ret.Results[1])
}
