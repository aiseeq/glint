package patterns

import (
	"go/ast"
	"go/token"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

// errorFieldStructs returns the names of the file's struct types with an
// Error string field: a result that carries its own failure.
func errorFieldStructs(file *ast.File) []string {
	var names []string
	ast.Inspect(file, func(n ast.Node) bool {
		spec, ok := n.(*ast.TypeSpec)
		if !ok {
			return true
		}
		st, ok := spec.Type.(*ast.StructType)
		if !ok {
			return true
		}
		for _, field := range st.Fields.List {
			typ, ok := field.Type.(*ast.Ident)
			if !ok || typ.Name != "string" {
				continue
			}
			for _, name := range field.Names {
				if name.Name == "Error" {
					names = append(names, spec.Name.Name)
				}
			}
		}
		return true
	})
	return names
}

// partialChecks are the shapes of a partial result returned as complete
// outside a loop over a fixed list.
func (r *AggregateSkipsFailedPartRule) partialChecks(ctx *core.FileContext, body *ast.BlockStmt) []*core.Violation {
	var violations []*core.Violation
	report := func(node ast.Node, message string) {
		line := ctx.LineFor(node)
		if ctx.IsSuppressed(line, r.Name()) {
			return
		}
		v := r.CreateViolation(ctx.RelPath, line, message)
		v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
		v.WithSuggestion("Return the error (errors.Join of the failed parts), or report the result as partial to the caller")
		violations = append(violations, v)
	}
	if ret := unreadErrorResults(body, r.errorStructs); ret != nil {
		report(ret, "Results carrying their own Error field are returned with a nil error by a function that never reads it - a failed item is served as a valid one")
	}
	forEachOwnStatementList(body, func(list []ast.Stmt) {
		for i := 0; i+1 < len(list); i++ {
			if check := loggedSourceSkipped(list[i], list[i+1]); check != nil {
				report(check, "A failed source is logged and its share is left out of the total the function returns as complete")
			}
		}
	})
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.RangeStmt:
			if check := failureCountedAsSkipped(node); check != nil {
				report(check, "A failed item is counted as skipped - the caller gets a clean run with skipped items instead of the error")
			}
		case *ast.IfStmt:
			if allFailedOnly(node) {
				report(node, "The collected errors are returned only when every item failed - a partial failure is reported as success")
			}
		}
		return true
	})
	return violations
}

// unreadErrorResults returns the final return of a function that builds a
// slice of results carrying an Error field and hands it out with a nil error
// without reading that field anywhere.
func unreadErrorResults(body *ast.BlockStmt, structs map[string]bool) *ast.ReturnStmt {
	if len(structs) == 0 || len(body.List) == 0 {
		return nil
	}
	ret, ok := body.List[len(body.List)-1].(*ast.ReturnStmt)
	if !ok || len(ret.Results) < 2 || !isNilIdent(ret.Results[len(ret.Results)-1]) {
		return nil
	}
	slices := make(map[string]bool)
	readsError := false
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CallExpr:
			// err.Error() is the text of an error, not a result's field.
			if sel, ok := node.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Error" {
				for _, arg := range node.Args {
					ast.Inspect(arg, func(inner ast.Node) bool {
						if s, ok := inner.(*ast.SelectorExpr); ok && s.Sel.Name == "Error" {
							readsError = true
						}
						return true
					})
				}
				return false
			}
		case *ast.SelectorExpr:
			if node.Sel.Name == "Error" {
				readsError = true
			}
		case *ast.AssignStmt:
			for i, lhs := range node.Lhs {
				if id, ok := lhs.(*ast.Ident); ok && i < len(node.Rhs) && sliceOfErrorStruct(node.Rhs[i], structs) {
					slices[id.Name] = true
				}
			}
		case *ast.ValueSpec:
			if sliceTypeOfErrorStruct(node.Type, structs) {
				for _, name := range node.Names {
					slices[name.Name] = true
				}
			}
		}
		return true
	})
	if readsError || len(slices) == 0 || inspectsItems(body, slices) {
		return nil
	}
	for _, value := range ret.Results[:len(ret.Results)-1] {
		if readsAnyOf(value, slices) {
			return ret
		}
	}
	return nil
}

// inspectsItems reports a function that hands single results to a call
// (issue := snapshotIssue(wb) for out[i] = wb, check(results[i])): the
// callee may read the Error field for it.
func inspectsItems(body *ast.BlockStmt, slices map[string]bool) bool {
	// The items are the values stored into the results: out[i] = wb, or
	// results = append(results, result).
	items := make(map[string]bool)
	ast.Inspect(body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
			return true
		}
		if index, ok := assign.Lhs[0].(*ast.IndexExpr); ok && readsAnyOf(index.X, slices) {
			if value, ok := assign.Rhs[0].(*ast.Ident); ok {
				items[value.Name] = true
			}
		}
		if call, ok := assign.Rhs[0].(*ast.CallExpr); ok && isIdentNamed(call.Fun, "append") && len(call.Args) > 1 && readsAnyOf(call.Args[0], slices) {
			for _, arg := range call.Args[1:] {
				if value, ok := arg.(*ast.Ident); ok {
					items[value.Name] = true
				}
			}
		}
		return true
	})
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || found {
			return !found
		}
		if fun, ok := call.Fun.(*ast.Ident); ok && (fun.Name == "append" || fun.Name == "len" || fun.Name == "cap" || fun.Name == "delete") {
			return true
		}
		if helpers.IsLoggerCall(call) {
			return true
		}
		for _, arg := range call.Args {
			switch a := ast.Unparen(arg).(type) {
			case *ast.Ident:
				found = found || items[a.Name]
			case *ast.IndexExpr:
				found = found || readsAnyOf(a.X, slices)
			}
		}
		return !found
	})
	return found
}

// sliceOfErrorStruct reports make([]*R, n) or []*R{} of such a struct.
func sliceOfErrorStruct(expr ast.Expr, structs map[string]bool) bool {
	switch e := ast.Unparen(expr).(type) {
	case *ast.CallExpr:
		return isIdentNamed(e.Fun, "make") && len(e.Args) > 0 && sliceTypeOfErrorStruct(e.Args[0], structs)
	case *ast.CompositeLit:
		return sliceTypeOfErrorStruct(e.Type, structs)
	}
	return false
}

func sliceTypeOfErrorStruct(expr ast.Expr, structs map[string]bool) bool {
	array, ok := expr.(*ast.ArrayType)
	if !ok {
		return false
	}
	elt := array.Elt
	if star, ok := elt.(*ast.StarExpr); ok {
		elt = star.X
	}
	if sel, ok := elt.(*ast.SelectorExpr); ok {
		elt = sel.Sel
	}
	id, ok := elt.(*ast.Ident)
	return ok && structs[id.Name]
}

// loggedSourceSkipped returns the if of
//
//	parts, partsErr := s.fetchParts(...)
//	if partsErr != nil { log } else { ... total = total.Add(p.Value) ... }
//
// where the failure branch only logs and the else branch adds the parts to a
// total declared before.
func loggedSourceSkipped(first, second ast.Stmt) *ast.IfStmt {
	assign, ok := first.(*ast.AssignStmt)
	if !ok || len(assign.Lhs) < 2 || len(assign.Rhs) != 1 {
		return nil
	}
	if _, isCall := ast.Unparen(assign.Rhs[0]).(*ast.CallExpr); !isCall {
		return nil
	}
	errVar, ok := assign.Lhs[len(assign.Lhs)-1].(*ast.Ident)
	if !ok || !isErrorVarName(errVar.Name) {
		return nil
	}
	check, ok := second.(*ast.IfStmt)
	if !ok || !errNotNil(check.Cond, errVar.Name) || !allStmtsAreLogs(check.Body.List) {
		return nil
	}
	elseBlock, ok := check.Else.(*ast.BlockStmt)
	if !ok {
		return nil
	}
	values := make(map[string]bool)
	for _, lhs := range assign.Lhs[:len(assign.Lhs)-1] {
		if id, ok := lhs.(*ast.Ident); ok && id.Name != "_" {
			values[id.Name] = true
		}
	}
	found := false
	ast.Inspect(elseBlock, func(n ast.Node) bool {
		if loop, ok := n.(*ast.RangeStmt); ok && readsAnyOf(loop.X, values) {
			for _, v := range []ast.Expr{loop.Key, loop.Value} {
				if id, ok := v.(*ast.Ident); ok && id.Name != "_" {
					values[id.Name] = true
				}
			}
		}
		if stmt, ok := n.(ast.Stmt); ok && accumulates(stmt, values, check.Pos()) {
			found = true
		}
		return !found
	})
	if !found {
		return nil
	}
	return check
}

// failureCountedAsSkipped returns the if of a loop that, on an error, bumps
// a counter named skipped (or ignored) and continues.
func failureCountedAsSkipped(loop *ast.RangeStmt) *ast.IfStmt {
	for _, stmt := range loop.Body.List {
		check, ok := stmt.(*ast.IfStmt)
		if !ok || errNilCheckName(check.Cond) == "" || !continuesOnly(check.Body) {
			continue
		}
		for _, inner := range check.Body.List {
			inc, ok := inner.(*ast.IncDecStmt)
			if !ok || inc.Tok != token.INC {
				continue
			}
			id, ok := inc.X.(*ast.Ident)
			if !ok {
				continue
			}
			for _, word := range helpers.IdentifierWords(id.Name) {
				if w := strings.ToLower(word); w == "skipped" || w == "ignored" || w == "skip" {
					return check
				}
			}
		}
	}
	return nil
}

// allFailedOnly reports `if len(errs) == len(items) { return ..., err }`: the
// error leaves the function only when every item failed.
func allFailedOnly(check *ast.IfStmt) bool {
	bin, ok := ast.Unparen(check.Cond).(*ast.BinaryExpr)
	if !ok || bin.Op != token.EQL || !isLenCall(bin.X) || !isLenCall(bin.Y) {
		return false
	}
	id, ok := lenArgument(bin.X).(*ast.Ident)
	if !ok || !strings.HasPrefix(strings.ToLower(id.Name), "err") && !strings.HasPrefix(strings.ToLower(id.Name), "fail") {
		return false
	}
	for _, stmt := range check.Body.List {
		if ret, ok := stmt.(*ast.ReturnStmt); ok && len(ret.Results) > 0 && !isNilIdent(ret.Results[len(ret.Results)-1]) {
			return true
		}
	}
	return false
}

func isLenCall(expr ast.Expr) bool {
	return lenArgument(expr) != nil
}

// lenArgument returns x of len(x), or nil.
func lenArgument(expr ast.Expr) ast.Expr {
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok || !isIdentNamed(call.Fun, "len") || len(call.Args) != 1 {
		return nil
	}
	return call.Args[0]
}
