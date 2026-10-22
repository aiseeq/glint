package patterns

import (
	"go/ast"
	"go/token"
	"slices"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewErrorCheckedOnlyForSuccessRule())
}

// ErrorCheckedOnlyForSuccessRule detects an error tested only for success:
//
//	users, err := repo.LoadUsers(ctx, ids)
//	if err == nil {
//		for id, u := range users { numbers[id] = u.Number }
//	}
//
// There is no else, and nothing after the check reads err: a failed call
// leaves the data out without a log or a returned error, and the caller
// takes the failure for an empty answer. silent-error-handling looks at the
// err != nil branches; this check has none.
//
// Only the error of a call taking a context counts: such a call goes out to
// a database, a service or a chain, and its failure is an outage. The error
// of a parse, a cookie or a map-like lookup answers whether the input has
// the form, and success-only is the way to ask.
type ErrorCheckedOnlyForSuccessRule struct{ *rules.BaseRule }

// NewErrorCheckedOnlyForSuccessRule creates the rule
func NewErrorCheckedOnlyForSuccessRule() *ErrorCheckedOnlyForSuccessRule {
	return &ErrorCheckedOnlyForSuccessRule{rules.NewBaseRule(
		"error-checked-only-for-success",
		"patterns",
		"Detects if err == nil { ... } on the error of a call taking a context, with no else and no other read of err — a failed database, service or network call is dropped without a log or a returned error",
		core.SeverityMedium,
	)}
}

// AnalyzeFile reports the success-only checks of every function.
func (r *ErrorCheckedOnlyForSuccessRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.HasGoAST() || ctx.IsTestFile() {
		return nil
	}
	var violations []*core.Violation
	for _, decl := range ctx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		assigned := assignedIdents(fn.Body)
		ast.Inspect(fn, func(n ast.Node) bool {
			var ftype *ast.FuncType
			var body *ast.BlockStmt
			switch f := n.(type) {
			case *ast.FuncDecl:
				ftype, body = f.Type, f.Body
			case *ast.FuncLit:
				ftype, body = f.Type, f.Body
			default:
				return true
			}
			named := namedResults(ftype)
			forEachOwnStatementList(body, func(list []ast.Stmt) {
				for i, stmt := range list {
					ifStmt, ok := stmt.(*ast.IfStmt)
					if !ok || ifStmt.Else != nil {
						continue
					}
					name := successCheckName(ifStmt.Cond)
					if name == "" || named[name] || readLater(fn.Body, list, i, name, assigned) {
						continue
					}
					if !lostOutageError(ifStmt, list[:i], name) {
						continue
					}
					line := ctx.PositionFor(ifStmt).Line
					if ctx.IsSuppressed(line, r.Name()) {
						continue
					}
					v := r.CreateViolation(ctx.RelPath, line,
						"Error checked only for success: no else, and nothing after the check reads "+name+" — a failure is dropped without a log or a returned error")
					v.WithCode(ctx.GetLine(line))
					v.WithSuggestion("Handle the failure: test " + name + " != nil and return or log it; an expected failure is tested by its kind (errors.Is) and the rest still handled")
					violations = append(violations, v)
				}
			})
			return true
		})
	}
	return violations
}

// successCheckName returns the error variable of err == nil, alone or the
// first operand of a && chain, "" for any other condition.
func successCheckName(cond ast.Expr) string {
	cond = ast.Unparen(cond)
	if bin, ok := cond.(*ast.BinaryExpr); ok && bin.Op == token.LAND {
		return successCheckName(bin.X)
	}
	bin, ok := cond.(*ast.BinaryExpr)
	if !ok || bin.Op != token.EQL || !helpers.IsNilIdent(bin.Y) {
		return ""
	}
	ident, ok := bin.X.(*ast.Ident)
	if !ok || !isErrorVarName(ident.Name) {
		return ""
	}
	return ident.Name
}

// readLater reports a read of name after list[i]. A variable declared in the
// same list before the check lives to the end of the list; one declared
// further out may be read anywhere after the check in the function.
func readLater(body *ast.BlockStmt, list []ast.Stmt, i int, name string, assigned map[*ast.Ident]bool) bool {
	scope := []ast.Node{body}
	if slices.ContainsFunc(list[:i], func(stmt ast.Stmt) bool { return definesVar(stmt, name) }) {
		scope = scope[:0]
		for _, stmt := range list[i+1:] {
			scope = append(scope, stmt)
		}
	}
	end := list[i].End()
	found := false
	for _, node := range scope {
		ast.Inspect(node, func(n ast.Node) bool {
			if ident, ok := n.(*ast.Ident); ok && ident.Name == name && ident.Pos() >= end && !assigned[ident] {
				found = true
			}
			return !found
		})
	}
	return found
}

// definesVar reports name := ... or var name in the statement itself.
func definesVar(stmt ast.Stmt, name string) bool {
	switch s := stmt.(type) {
	case *ast.AssignStmt:
		return s.Tok == token.DEFINE && slices.ContainsFunc(s.Lhs, func(lhs ast.Expr) bool { return helpers.IsIdentNamed(lhs, name) })
	case *ast.DeclStmt:
		gen, ok := s.Decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.VAR {
			return false
		}
		for _, spec := range gen.Specs {
			if vs, ok := spec.(*ast.ValueSpec); ok && slices.ContainsFunc(vs.Names, func(n *ast.Ident) bool { return n.Name == name }) {
				return true
			}
		}
	}
	return false
}

// namedResults returns the names of a function's named results: a bare
// return reads them.
func namedResults(ftype *ast.FuncType) map[string]bool {
	names := map[string]bool{}
	if ftype == nil || ftype.Results == nil {
		return names
	}
	for _, field := range ftype.Results.List {
		for _, name := range field.Names {
			names[name.Name] = true
		}
	}
	return names
}

// lostOutageError reports a check whose error comes from a call taking a
// context, assigned in the if itself or by an earlier statement of the list
// with nothing in between reading it: an earlier err != nil test may have
// handled the failures already and left success-only for the expected case.
func lostOutageError(ifStmt *ast.IfStmt, before []ast.Stmt, name string) bool {
	if assigns(ifStmt.Init, name) {
		return callsWithContext(ifStmt.Init)
	}
	for j := len(before) - 1; j >= 0; j-- {
		if assigns(before[j], name) {
			return callsWithContext(before[j])
		}
		if mentions(stmtExpr(before[j]), name) {
			return false
		}
	}
	return false
}

// assigns reports an assignment with name on its left side.
func assigns(stmt ast.Stmt, name string) bool {
	assign, ok := stmt.(*ast.AssignStmt)
	return ok && slices.ContainsFunc(assign.Lhs, func(lhs ast.Expr) bool { return helpers.IsIdentNamed(lhs, name) })
}

// stmtExpr wraps a statement for mentions, which takes an expression.
func stmtExpr(stmt ast.Stmt) ast.Expr {
	return &ast.FuncLit{Type: &ast.FuncType{}, Body: &ast.BlockStmt{List: []ast.Stmt{stmt}}}
}

// callsWithContext reports an assignment of one call that takes a context:
// an argument named ctx or ending in Ctx, a call of .Context() or of the
// context package.
func callsWithContext(stmt ast.Stmt) bool {
	assign, ok := stmt.(*ast.AssignStmt)
	if !ok || len(assign.Rhs) != 1 {
		return false
	}
	call, ok := ast.Unparen(assign.Rhs[0]).(*ast.CallExpr)
	if !ok {
		return false
	}
	return slices.ContainsFunc(call.Args, contextArg)
}

func contextArg(arg ast.Expr) bool {
	switch a := ast.Unparen(arg).(type) {
	case *ast.Ident:
		return a.Name == "ctx" || strings.HasSuffix(a.Name, "Ctx")
	case *ast.CallExpr:
		if sel, ok := a.Fun.(*ast.SelectorExpr); ok {
			return sel.Sel.Name == "Context" || helpers.IsIdentNamed(sel.X, "context")
		}
	}
	return false
}
