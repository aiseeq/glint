package patterns

import (
	"errors"
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewHandlerErrorOnlyLoggedRule())
}

// HandlerErrorOnlyLoggedRule detects an HTTP handler that logs a failed call
// at ERROR and goes on with the value the call returned:
//
//	projects, err := a.projectRepo.GetAll(ctx)
//	if err != nil {
//		a.logger.Error("failed to get projects", "error", err)
//	}
//	a.render(w, "page.html", projects)
//
// The client gets an answer built from the zero value - an empty list, a page
// without its data - with nothing saying the load failed, and the status
// says success. The ERROR level is the author's own verdict that this is a
// failure; a WARN is taken for a deliberate degradation and left alone.
type HandlerErrorOnlyLoggedRule struct {
	*rules.BaseRule
}

// NewHandlerErrorOnlyLoggedRule creates the rule
func NewHandlerErrorOnlyLoggedRule() *HandlerErrorOnlyLoggedRule {
	return &HandlerErrorOnlyLoggedRule{BaseRule: rules.NewBaseRule(
		"handler-error-only-logged",
		"patterns",
		"Detects an HTTP handler that logs a failed call at ERROR and goes on answering with the value the call returned — the client gets the zero value as data and a success status",
		core.SeverityMedium,
	)}
}

// AnalyzeFile is a no-op: the handler and the error are recognized by type.
func (r *HandlerErrorOnlyLoggedRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *HandlerErrorOnlyLoggedRule) RequiresSSA() bool { return false }

// AnalyzeGoProject reports the failures handlers only log.
func (r *HandlerErrorOnlyLoggedRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, errors.New("handler error only logged: nil Go project context")
	}
	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(file *core.FileContext, info *types.Info) []*core.Violation {
		var violations []*core.Violation
		for _, decl := range file.GoAST.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || !takesResponseWriter(info, fn.Type) {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if _, nested := n.(*ast.FuncLit); nested {
					return false
				}
				block, ok := n.(*ast.BlockStmt)
				if !ok {
					return true
				}
				for i := 0; i+1 < len(block.List); i++ {
					check := onlyLoggedFailure(info, block.List, i)
					if check == nil {
						continue
					}
					line := file.LineFor(check)
					if file.IsSuppressed(line, r.Name()) {
						continue
					}
					v := r.CreateViolation(file.RelPath, line,
						"The handler logs this failure at ERROR and goes on with the value the call returned — the client gets the zero value as if it were the data, with a success status")
					v.WithCode(strings.TrimSpace(file.GetLine(line)))
					v.WithSuggestion("Answer the failure (an error status or an error shown on the page) and return, or log at WARN and show that the data is missing when going on without it is intended")
					violations = append(violations, v)
				}
				return true
			})
		}
		return violations
	})
}

// takesResponseWriter reports a function with an http.ResponseWriter
// parameter.
func takesResponseWriter(info *types.Info, ftype *ast.FuncType) bool {
	for _, field := range ftype.Params.List {
		if isNamedType(info.TypeOf(field.Type), "net/http", "ResponseWriter") {
			return true
		}
	}
	return false
}

// onlyLoggedFailure returns the `if err != nil` following the statement at i
// - values, err := call - when its branch only logs at ERROR and a later
// statement of the block reads one of the values.
func onlyLoggedFailure(info *types.Info, list []ast.Stmt, i int) *ast.IfStmt {
	assign, ok := list[i].(*ast.AssignStmt)
	if !ok || len(assign.Lhs) < 2 || len(assign.Rhs) != 1 {
		return nil
	}
	if _, isCall := ast.Unparen(assign.Rhs[0]).(*ast.CallExpr); !isCall {
		return nil
	}
	errIdent, ok := assign.Lhs[len(assign.Lhs)-1].(*ast.Ident)
	if !ok || !isErrorInterface(info.TypeOf(errIdent)) {
		return nil
	}
	errVar, _ := info.ObjectOf(errIdent).(*types.Var)
	var values []*types.Var
	for _, lhs := range assign.Lhs[:len(assign.Lhs)-1] {
		if ident, ok := lhs.(*ast.Ident); ok && ident.Name != "_" {
			if v, ok := info.ObjectOf(ident).(*types.Var); ok {
				values = append(values, v)
			}
		}
	}
	check, ok := list[i+1].(*ast.IfStmt)
	if !ok || errVar == nil || len(values) == 0 || check.Init != nil || check.Else != nil || !testsNotNil(info, check.Cond, errVar) || !onlyLogsErrors(check.Body) {
		return nil
	}
	for _, later := range list[i+2:] {
		for _, v := range values {
			if mentionsVar(info, later, v) {
				return check
			}
		}
	}
	return nil
}

// testsNotNil reports a condition `v != nil`.
func testsNotNil(info *types.Info, cond ast.Expr, v *types.Var) bool {
	bin, ok := ast.Unparen(cond).(*ast.BinaryExpr)
	return ok && bin.Op == token.NEQ && isNilIdent(ast.Unparen(bin.Y)) && isObjectIdent(info, bin.X, v)
}

// errorLogMethods are the logger methods that record a failure.
var errorLogMethods = map[string]bool{"Error": true, "Errorf": true, "ErrorContext": true, "Errorw": true}

// onlyLogsErrors reports a branch made only of ERROR log calls.
func onlyLogsErrors(body *ast.BlockStmt) bool {
	if len(body.List) == 0 {
		return false
	}
	for _, stmt := range body.List {
		expr, ok := stmt.(*ast.ExprStmt)
		if !ok {
			return false
		}
		call, ok := expr.X.(*ast.CallExpr)
		if !ok {
			return false
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || !errorLogMethods[sel.Sel.Name] {
			return false
		}
	}
	return true
}
