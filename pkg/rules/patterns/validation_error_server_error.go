package patterns

import (
	"errors"
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"golang.org/x/tools/go/types/typeutil"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewValidationErrorAnsweredAsServerErrorRule())
}

// mapperDepth bounds how deep a mapper passing the error on is followed to
// its 5xx default.
const mapperDepth = 3

// ValidationErrorAnsweredAsServerErrorRule detects an HTTP handler that hands
// the error of a call to a mapper telling errors apart by errors.Is and
// answering the rest with a 5xx, while the call can fail with a plain input
// check - a fresh error no errors.Is matches:
//
//	if protocol.Name == "" {
//	    return fmt.Errorf("protocol name is required") // no sentinel to match
//	}
//	...
//	if err := r.service.CreateEntry(ctx, &protocol); err != nil {
//	    writeItemError(w, req, err) // ErrNotFound → 404, ErrConflict → 409, the rest → 500
//	}
//
// The client's invalid input is answered as a server failure and logged as
// one. The call has to be handed what the handler decoded the request body
// into, and the error made under a check of a parameter (not of the
// server's own state): a path id is never empty, and a missing dependency is
// a server failure.
type ValidationErrorAnsweredAsServerErrorRule struct {
	*rules.BaseRule
}

// NewValidationErrorAnsweredAsServerErrorRule creates the rule
func NewValidationErrorAnsweredAsServerErrorRule() *ValidationErrorAnsweredAsServerErrorRule {
	return &ValidationErrorAnsweredAsServerErrorRule{BaseRule: rules.NewBaseRule(
		"validation-error-answered-as-server-error",
		"patterns",
		"Detects an HTTP handler handing a call's error to a mapper that answers unknown errors with a 5xx, while the call fails an input check with a plain error no errors.Is matches — the client's invalid input is reported as a server failure",
		core.SeverityMedium,
	)}
}

// AnalyzeFile is a no-op: what a call returns is found in other files.
func (r *ValidationErrorAnsweredAsServerErrorRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *ValidationErrorAnsweredAsServerErrorRule) RequiresSSA() bool { return false }

// AnalyzeGoProject reports the mapper calls that answer an input check's
// plain error with a 5xx.
func (r *ValidationErrorAnsweredAsServerErrorRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, errors.New("validation error answered as server error: nil Go project context")
	}
	flow := newErrorFlow(ctx)
	var violations []*core.Violation
	for _, fn := range flow.order {
		request := handlerRequestParam(fn)
		if request == nil {
			continue
		}
		decoded := make(map[types.Object]bool)
		for _, target := range requestDecodeTargets(fn) {
			if root := rootIdent(addressed(target)); root != nil {
				decoded[fn.info.ObjectOf(root)] = true
			}
		}
		if len(decoded) == 0 {
			continue
		}
		ast.Inspect(fn.decl.Body, func(n ast.Node) bool {
			if _, nested := n.(*ast.FuncLit); nested {
				return false
			}
			check, ok := n.(*ast.IfStmt)
			if !ok || len(check.Body.List) == 0 {
				return true
			}
			errIdent := errNotNilIdent(fn.info, check.Cond)
			if errIdent == nil || comparesError(check.Body) {
				return true
			}
			mapper := serverErrorMapperCall(flow, fn, check.Body, errIdent)
			if mapper == nil {
				return true
			}
			call := flow.originCall(fn, errIdent, check.Body.List[0])
			if call == nil || !takesDecodedBody(fn, call, decoded) {
				return true
			}
			rejected := clientRejection(fn, call, flow.exprErrors(fn, errIdent, check.Body.List[0], 0))
			if rejected == nil {
				return true
			}
			line := fn.file.LineFor(mapper)
			if fn.file.IsSuppressed(line, r.Name()) {
				return true
			}
			v := r.CreateViolation(fn.file.RelPath, line, callName(call)+" can fail an input check with a plain error (\""+rejected.text+"\"), and "+callName(mapper)+" tells errors apart only by errors.Is and answers the rest with a 5xx — the client's invalid input is reported as a server failure")
			v.WithCode(strings.TrimSpace(fn.file.GetLine(line)))
			v.WithSuggestion("Wrap the input check's error in a validation sentinel (fmt.Errorf(\"%w: ...\", ErrInvalid)) and answer it with 400 in the mapper")
			violations = append(violations, v)
			return true
		})
	}
	return violations, nil
}

// serverErrorMapperCall returns the call of a branch handing the error to a
// project mapper that tells errors apart by errors.Is and answers the rest
// with a 5xx: a server-error answer among its top-level statements, or in a
// mapper it passes the error on to.
func serverErrorMapperCall(flow *errorFlow, fn typedFunc, body *ast.BlockStmt, errIdent *ast.Ident) *ast.CallExpr {
	errVar := fn.info.Uses[errIdent]
	var found *ast.CallExpr
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || found != nil {
			return found == nil
		}
		for i, arg := range call.Args {
			if ident, ok := ast.Unparen(arg).(*ast.Ident); ok && fn.info.Uses[ident] == errVar && answersRestWithServerError(flow, fn, call, i, mapperDepth) {
				found = call
			}
		}
		return found == nil
	})
	return found
}

// answersRestWithServerError reports a project function, handed the error
// at index, that compares it (errors.Is) and ends in a 5xx answer at its top
// level, or passes it on to such a function; one that reads the error's
// text to decide is left out.
func answersRestWithServerError(flow *errorFlow, fn typedFunc, call *ast.CallExpr, index, depth int) bool {
	callee, ok := typeutil.Callee(fn.info, call).(*types.Func)
	if !ok || depth == 0 {
		return false
	}
	target, ok := flow.funcs[callee.Origin()]
	if !ok || readsErrorText(target.decl.Body) {
		return false
	}
	sig, ok := callee.Type().(*types.Signature)
	if !ok || index >= sig.Params().Len() {
		return false
	}
	param := target.info.Defs[paramIdentAt(target.decl.Type, index)]
	compares := comparesParam(target, index)
	for _, stmt := range target.decl.Body.List {
		expr, ok := stmt.(*ast.ExprStmt)
		if !ok {
			continue
		}
		inner, ok := expr.X.(*ast.CallExpr)
		if !ok {
			continue
		}
		if compares && serverErrorAnswer(target.info, &ast.BlockStmt{List: []ast.Stmt{stmt}}) != nil {
			return true
		}
		for i, arg := range inner.Args {
			if ident, ok := ast.Unparen(arg).(*ast.Ident); ok && param != nil && target.info.Uses[ident] == param && answersRestWithServerError(flow, target, inner, i, depth-1) {
				return true
			}
		}
	}
	return false
}

// takesDecodedBody reports a call handed the value the handler decoded the
// request body into, whole (&item, item): the fields the callee checks are
// the client's own.
func takesDecodedBody(fn typedFunc, call *ast.CallExpr, decoded map[types.Object]bool) bool {
	for _, arg := range call.Args {
		if whole, ok := ast.Unparen(addressed(arg)).(*ast.Ident); ok && decoded[fn.info.ObjectOf(whole)] {
			return true
		}
	}
	return false
}

// clientRejection returns an input check of a field the call can fail,
// where the handler leaves the field as the client sent it: a field the
// handler sets itself (item.ID = id from the path) is never the client's
// mistake, and a plain parameter (id == "") is a value the handler parsed
// and checked already.
func clientRejection(fn typedFunc, call *ast.CallExpr, set *errorSet) *inputCheck {
	assigned := assignedFields(fn, call)
	for i := range set.invalid {
		if set.invalid[i].field != "" && !assigned[set.invalid[i].field] {
			return &set.invalid[i]
		}
	}
	return nil
}

// assignedFields returns the names of the fields the handler assigns before
// call (item.ID = id).
func assignedFields(fn typedFunc, call *ast.CallExpr) map[string]bool {
	fields := map[string]bool{}
	ast.Inspect(fn.decl.Body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || assign.Pos() > call.Pos() {
			return true
		}
		for _, lhs := range assign.Lhs {
			if sel, ok := ast.Unparen(lhs).(*ast.SelectorExpr); ok {
				fields[sel.Sel.Name] = true
			}
		}
		return true
	})
	return fields
}

// addressed returns x of &x, and expr itself otherwise.
func addressed(expr ast.Expr) ast.Expr {
	if unary, ok := ast.Unparen(expr).(*ast.UnaryExpr); ok && unary.Op == token.AND {
		return unary.X
	}
	return expr
}

// readsErrorText reports a body that decides by an error's text:
// strings.Contains(err.Error(), ...) and the like.
func readsErrorText(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return !found
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && isIdentNamed(sel.X, "strings") {
			for _, arg := range call.Args {
				if inner, ok := ast.Unparen(arg).(*ast.CallExpr); ok && callName(inner) == "Error" && len(inner.Args) == 0 {
					found = true
				}
			}
		}
		return !found
	})
	return found
}
