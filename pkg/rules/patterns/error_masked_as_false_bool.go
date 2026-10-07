package patterns

import (
	"go/ast"
	"go/token"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewErrorMaskedAsFalseBoolRule())
}

// ErrorMaskedAsFalseBoolRule detects `if err != nil { return false }` patterns
// inside non-predicate bool-returning functions.
//
// The existing `error-masking` rule requires the function to return `error`.
// That misses a class of security-sensitive bugs where a `(...) bool`
// function internally calls an error-returning API, then conflates "error"
// with "not allowed":
//
//	func ValidateUserPermission(user, perm string) bool {
//	    permissions, err := c.GetRolePermissions(user)
//	    if err != nil {
//	        return false  // ← user gets denied for reasons they can't debug;
//	                      //   ops can't see that lookup is broken
//	    }
//	    ...
//	}
//
// Pure predicates (IsEnabled, HasRole, CanWrite, ShouldRetry) are exempt —
// returning false on lookup miss is their whole contract.
//
// Detects:
//   - `if err != nil { ... return false ... }` without any logging call
//   - Function's return type contains `bool` (any position, not just last)
//   - Function name does NOT start with Is/Has/Can/Should
//
// Skips:
//   - Test files
//   - Pure predicate functions (Is/Has/Can/Should prefix)
//   - Blocks that log the error before returning false
//   - Returns under a classification of the error (errors.Is(err, ErrNoRows))
//   - Branches that answer the client through the http.ResponseWriter
//   - Iterators in the manner of sql.Rows: the branch stores the error in a
//     field of the receiver that the type's Err() error method reads
type ErrorMaskedAsFalseBoolRule struct {
	*rules.BaseRule
}

// NewErrorMaskedAsFalseBoolRule creates the rule
func NewErrorMaskedAsFalseBoolRule() *ErrorMaskedAsFalseBoolRule {
	return &ErrorMaskedAsFalseBoolRule{
		BaseRule: rules.NewBaseRule(
			"error-masked-as-false-bool",
			"patterns",
			"Detects error conflated with 'false' return in non-predicate bool functions",
			core.SeverityHigh,
		),
	}
}

// AnalyzeFile runs the rule.
func (r *ErrorMaskedAsFalseBoolRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || ctx.IsTestFile() || !ctx.HasGoAST() {
		return nil
	}

	var violations []*core.Violation
	errFields := errMethodFields(ctx.GoAST)

	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			return true
		}

		if !r.returnsBool(fn) {
			return true
		}
		if isPredicateName(fn.Name.Name) {
			return true
		}

		violations = append(violations, r.findViolations(ctx, fn, errFields)...)
		return true
	})

	return violations
}

// errMethodFields maps a type name to the receiver fields its Err() error
// method reads: return r.err, if r.err != nil { return r.err },
// strings.Join(r.errs, "; ") — whatever the method makes its answer from.
func errMethodFields(file *ast.File) map[string]map[string]bool {
	fields := map[string]map[string]bool{}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "Err" || fn.Body == nil {
			continue
		}
		recvName, typeName := receiverNames(fn)
		if recvName == "" || fn.Type.Params.NumFields() != 0 || !returnsOnlyError(fn.Type) {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			expr, ok := n.(ast.Expr)
			if !ok {
				return true
			}
			if field := receiverField(expr, recvName); field != "" {
				if fields[typeName] == nil {
					fields[typeName] = map[string]bool{}
				}
				fields[typeName][field] = true
			}
			return true
		})
	}
	return fields
}

// receiverNames returns the receiver's variable and type names, or "" for a
// function or an unnamed receiver.
func receiverNames(fn *ast.FuncDecl) (recvName, typeName string) {
	if fn.Recv == nil {
		return "", ""
	}
	name, ok := receiverName(fn)
	if !ok {
		return "", ""
	}
	return name, helpers.ReceiverTypeName(fn.Recv.List[0].Type)
}

func returnsOnlyError(ftype *ast.FuncType) bool {
	if ftype.Results == nil || ftype.Results.NumFields() != 1 {
		return false
	}
	return isIdentNamed(ftype.Results.List[0].Type, "error")
}

// storesErrorForErrMethod reports whether the branch assigns the error (a
// wrap of it, its text appended to a list) to a receiver field the type's Err
// method reads: the failure stays observable, as with sql.Rows.Next and
// Rows.Err.
func storesErrorForErrMethod(fn *ast.FuncDecl, body *ast.BlockStmt, errName string, errFields map[string]map[string]bool) bool {
	recvName, typeName := receiverNames(fn)
	fields := errFields[typeName]
	if recvName == "" || len(fields) == 0 {
		return false
	}
	stored := false
	ast.Inspect(body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if stored || !ok || assign.Tok != token.ASSIGN || len(assign.Lhs) != len(assign.Rhs) {
			return !stored
		}
		for i, lhs := range assign.Lhs {
			if fields[receiverField(lhs, recvName)] && mentionsIdent(assign.Rhs[i], errName) {
				stored = true
			}
		}
		return !stored
	})
	return stored
}

// returnsBool checks if any of the function's return values is bool.
func (r *ErrorMaskedAsFalseBoolRule) returnsBool(fn *ast.FuncDecl) bool {
	if fn.Type.Results == nil {
		return false
	}
	for _, field := range fn.Type.Results.List {
		if ident, ok := field.Type.(*ast.Ident); ok && ident.Name == "bool" {
			return true
		}
	}
	return false
}

// findViolations scans a function body for `if err != nil { return false }`
// patterns without logging.
func (r *ErrorMaskedAsFalseBoolRule) findViolations(ctx *core.FileContext, fn *ast.FuncDecl, errFields map[string]map[string]bool) []*core.Violation {
	var violations []*core.Violation

	ast.Inspect(fn.Body, func(n ast.Node) bool {
		ifStmt, ok := n.(*ast.IfStmt)
		if !ok {
			return true
		}
		errName := errNilCheckName(ifStmt.Cond)
		if errName == "" {
			return true
		}

		ret := r.findReturnFalse(ifStmt.Body, errName)
		if ret == nil {
			return true
		}
		if r.hasLoggingCall(ifStmt.Body) {
			return true
		}
		if answersClient(fn, ifStmt.Body) {
			return true
		}
		if storesErrorForErrMethod(fn, ifStmt.Body, errName, errFields) {
			return true
		}

		pos := ctx.PositionFor(ret)
		lineContent := ctx.GetLine(pos.Line)
		if ctx.LineSuppresses(pos.Line, "error-masked-as-false-bool") {
			return true
		}

		v := r.CreateViolation(ctx.RelPath, pos.Line,
			"Error from subcall masked as 'false' in "+fn.Name.Name+
				" — caller can't distinguish failure from denial")
		v.WithCode(strings.TrimSpace(lineContent))
		v.WithSuggestion("Either log the error before returning false, or change the signature to " +
			"(bool, error) so the caller can handle lookup failure explicitly. CLAUDE.md: " +
			"'Every error must be explicit, never hidden'.")
		v.WithContext("function", fn.Name.Name)
		violations = append(violations, v)
		return true
	})

	return violations
}

// findReturnFalse returns the first `return false` (or `return false, ...`)
// inside the body, or nil.
//
// A branch that has classified the error — `if errors.Is(err, sql.ErrNoRows)`,
// `case errors.Is(err, ErrNotFound):` — answers false for that one kind of
// failure: "not found" is the answer, not a failure hidden behind it. Such
// branches are skipped; an else next to them is still read.
func (r *ErrorMaskedAsFalseBoolRule) findReturnFalse(body *ast.BlockStmt, errName string) *ast.ReturnStmt {
	var found *ast.ReturnStmt
	classified := map[*ast.BlockStmt]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		if found != nil {
			return false
		}
		switch node := n.(type) {
		case *ast.IfStmt:
			if classifiesError(node.Cond, errName) {
				classified[node.Body] = true
			}
		case *ast.BlockStmt:
			if classified[node] {
				return false
			}
		case *ast.CaseClause:
			for _, expr := range node.List {
				if classifiesError(expr, errName) {
					return false
				}
			}
		}
		ret, ok := n.(*ast.ReturnStmt)
		if !ok || len(ret.Results) == 0 {
			return true
		}
		// `return false, err` hands the error to the caller alongside the
		// bool — that is propagation, which is what this rule asks for, not
		// the masking it looks for.
		if returnCarriesError(ret) {
			return true
		}
		for _, res := range ret.Results {
			if ident, ok := res.(*ast.Ident); ok && ident.Name == "false" {
				found = ret
				return false
			}
		}
		return true
	})
	return found
}

// classifiesError reports whether the condition picks out one kind of the
// error: a call handed the error (errors.Is(err, X), errors.As(err, &t),
// os.IsNotExist(err)) or a comparison with a sentinel (err == io.EOF), alone
// or joined with ||. A negation selects everything but that kind, so it does
// not classify.
func classifiesError(cond ast.Expr, errName string) bool {
	switch c := cond.(type) {
	case *ast.ParenExpr:
		return classifiesError(c.X, errName)
	case *ast.BinaryExpr:
		switch c.Op {
		case token.LOR:
			return classifiesError(c.X, errName) && classifiesError(c.Y, errName)
		case token.EQL:
			return (isIdentNamed(c.X, errName) && !isNilIdent(c.Y)) ||
				(isIdentNamed(c.Y, errName) && !isNilIdent(c.X))
		}
	case *ast.CallExpr:
		for _, arg := range c.Args {
			if isIdentNamed(arg, errName) {
				return true
			}
		}
	}
	return false
}

func isIdentNamed(expr ast.Expr, name string) bool {
	ident, ok := expr.(*ast.Ident)
	return ok && ident.Name == name
}

// hasLoggingCall returns true if any statement in the block calls a logger
// (see helpers.IsLoggerCall).
func (r *ErrorMaskedAsFalseBoolRule) hasLoggingCall(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if found {
			return false
		}
		if call, ok := n.(*ast.CallExpr); ok && helpers.IsLoggerCall(call) {
			found = true
		}
		return !found
	})
	return found
}

// answersClient reports whether the branch hands the function's own
// http.ResponseWriter to somebody. Ошибка, о которой клиенту ответили, не
// потеряна: вызывающий узнал о сбое из ответа, а куда при этом уехала строка
// лога, решает тот помощник, которому writer передали. По имени помощника это
// не определить, поэтому признак взят по самому writer.
func answersClient(fn *ast.FuncDecl, body *ast.BlockStmt) bool {
	writers := responseWriterParamNames(fn.Type)
	if len(writers) == 0 {
		return false
	}
	answered := false
	ast.Inspect(body, func(n ast.Node) bool {
		if answered {
			return false
		}
		if call, ok := n.(*ast.CallExpr); ok && callWritesResponse(call, writers) {
			answered = true
		}
		return !answered
	})
	return answered
}

// callWritesResponse reports whether the call is given one of the writers:
// as an argument (a responder helper) or as the receiver (w.WriteHeader).
func callWritesResponse(call *ast.CallExpr, writers map[string]bool) bool {
	if len(writers) == 0 {
		return false
	}
	if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
		if ident, ok := sel.X.(*ast.Ident); ok && writers[ident.Name] {
			return true
		}
	}
	for _, arg := range call.Args {
		if ident, ok := arg.(*ast.Ident); ok && writers[ident.Name] {
			return true
		}
	}
	return false
}

// responseWriterParamNames lists the parameters declared as http.ResponseWriter.
func responseWriterParamNames(ftype *ast.FuncType) map[string]bool {
	names := map[string]bool{}
	if ftype == nil || ftype.Params == nil {
		return names
	}
	for _, field := range ftype.Params.List {
		sel, ok := field.Type.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "ResponseWriter" {
			continue
		}
		for _, name := range field.Names {
			names[name.Name] = true
		}
	}
	return names
}
