package patterns

import (
	"errors"
	"go/ast"
	"go/types"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewResponseWrapperRecordsLastStatusRule())
}

// ResponseWrapperRecordsLastStatusRule detects a WriteHeader of a type
// wrapping http.ResponseWriter that stores the status it is given with no
// guard on a status already stored:
//
//	func (w *watchWriter) WriteHeader(code int) {
//		w.status = code
//		w.ResponseWriter.WriteHeader(code)
//	}
//
// net/http keeps the first status and ignores the later calls ("superfluous
// response.WriteHeader"), the wrapper keeps the last one. A timeout or
// recovery middleware that writes its code after the handler answered makes
// the wrapper record a failure the client never got, and the access log,
// metrics or alerts built on it disagree with what was sent.
type ResponseWrapperRecordsLastStatusRule struct {
	*rules.BaseRule
}

// NewResponseWrapperRecordsLastStatusRule creates the rule
func NewResponseWrapperRecordsLastStatusRule() *ResponseWrapperRecordsLastStatusRule {
	return &ResponseWrapperRecordsLastStatusRule{BaseRule: rules.NewBaseRule(
		"response-wrapper-records-last-status",
		"patterns",
		"Detects a WriteHeader of an http.ResponseWriter wrapper that stores every status it gets — the client got the first one, the wrapper records the last",
		core.SeverityMedium,
	)}
}

// AnalyzeFile is a no-op: the wrapped writer is recognized by its type.
func (r *ResponseWrapperRecordsLastStatusRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *ResponseWrapperRecordsLastStatusRule) RequiresSSA() bool { return false }

// AnalyzeGoProject reports the unguarded status stores of wrappers.
func (r *ResponseWrapperRecordsLastStatusRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, errors.New("response wrapper records last status: nil Go project context")
	}
	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(file *core.FileContext, info *types.Info) []*core.Violation {
		var violations []*core.Violation
		for _, decl := range file.GoAST.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || fn.Recv == nil || fn.Name.Name != "WriteHeader" || !wrapsResponseWriter(info, fn) {
				continue
			}
			store := unguardedStatusStore(info, fn)
			if store == nil {
				continue
			}
			line := file.LineFor(store)
			if file.IsSuppressed(line, r.Name()) {
				continue
			}
			v := r.CreateViolation(file.RelPath, line,
				"WriteHeader stores every status it gets — net/http sends the first one and ignores the rest, so a code written later (a timeout, a recovery) is recorded while the client got another")
			v.WithCode(strings.TrimSpace(file.GetLine(line)))
			v.WithSuggestion("Store the status only while none is recorded (if w.status == 0, or a wroteHeader flag), as net/http does")
			violations = append(violations, v)
		}
		return violations
	})
}

// wrapsResponseWriter reports a method whose receiver is a struct holding an
// http.ResponseWriter, embedded or in a named field.
func wrapsResponseWriter(info *types.Info, fn *ast.FuncDecl) bool {
	if len(fn.Recv.List) != 1 {
		return false
	}
	recv := info.TypeOf(fn.Recv.List[0].Type)
	if ptr, ok := recv.(*types.Pointer); ok {
		recv = ptr.Elem()
	}
	structType, ok := recv.Underlying().(*types.Struct)
	if !ok {
		return false
	}
	for field := range structType.Fields() {
		if isNamedType(field.Type(), "net/http", "ResponseWriter") {
			return true
		}
	}
	return false
}

// unguardedStatusStore returns the assignment of the status parameter to a
// field of the receiver made at the top of WriteHeader, when no statement of
// the method tests a field of the receiver first: a guard (if w.status == 0,
// if w.wroteHeader) keeps the first code.
func unguardedStatusStore(info *types.Info, fn *ast.FuncDecl) *ast.AssignStmt {
	params := fn.Type.Params.List
	if len(params) != 1 || len(params[0].Names) != 1 || len(fn.Recv.List[0].Names) != 1 {
		return nil
	}
	code, codeOK := info.Defs[params[0].Names[0]].(*types.Var)
	recv, recvOK := info.Defs[fn.Recv.List[0].Names[0]].(*types.Var)
	if !codeOK || !recvOK {
		return nil
	}
	var store *ast.AssignStmt
	for _, stmt := range fn.Body.List {
		switch s := stmt.(type) {
		case *ast.IfStmt, *ast.SwitchStmt:
			if mentionsVar(info, s, recv) {
				return nil
			}
		case *ast.AssignStmt:
			if store != nil || len(s.Lhs) != 1 || len(s.Rhs) != 1 {
				continue
			}
			sel, ok := s.Lhs[0].(*ast.SelectorExpr)
			value, isIdent := ast.Unparen(s.Rhs[0]).(*ast.Ident)
			if ok && isIdent && info.Uses[value] == code && isObjectIdent(info, sel.X, recv) {
				store = s
			}
		}
	}
	return store
}

// isObjectIdent reports an identifier naming obj.
func isObjectIdent(info *types.Info, expr ast.Expr, obj types.Object) bool {
	ident, ok := ast.Unparen(expr).(*ast.Ident)
	return ok && info.Uses[ident] == obj
}
