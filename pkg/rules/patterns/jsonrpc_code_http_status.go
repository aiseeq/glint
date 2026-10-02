package patterns

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewJSONRPCCodeComparedToHTTPStatusRule())
}

// JSONRPCCodeComparedToHTTPStatusRule detects the code of a JSON-RPC error
// compared with HTTP statuses, directly or by a predicate written for them:
//
//	if out.Error != nil {
//	    return zero, statusIsRetryable(out.Error.Code), err // switch status { case http.StatusTooManyRequests ... }
//	}
//
// JSON-RPC codes are negative (-32005 node behind, -32429 rate limited) and
// never equal an HTTP status: the check is always false, and every RPC-level
// failure is handled as the status branch's "otherwise" - no retry, no
// failover. The error is recognized by its envelope: a struct with a "result"
// and an "error" JSON field, the error holding a "code".
type JSONRPCCodeComparedToHTTPStatusRule struct {
	*rules.BaseRule
}

// NewJSONRPCCodeComparedToHTTPStatusRule creates the rule
func NewJSONRPCCodeComparedToHTTPStatusRule() *JSONRPCCodeComparedToHTTPStatusRule {
	return &JSONRPCCodeComparedToHTTPStatusRule{BaseRule: rules.NewBaseRule(
		"jsonrpc-code-compared-to-http-status",
		"patterns",
		"Detects a JSON-RPC error code compared with HTTP statuses, directly or by a status predicate — the negative code never matches, every RPC failure takes the other branch",
		core.SeverityHigh,
	)}
}

// AnalyzeFile is a no-op: the envelope and the predicate are types and other files.
func (r *JSONRPCCodeComparedToHTTPStatusRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *JSONRPCCodeComparedToHTTPStatusRule) RequiresSSA() bool { return false }

type httpStatusPredicatesKey struct{}

// AnalyzeGoProject reports the JSON-RPC codes judged as HTTP statuses.
func (r *JSONRPCCodeComparedToHTTPStatusRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%s: nil Go project context", r.Name())
	}
	predicates, err := core.SharedLoad(ctx, httpStatusPredicatesKey{}, func() (map[*types.Func]map[int]bool, error) {
		return collectHTTPStatusPredicates(ctx)
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", r.Name(), err)
	}
	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(fileCtx *core.FileContext, info *types.Info) []*core.Violation {
		var violations []*core.Violation
		report := func(node ast.Node) {
			line := fileCtx.LineFor(node)
			if fileCtx.IsSuppressed(line, r.Name()) {
				return
			}
			v := r.CreateViolation(fileCtx.RelPath, line, "A JSON-RPC error code is judged by HTTP statuses — the negative code never matches, and every RPC-level failure takes the other branch")
			v.WithCode(strings.TrimSpace(fileCtx.GetLine(line)))
			v.WithSuggestion("Decide by the JSON-RPC codes (-32005, -32429 ...) or the message, in a predicate of their own")
			violations = append(violations, v)
		}
		ast.Inspect(fileCtx.GoAST, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.CallExpr:
				callee := staticFunc(info, node)
				for index := range predicates[callee] {
					if index < len(node.Args) && jsonRPCErrorCode(info, node.Args[index]) {
						report(node)
					}
				}
			case *ast.BinaryExpr:
				if (node.Op == token.EQL || node.Op == token.NEQ) &&
					((jsonRPCErrorCode(info, node.X) && isHTTPStatusConst(info, node.Y)) || (jsonRPCErrorCode(info, node.Y) && isHTTPStatusConst(info, node.X))) {
					report(node)
				}
			case *ast.SwitchStmt:
				if node.Tag != nil && jsonRPCErrorCode(info, node.Tag) && switchesOnHTTPStatus(info, node.Body) {
					report(node)
				}
			}
			return true
		})
		return violations
	})
}

// collectHTTPStatusPredicates indexes the functions comparing an int
// parameter with net/http Status constants, by the parameter's index.
func collectHTTPStatusPredicates(ctx *core.GoProjectContext) (map[*types.Func]map[int]bool, error) {
	predicates := make(map[*types.Func]map[int]bool)
	err := forEachTypedFuncDecl(ctx, func(info *types.Info, fn *ast.FuncDecl, obj *types.Func) {
		if obj == nil {
			return
		}
		for index := range fn.Type.Params.NumFields() {
			param := info.Defs[paramIdentAt(fn.Type, index)]
			if param == nil || !comparesWithHTTPStatus(info, fn.Body, param) {
				continue
			}
			if predicates[obj] == nil {
				predicates[obj] = map[int]bool{}
			}
			predicates[obj][index] = true
		}
	})
	return predicates, err
}

// comparesWithHTTPStatus reports a body comparing param with an http.Status
// constant: in a switch on it, or with == or !=.
func comparesWithHTTPStatus(info *types.Info, body *ast.BlockStmt, param types.Object) bool {
	isParam := func(expr ast.Expr) bool {
		ident, ok := ast.Unparen(expr).(*ast.Ident)
		return ok && info.Uses[ident] == param
	}
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.SwitchStmt:
			found = node.Tag != nil && isParam(node.Tag) && switchesOnHTTPStatus(info, node.Body)
		case *ast.BinaryExpr:
			found = (node.Op == token.EQL || node.Op == token.NEQ) &&
				((isParam(node.X) && isHTTPStatusConst(info, node.Y)) || (isParam(node.Y) && isHTTPStatusConst(info, node.X)))
		}
		return !found
	})
	return found
}

func switchesOnHTTPStatus(info *types.Info, body *ast.BlockStmt) bool {
	for _, stmt := range body.List {
		clause, ok := stmt.(*ast.CaseClause)
		if !ok {
			continue
		}
		for _, value := range clause.List {
			if isHTTPStatusConst(info, value) {
				return true
			}
		}
	}
	return false
}

// isHTTPStatusConst reports a net/http Status constant.
func isHTTPStatusConst(info *types.Info, expr ast.Expr) bool {
	sel, ok := ast.Unparen(expr).(*ast.SelectorExpr)
	if !ok || !strings.HasPrefix(sel.Sel.Name, "Status") {
		return false
	}
	c, ok := info.Uses[sel.Sel].(*types.Const)
	return ok && c.Pkg() != nil && c.Pkg().Path() == "net/http"
}

// jsonRPCErrorCode reports env.Error.Code of a JSON-RPC envelope: the field
// tagged "error" of a struct that also has a field tagged "result", whose
// type has an int field tagged "code".
func jsonRPCErrorCode(info *types.Info, expr ast.Expr) bool {
	code, ok := ast.Unparen(expr).(*ast.SelectorExpr)
	if !ok {
		return false
	}
	errField, ok := ast.Unparen(code.X).(*ast.SelectorExpr)
	if !ok {
		return false
	}
	errStruct, ok := structOf(info.TypeOf(errField))
	if !ok {
		return false
	}
	envelope, ok := structOf(info.TypeOf(errField.X))
	if !ok {
		return false
	}
	return jsonTagOf(errStruct.fields, code.Sel.Name) == "code" && jsonTagOf(envelope.fields, errField.Sel.Name) == "error" && hasJSONTag(envelope.fields, "result")
}

// jsonTagOf returns the JSON name of a struct's field.
func jsonTagOf(s *types.Struct, field string) string {
	for i := range s.NumFields() {
		if s.Field(i).Name() == field {
			name, _ := jsonTagName(s.Tag(i))
			return name
		}
	}
	return ""
}

func hasJSONTag(s *types.Struct, name string) bool {
	for i := range s.NumFields() {
		if tag, ok := jsonTagName(s.Tag(i)); ok && tag == name {
			return true
		}
	}
	return false
}
