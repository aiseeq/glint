package httprules

import (
	"errors"
	"go/ast"
	"go/constant"
	"go/types"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
)

func init() {
	rules.Register(NewTemplateExecutedIntoResponseRule())
}

// TemplateExecutedIntoResponseRule detects a template executed straight into
// an http.ResponseWriter whose error branch answers with an error status on
// the same writer:
//
//	if err := t.ExecuteTemplate(w, name, data); err != nil {
//		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
//	}
//
// The first byte the template writes commits status 200. A failing action
// halfway through leaves the client a page cut at that action with the error
// text glued to it, and monitoring, logs and tests reading the status see a
// success. Rendered into a buffer first, the failure can still become a 500.
type TemplateExecutedIntoResponseRule struct {
	*rules.BaseRule
}

// NewTemplateExecutedIntoResponseRule creates the rule
func NewTemplateExecutedIntoResponseRule() *TemplateExecutedIntoResponseRule {
	return &TemplateExecutedIntoResponseRule{BaseRule: rules.NewBaseRule(
		"template-executed-into-response",
		"patterns",
		"Detects a template executed straight into the http.ResponseWriter whose error branch answers an error status — the first byte already sent 200, the error lands inside the page",
		core.SeverityMedium,
	)}
}

// AnalyzeFile is a no-op: the template and the writer are recognized by type.
func (r *TemplateExecutedIntoResponseRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *TemplateExecutedIntoResponseRule) RequiresSSA() bool { return false }

// AnalyzeGoProject reports the executions into a writer answered by an error
// status on failure.
func (r *TemplateExecutedIntoResponseRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, errors.New("template executed into response: nil Go project context")
	}
	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(file *core.FileContext, info *types.Info) []*core.Violation {
		var violations []*core.Violation
		ast.Inspect(file.GoAST, func(n ast.Node) bool {
			block, ok := n.(*ast.BlockStmt)
			if !ok {
				return true
			}
			for i, stmt := range block.List {
				call, branch := patternkit.ExecuteChecked(block.List, i, stmt)
				if call == nil {
					continue
				}
				writer := templateResponseWriter(info, call)
				if writer == nil || !writesErrorStatus(info, branch, writer) {
					continue
				}
				line := file.LineFor(call)
				if file.IsSuppressed(line, r.Name()) {
					continue
				}
				v := r.CreateViolation(file.RelPath, line,
					"The template is executed straight into the ResponseWriter while its error branch answers an error status — the first byte already committed 200, so a failing template leaves a cut page with the error text inside it")
				v.WithCode(strings.TrimSpace(file.GetLine(line)))
				v.WithSuggestion("Execute the template into a bytes.Buffer, answer the error status when it fails, and write the buffer only on success")
				violations = append(violations, v)
			}
			return true
		})
		return violations
	})
}

// templateResponseWriter returns the http.ResponseWriter a call of
// Execute or ExecuteTemplate of html/template or text/template writes into.
func templateResponseWriter(info *types.Info, call *ast.CallExpr) *types.Var {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || (sel.Sel.Name != "Execute" && sel.Sel.Name != "ExecuteTemplate") || len(call.Args) == 0 {
		return nil
	}
	recv := info.TypeOf(sel.X)
	if !patternkit.IsPointerToNamedType(recv, "html/template", "Template") && !patternkit.IsPointerToNamedType(recv, "text/template", "Template") {
		return nil
	}
	ident, ok := ast.Unparen(call.Args[0]).(*ast.Ident)
	if !ok || !patternkit.IsNamedType(info.TypeOf(ident), "net/http", "ResponseWriter") {
		return nil
	}
	writer, _ := info.Uses[ident].(*types.Var)
	return writer
}

// writesErrorStatus reports a branch answering an error status on the
// writer: http.Error(w, ...), w.WriteHeader(...), or a call handed the writer
// and a 4xx or 5xx status.
func writesErrorStatus(info *types.Info, body *ast.BlockStmt, writer *types.Var) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || found {
			return !found
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "WriteHeader" && patternkit.IsObjectIdent(info, sel.X, writer) {
			found = true
			return false
		}
		handed := false
		for _, arg := range call.Args {
			handed = handed || patternkit.IsObjectIdent(info, arg, writer)
		}
		if !handed {
			return true
		}
		for _, arg := range call.Args {
			if tv, ok := info.Types[arg]; ok && tv.Value != nil && tv.Value.Kind() == constant.Int && patternkit.IsStatusExpr(arg) {
				if status, exact := constant.Int64Val(tv.Value); exact && status >= 400 && status <= 599 {
					found = true
				}
			}
		}
		return !found
	})
	return found
}
