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
	rules.Register(NewResponseWriterWrapperRule())
}

// ResponseWriterWrapperRule detects a type that embeds http.ResponseWriter
// to wrap it and has neither Flush nor Unwrap:
//
//	type statusWriter struct {
//		http.ResponseWriter
//		status int
//	}
//
//	func (w *statusWriter) WriteHeader(code int) { w.status = code; w.ResponseWriter.WriteHeader(code) }
//
// The embedded interface promotes Header, Write and WriteHeader only: the
// wrapper hides the http.Flusher of the writer under it, a streaming handler
// (server-sent events, a long download) behind the middleware finds no
// Flusher and fails, and http.ResponseController cannot reach the writer
// without Unwrap. Forward Flush, or give the wrapper
// Unwrap() http.ResponseWriter. In a project that calls
// http.NewResponseController a forwarded Flush is not enough: the controller
// reaches deadlines and hijacking only through Unwrap, and a handler behind
// the wrapper gets http.ErrNotSupported.
type ResponseWriterWrapperRule struct {
	*rules.BaseRule
}

// NewResponseWriterWrapperRule creates the rule
func NewResponseWriterWrapperRule() *ResponseWriterWrapperRule {
	return &ResponseWriterWrapperRule{BaseRule: rules.NewBaseRule(
		"response-writer-wrapper-hides-flush",
		"patterns",
		"Detects a wrapper embedding http.ResponseWriter with neither Flush nor Unwrap — streaming handlers behind it lose http.Flusher",
		core.SeverityMedium,
	)}
}

// AnalyzeFile is a no-op: the wrapper's methods may be in any file of its package.
func (r *ResponseWriterWrapperRule) AnalyzeFile(_ *core.FileContext) []*core.Violation { return nil }

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *ResponseWriterWrapperRule) RequiresSSA() bool { return false }

// AnalyzeGoProject reports the wrappers that hide Flush.
func (r *ResponseWriterWrapperRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, errors.New("response writer wrapper: nil Go project context")
	}
	controller := usesResponseController(ctx)
	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(file *core.FileContext, info *types.Info) []*core.Violation {
		var violations []*core.Violation
		ast.Inspect(file.GoAST, func(n ast.Node) bool {
			spec, ok := n.(*ast.TypeSpec)
			if !ok {
				return true
			}
			structType, ok := spec.Type.(*ast.StructType)
			if !ok || !embedsResponseWriter(structType, info) {
				return true
			}
			obj, ok := info.Defs[spec.Name].(*types.TypeName)
			if !ok {
				return true
			}
			methods := types.NewMethodSet(types.NewPointer(obj.Type()))
			if methods.Lookup(nil, "Unwrap") != nil {
				return true
			}
			message := "Type " + spec.Name.Name + " wraps http.ResponseWriter with neither Flush nor Unwrap — a streaming handler behind it finds no http.Flusher"
			if methods.Lookup(nil, "Flush") != nil {
				if !controller {
					return true
				}
				message = "Type " + spec.Name.Name + " wraps http.ResponseWriter without Unwrap, while the project uses http.ResponseController — deadline and hijack calls behind it return http.ErrNotSupported"
			}
			line := file.LineFor(spec)
			if file.IsSuppressed(line, r.Name()) {
				return true
			}
			v := r.CreateViolation(file.RelPath, line, message)
			v.WithCode(strings.TrimSpace(file.GetLine(line)))
			v.WithSuggestion("Add Unwrap() http.ResponseWriter returning the inner writer, and forward Flush to it when it is an http.Flusher")
			violations = append(violations, v)
			return true
		})
		return violations
	})
}

// embedsResponseWriter reports a struct with an embedded http.ResponseWriter.
func embedsResponseWriter(structType *ast.StructType, info *types.Info) bool {
	for _, field := range structType.Fields.List {
		if len(field.Names) != 0 {
			continue
		}
		named, ok := types.Unalias(info.TypeOf(field.Type)).(*types.Named)
		if ok && named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == "net/http" && named.Obj().Name() == "ResponseWriter" {
			return true
		}
	}
	return false
}

// usesResponseController reports a project calling http.NewResponseController.
func usesResponseController(ctx *core.GoProjectContext) bool {
	for _, pkgCtx := range ctx.Packages {
		if pkgCtx == nil || pkgCtx.Package == nil || pkgCtx.Package.TypesInfo == nil {
			continue
		}
		for _, file := range pkgCtx.Package.Syntax {
			found := false
			ast.Inspect(file, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok && isPackageFuncCall(file, pkgCtx.Package.TypesInfo, call, "net/http", "NewResponseController") {
					found = true
				}
				return !found
			})
			if found {
				return true
			}
		}
	}
	return false
}
