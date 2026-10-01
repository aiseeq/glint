package security

import (
	"go/ast"
	"reflect"
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewDebugFieldInResponseRule())
}

// DebugFieldInResponseRule detects a debug section in an API response type:
//
//	type StrategiesResponse struct {
//	    Strategies []Strategy `json:"strategies"`
//	    Debug      DebugInfo  `json:"debug"`
//	}
//	resp.Debug = DebugInfo{ConfigType: fmt.Sprintf("%T", h.service)}
//
// Every client, and whoever watches its traffic, reads the internals the
// section carries: implementation types, counts, server timestamps. A
// response type is one named …Response, …Reply, …Payload or …DTO, or one
// declared inside an HTTP handler. A boolean debug switch is a setting, not
// a section, and is left alone.
type DebugFieldInResponseRule struct {
	*rules.BaseRule
}

// NewDebugFieldInResponseRule creates the rule
func NewDebugFieldInResponseRule() *DebugFieldInResponseRule {
	return &DebugFieldInResponseRule{BaseRule: rules.NewBaseRule(
		"debug-field-in-response",
		"security",
		"Detects a debug section (json:\"debug\") in an API response type — every client reads the internals it carries",
		core.SeverityMedium,
	)}
}

var (
	responseTypeName = regexp.MustCompile(`(?:Response|Resp|Reply|Payload|DTO)$`)
	debugJSONName    = regexp.MustCompile(`(?i)^_?debug(?:_?info)?$`)
)

// AnalyzeFile reports the debug fields of response types.
func (r *DebugFieldInResponseRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.HasGoAST() || ctx.IsTestFile() {
		return nil
	}
	lr := newLineReporter(ctx, r.BaseRule)
	check := func(spec *ast.TypeSpec, inHandler bool) {
		st, ok := spec.Type.(*ast.StructType)
		if !ok || (!inHandler && !responseTypeName.MatchString(spec.Name.Name)) {
			return
		}
		for _, field := range st.Fields.List {
			if field.Tag == nil || isBoolType(field.Type) {
				continue
			}
			tag := reflect.StructTag(strings.Trim(field.Tag.Value, "`"))
			name, _, _ := strings.Cut(tag.Get("json"), ",")
			if debugJSONName.MatchString(name) {
				lr.report(field, "Response type "+spec.Name.Name+" carries a debug section (json:\""+name+"\") — every client reads the internals it holds",
					"Log the diagnostics on the server, or drop the section from the response", "debug_field_in_response")
			}
		}
	}
	for _, decl := range ctx.GoAST.Decls {
		switch d := decl.(type) {
		case *ast.GenDecl:
			for _, spec := range d.Specs {
				if ts, ok := spec.(*ast.TypeSpec); ok {
					check(ts, false)
				}
			}
		case *ast.FuncDecl:
			if d.Body == nil {
				continue
			}
			handler := takesResponseWriter(d.Type)
			ast.Inspect(d.Body, func(n ast.Node) bool {
				if ts, ok := n.(*ast.TypeSpec); ok {
					check(ts, handler)
				}
				return true
			})
		}
	}
	return lr.violations
}

// isBoolType reports the bool type written in a field.
func isBoolType(expr ast.Expr) bool {
	ident, ok := expr.(*ast.Ident)
	return ok && ident.Name == "bool"
}

// takesResponseWriter reports a function with an http.ResponseWriter parameter.
func takesResponseWriter(fn *ast.FuncType) bool {
	for _, param := range fn.Params.List {
		if sel, ok := param.Type.(*ast.SelectorExpr); ok && sel.Sel.Name == "ResponseWriter" {
			return true
		}
	}
	return false
}
