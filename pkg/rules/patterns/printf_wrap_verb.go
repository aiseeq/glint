package patterns

import (
	"go/ast"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewPrintfWrapVerbRule())
}

// PrintfWrapVerbRule detects the %w verb in a format that does not reach
// fmt.Errorf:
//
//	s.logger.Error(fmt.Sprintf("begin tx: %w", err))
//	dh.logger.Printf("validation failed: %w", err)
//
// Only fmt.Errorf (and errors packages built on it) knows %w; every other
// printf prints "%!w(*errors.errorString=&{...})", and the log line meant to
// explain a failure carries noise instead. go vet catches fmt.Sprintf, but
// not a logger's Printf it cannot prove to be a printf wrapper. Use %v (or
// %s) outside fmt.Errorf. A project function that passes its format on to
// fmt.Errorf is an Errorf too.
type PrintfWrapVerbRule struct {
	*rules.BaseRule
	// forwarders are the names of the project's functions that pass their
	// format parameter on to fmt.Errorf.
	forwarders map[string]bool
}

// NewPrintfWrapVerbRule creates the rule
func NewPrintfWrapVerbRule() *PrintfWrapVerbRule {
	return &PrintfWrapVerbRule{BaseRule: rules.NewBaseRule(
		"printf-w-outside-errorf",
		"patterns",
		"Detects %w in a format passed to a printf other than fmt.Errorf — the text gets %!w(...) instead of the error",
		core.SeverityMedium,
	)}
}

// errorfPackages know %w in their Errorf-like functions.
var errorfPackages = map[string]string{
	`"fmt"`:                           "fmt",
	`"golang.org/x/xerrors"`:          "xerrors",
	`"github.com/cockroachdb/errors"`: "errors",
}

// UseProjectFiles collects the project's functions that forward a format to
// fmt.Errorf.
func (r *PrintfWrapVerbRule) UseProjectFiles(files []*core.FileContext) {
	r.forwarders = make(map[string]bool)
	for _, ctx := range files {
		if !ctx.IsGoFile() || !ctx.HasGoAST() {
			continue
		}
		for _, decl := range ctx.GoAST.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if ok && fn.Body != nil && forwardsFormat(ctx.GoAST, fn) {
				r.forwarders[fn.Name.Name] = true
			}
		}
	}
}

// ResetState drops the forwarders of the previous root.
func (r *PrintfWrapVerbRule) ResetState() { r.forwarders = nil }

// AnalyzeFile reports the %w formats of a file that do not reach an Errorf.
func (r *PrintfWrapVerbRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || !ctx.HasGoAST() {
		return nil
	}
	var violations []*core.Violation
	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) < 2 {
			return true
		}
		name := calledName(call)
		if !strings.HasSuffix(name, "f") || r.wraps(ctx.GoAST, call, name) {
			return true
		}
		// The format is the literal that has arguments after it.
		for _, arg := range call.Args[:len(call.Args)-1] {
			format, ok := literalText(arg)
			if !ok || !hasWrapVerb(format) {
				continue
			}
			line := ctx.LineFor(arg)
			if ctx.IsSuppressed(line, r.Name()) {
				break
			}
			v := r.CreateViolation(ctx.RelPath, line, "%w in a format for "+name+" — only fmt.Errorf knows %w, and the text gets %!w(...) instead of the error")
			v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
			v.WithSuggestion("Use %v for the error outside fmt.Errorf")
			violations = append(violations, v)
			break
		}
		return true
	})
	return violations
}

// wraps reports a call to an Errorf that knows %w: fmt.Errorf (or an errors
// package's), or a project function forwarding to it.
func (r *PrintfWrapVerbRule) wraps(file *ast.File, call *ast.CallExpr, name string) bool {
	if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
		if pkg, ok := sel.X.(*ast.Ident); ok && name == "Errorf" {
			for path, defaultName := range errorfPackages {
				if helpers.PackageAliases(file, path, defaultName)[pkg.Name] {
					return true
				}
			}
		}
	}
	return r.forwarders[name]
}

// calledName is the name of the called function or method.
func calledName(call *ast.CallExpr) string {
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		return fun.Name
	case *ast.SelectorExpr:
		return fun.Sel.Name
	}
	return ""
}

// hasWrapVerb reports a %w verb (flags and width allowed), %% excluded.
func hasWrapVerb(format string) bool {
	for i := 0; i < len(format); i++ {
		if format[i] != '%' {
			continue
		}
		j := i + 1
		for j < len(format) && strings.IndexByte("+-# 0123456789.*[]", format[j]) >= 0 {
			j++
		}
		if j < len(format) && format[j] == 'w' {
			return true
		}
		i = j // skips the verb, and the second % of %%
	}
	return false
}

// forwardsFormat reports a function whose string parameter is passed as the
// format of fmt.Errorf.
func forwardsFormat(file *ast.File, fn *ast.FuncDecl) bool {
	params := make(map[string]bool)
	for _, field := range fn.Type.Params.List {
		if ident, ok := field.Type.(*ast.Ident); ok && ident.Name == "string" {
			for _, name := range field.Names {
				params[name.Name] = true
			}
		}
	}
	if len(params) == 0 {
		return false
	}
	fmtNames := helpers.PackageAliases(file, `"fmt"`, "fmt")
	found := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || found || len(call.Args) == 0 {
			return !found
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Errorf" {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		format, isIdent := call.Args[0].(*ast.Ident)
		found = ok && fmtNames[pkg.Name] && isIdent && params[format.Name]
		return !found
	})
	return found
}
