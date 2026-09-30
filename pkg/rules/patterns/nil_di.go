package patterns

import (
	"go/ast"
	"go/types"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewNilDIRule())
}

// NilDIRule detects nil arguments passed to constructor functions (New*)
// which often indicates missing dependency injection configuration.
// Focuses on high-risk parameters: logger, service, repo, storage, handler.
type NilDIRule struct {
	*rules.BaseRule
}

// NewNilDIRule creates the rule
func NewNilDIRule() *NilDIRule {
	return &NilDIRule{
		BaseRule: rules.NewBaseRule(
			"nil-di",
			"patterns",
			"Detects nil arguments to constructor functions for high-risk DI parameters (logger, service, repo)",
			core.SeverityMedium,
		),
	}
}

// AnalyzeFile checks one file without type information: the fallback the
// project analysis uses for files no type-checked package covers.
func (r *NilDIRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	return r.analyze(ctx, nil)
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *NilDIRule) RequiresSSA() bool { return false }

// AnalyzeGoProject checks every file: a constructor declared anywhere in the
// project is resolved through type information, so the nil argument is
// matched against the parameter it really lands in.
func (r *NilDIRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	return rules.AnalyzeGoFiles(ctx, r.Name(), r.analyze)
}

// analyze checks for nil arguments in constructor calls. info is nil for a
// file without type information; a constructor that file does not declare is
// then unknown, and the rule does not guess its parameters.
func (r *NilDIRule) analyze(ctx *core.FileContext, info *types.Info) []*core.Violation {
	if !ctx.IsGoFile() || ctx.IsTestFile() {
		return nil
	}

	// Skip files named test.go (benchmark files, etc.)
	if strings.HasSuffix(ctx.RelPath, "/test.go") || ctx.RelPath == "test.go" {
		return nil
	}

	if ctx.GoAST == nil {
		return nil
	}

	var violations []*core.Violation

	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		// Get function name
		funcName := r.getFuncName(call)
		if funcName == "" {
			return true
		}

		// Only check constructors (functions starting with "New")
		if !strings.HasPrefix(funcName, "New") {
			return true
		}

		// Skip known stdlib constructors where the nil-able parameter is not a DI dependency
		// (e.g. http.NewRequest body is io.Reader, bytes.NewReader takes []byte).
		if r.isStdlibNonDI(call) {
			return true
		}

		// Check each argument for nil
		for i, arg := range call.Args {
			if !isNilIdent(arg) {
				continue
			}

			// Check if this line has suppression comment
			line := ctx.LineFor(call)
			if r.hasSuppression(ctx, line) {
				continue
			}

			// The parameter the nil lands in decides. An unresolved one
			// (no type information and no declaration in this file) is
			// not guessed from the constructor name or the position.
			paramName := constructorParamName(ctx.GoAST, info, call, i)
			if !r.isHighRiskParam(paramName) {
				continue
			}

			v := r.CreateViolation(ctx.RelPath, line, "Nil "+paramName+" argument to constructor "+funcName)
			v.WithCode(ctx.GetLine(line))
			v.WithSuggestion("Verify this nil is intentional. Add '// nil-di: safe' comment to suppress if safe.")
			v.WithContext("constructor", funcName)
			v.WithContext("param_hint", paramName)
			violations = append(violations, v)
		}

		return true
	})

	return violations
}

// isHighRiskParam checks if a parameter name/type suggests it's risky to pass nil
func (r *NilDIRule) isHighRiskParam(paramHint string) bool {
	highRiskPatterns := []string{
		"logger", "log",
		"service", "svc",
		"repo", "repository",
		"storage", "store",
		"handler", "controller",
		"client", "conn",
		"db", "database",
		"cache",
		"metrics",
		"validator",
	}

	paramLower := strings.ToLower(paramHint)
	for _, pattern := range highRiskPatterns {
		if strings.Contains(paramLower, pattern) {
			return true
		}
	}

	return false
}

// hasSuppression delegates to the canonical core suppression check.
func (r *NilDIRule) hasSuppression(ctx *core.FileContext, line int) bool {
	return ctx.IsSuppressed(line, r.Name())
}

// getFuncName extracts the function name from a call expression
func (r *NilDIRule) getFuncName(call *ast.CallExpr) string {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		return fn.Name
	case *ast.SelectorExpr:
		return fn.Sel.Name
	}
	return ""
}

// isStdlibNonDI reports whether the call is a known stdlib constructor where a nil argument
// is a canonical use (not a missing dependency). Example: http.NewRequest(..., nil) is a
// bodiless GET; bytes.NewReader(nil) returns an empty reader.
func (r *NilDIRule) isStdlibNonDI(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	switch pkg.Name + "." + sel.Sel.Name {
	case "http.NewRequest",
		"http.NewRequestWithContext",
		"bytes.NewReader",
		"bytes.NewBuffer",
		"strings.NewReader":
		return true
	}
	return false
}

// constructorParamName returns the name of the parameter the argument at
// argIndex of call lands in, or "" when it cannot be resolved. With type
// information the callee's signature answers, wherever it is declared.
// Without it only a plain call of a function declared in file is resolved.
func constructorParamName(file *ast.File, info *types.Info, call *ast.CallExpr, argIndex int) string {
	if info != nil {
		return signatureParamName(info, call, argIndex)
	}
	ident, ok := call.Fun.(*ast.Ident)
	if !ok {
		return ""
	}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv != nil || fn.Name.Name != ident.Name || fn.Type.Params == nil {
			continue
		}
		return fieldListParamName(fn.Type.Params, argIndex)
	}
	return ""
}

// signatureParamName reads the parameter name from the type of the called
// expression; a conversion or a call the checker did not type has none.
func signatureParamName(info *types.Info, call *ast.CallExpr, argIndex int) string {
	tv, ok := info.Types[call.Fun]
	if !ok || !tv.IsValue() || tv.Type == nil {
		return ""
	}
	sig, ok := tv.Type.Underlying().(*types.Signature)
	if !ok {
		return ""
	}
	params := sig.Params()
	last := params.Len() - 1
	if sig.Variadic() && argIndex > last {
		argIndex = last
	}
	if argIndex < 0 || argIndex > last {
		return ""
	}
	return params.At(argIndex).Name()
}

// fieldListParamName returns the name of the parameter at argIndex, "" for an
// unnamed one. Arguments past the end land in a trailing variadic parameter.
func fieldListParamName(params *ast.FieldList, argIndex int) string {
	var names []string
	variadic := false
	for _, field := range params.List {
		_, variadic = field.Type.(*ast.Ellipsis)
		if len(field.Names) == 0 {
			names = append(names, "") // unnamed parameter still occupies a position
			continue
		}
		for _, name := range field.Names {
			names = append(names, name.Name)
		}
	}
	if variadic && argIndex >= len(names) {
		argIndex = len(names) - 1
	}
	if argIndex < 0 || argIndex >= len(names) {
		return ""
	}
	return names[argIndex]
}
