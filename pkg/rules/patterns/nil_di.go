package patterns

import (
	"go/ast"
	"go/types"
	"strings"
	"unicode"

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
			"Detects nil arguments to constructor functions for high-risk DI parameters (a pointer or interface named logger, service, repo, ...)",
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
			// not guessed from the constructor name or the position, and
			// one whose type is a collection is not a dependency.
			paramName, dependency := constructorParam(ctx.GoAST, info, call, i)
			if !dependency || !r.isHighRiskParam(paramName) {
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

// highRiskParamWords are the words of a parameter name that mark a
// dependency a constructor cannot work without.
var highRiskParamWords = map[string]bool{
	"logger": true, "log": true,
	"service": true, "svc": true,
	"repo": true, "repository": true,
	"storage": true, "store": true,
	"handler": true, "controller": true,
	"client": true, "conn": true,
	"db": true, "database": true,
	"cache":     true,
	"metrics":   true,
	"validator": true,
}

// isHighRiskParam reports whether one of the words of the parameter name
// (camelCase or snake_case, singular or plural) marks a dependency: userRepo,
// dbConn and loggers do, catalog and blog do not contain the word log.
func (r *NilDIRule) isHighRiskParam(paramHint string) bool {
	for _, word := range identifierWords(paramHint) {
		// A plural names several of the same dependency: loggers, repos.
		if highRiskParamWords[word] || highRiskParamWords[strings.TrimSuffix(word, "s")] {
			return true
		}
	}
	return false
}

// identifierWords splits an identifier into lower-case words at underscores
// and camelCase boundaries; an acronym is one word (HTTPClient: http, client).
func identifierWords(name string) []string {
	var words []string
	runes := []rune(name)
	start := 0
	flush := func(end int) {
		if end > start {
			words = append(words, strings.ToLower(string(runes[start:end])))
		}
		start = end
	}
	for i := 0; i < len(runes); i++ {
		switch {
		case runes[i] == '_':
			flush(i)
			start = i + 1
		case i > start && unicode.IsUpper(runes[i]):
			prevLower := !unicode.IsUpper(runes[i-1])
			nextLower := i+1 < len(runes) && unicode.IsLower(runes[i+1])
			if prevLower || nextLower {
				flush(i)
			}
		}
	}
	flush(len(runes))
	return words
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

// constructorParam returns the name of the parameter the argument at
// argIndex of call lands in, "" when it cannot be resolved, and whether that
// parameter can be a dependency left unset. With type information the
// callee's signature answers, wherever it is declared: only a pointer or an
// interface is a dependency. Without it only a plain call of a function
// declared in file is resolved, and a parameter declared as a slice, map,
// channel or function is not a dependency.
func constructorParam(file *ast.File, info *types.Info, call *ast.CallExpr, argIndex int) (string, bool) {
	if info != nil {
		return signatureParam(info, call, argIndex)
	}
	ident, ok := call.Fun.(*ast.Ident)
	if !ok {
		return "", false
	}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv != nil || fn.Name.Name != ident.Name || fn.Type.Params == nil {
			continue
		}
		return fieldListParam(fn.Type.Params, argIndex)
	}
	return "", false
}

// signatureParam reads the parameter from the type of the called expression;
// a conversion or a call the checker did not type has none. A nil argument
// for a variadic parameter is one element of it.
func signatureParam(info *types.Info, call *ast.CallExpr, argIndex int) (string, bool) {
	tv, ok := info.Types[call.Fun]
	if !ok || !tv.IsValue() || tv.Type == nil {
		return "", false
	}
	sig, ok := tv.Type.Underlying().(*types.Signature)
	if !ok {
		return "", false
	}
	params := sig.Params()
	last := params.Len() - 1
	if argIndex < 0 || last < 0 {
		return "", false
	}
	if sig.Variadic() && argIndex >= last && !call.Ellipsis.IsValid() {
		slice, ok := params.At(last).Type().(*types.Slice)
		if !ok {
			return "", false
		}
		return params.At(last).Name(), isDependencyType(slice.Elem())
	}
	if argIndex > last {
		return "", false
	}
	return params.At(argIndex).Name(), isDependencyType(params.At(argIndex).Type())
}

// isDependencyType reports a type whose nil value is a missing dependency: a
// pointer or an interface. A nil slice or map is an empty collection.
func isDependencyType(t types.Type) bool {
	switch t.Underlying().(type) {
	case *types.Pointer, *types.Interface:
		return true
	}
	return false
}

// fieldListParam returns the name of the parameter at argIndex, "" for an
// unnamed one, and whether its declared type can be a dependency. Arguments
// past the end land in a trailing variadic parameter, one element each.
func fieldListParam(params *ast.FieldList, argIndex int) (string, bool) {
	var names []string
	var typeExprs []ast.Expr
	variadic := false
	for _, field := range params.List {
		_, variadic = field.Type.(*ast.Ellipsis)
		if len(field.Names) == 0 {
			names = append(names, "") // unnamed parameter still occupies a position
			typeExprs = append(typeExprs, field.Type)
			continue
		}
		for _, name := range field.Names {
			names = append(names, name.Name)
			typeExprs = append(typeExprs, field.Type)
		}
	}
	if variadic && argIndex >= len(names) {
		argIndex = len(names) - 1
	}
	if argIndex < 0 || argIndex >= len(names) {
		return "", false
	}
	typeExpr := typeExprs[argIndex]
	if ellipsis, ok := typeExpr.(*ast.Ellipsis); ok {
		typeExpr = ellipsis.Elt
	}
	switch typeExpr.(type) {
	case *ast.ArrayType, *ast.MapType, *ast.ChanType, *ast.FuncType:
		return names[argIndex], false
	}
	return names[argIndex], true
}
