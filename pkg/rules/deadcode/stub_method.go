package deadcode

import (
	"go/ast"
	"go/token"
	"regexp"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewStubMethodRule())
}

// StubMethodRule detects methods that only return errors indicating they are deprecated or not implemented.
// These are typically interface compliance stubs that should be removed or properly implemented.
//
// Detects patterns like:
//
//	func (s *Service) Method() error {
//	    return fmt.Errorf("not implemented")
//	}
//
//	func (s *Service) Method() error {
//	    return errors.New("deprecated: use NewMethod instead")
//	}
type StubMethodRule struct {
	*rules.BaseRule
	stubPatterns []*regexp.Regexp
}

// NewStubMethodRule creates the rule
func NewStubMethodRule() *StubMethodRule {
	r := &StubMethodRule{
		BaseRule: rules.NewBaseRule(
			"stub-method",
			"deadcode",
			"Detects methods that only return 'not implemented' or 'deprecated' errors",
			core.SeverityMedium,
		),
	}
	r.stubPatterns = r.initStubPatterns()
	return r
}

// initStubPatterns initializes patterns for detecting stub error messages
func (r *StubMethodRule) initStubPatterns() []*regexp.Regexp {
	return []*regexp.Regexp{
		// "not implemented" variations
		regexp.MustCompile(`(?i)not\s+implemented`),
		// "deprecated" variations
		regexp.MustCompile(`(?i)deprecated`),
		// "removed" variations
		regexp.MustCompile(`(?i)\bremoved\b`),
		// "use X instead" pattern
		regexp.MustCompile(`(?i)use\s+\w+.*instead`),
		// "INTERFACE COMPLIANCE" comments
		regexp.MustCompile(`(?i)interface\s+compliance`),
		// "stub" or "placeholder"
		regexp.MustCompile(`(?i)\b(?:stub|placeholder)\b`),
		// "todo: implement" in error
		regexp.MustCompile(`(?i)todo:?\s*implement`),
	}
}

// AnalyzeFile checks for stub methods in Go files
func (r *StubMethodRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.HasGoAST() || ctx.IsTestFile() {
		return nil
	}

	var violations []*core.Violation

	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			return true
		}

		// Check if this function is a stub
		if v := r.checkForStubMethod(ctx, fn); v != nil {
			violations = append(violations, v)
		}

		return true
	})

	return violations
}

// checkForStubMethod reports a function whose every path ends in a stub: all
// of its return statements return a fixed "not implemented"/"deprecated"
// error, or it has none and its body panics with such a message. A function
// with a single real return path is an implementation whose fallback error
// merely uses one of those words.
func (r *StubMethodRule) checkForStubMethod(ctx *core.FileContext, fn *ast.FuncDecl) *core.Violation {
	if fn.Body == nil || len(fn.Body.List) == 0 || len(fn.Body.List) > 5 {
		return nil // a stub is short; a long body does real work
	}

	// A stub returns a fixed error. A function whose parameters feed the
	// error message is a domain error constructor, not a stub, even when the
	// message contains a trigger word ("user %s was removed").
	params := funcParamNames(fn)
	pos := ctx.PositionFor(fn.Name)

	returns := functionReturns(fn.Body)
	if len(returns) > 0 {
		for _, ret := range returns {
			if !r.isStubReturn(ret, params) {
				return nil
			}
		}
		funcName := fn.Name.Name
		if fn.Recv != nil && len(fn.Recv.List) > 0 {
			funcName = receiverTypeName(fn.Recv.List[0]) + "." + funcName
		}
		v := r.CreateViolation(ctx.RelPath, pos.Line,
			"Stub method '"+funcName+"' only returns deprecated/not-implemented error")
		v.WithCode(ctx.GetLine(pos.Line))
		v.WithSuggestion("Either implement the method properly or remove it from the interface")
		return v
	}

	// No return statement: a top-level panic ends every path.
	for _, stmt := range fn.Body.List {
		if msg, ok := r.panicMessage(stmt); ok && r.isStubPattern(msg) {
			v := r.CreateViolation(ctx.RelPath, pos.Line,
				"Function '"+fn.Name.Name+"' exits with deprecated message")
			v.WithCode(ctx.GetLine(pos.Line))
			v.WithSuggestion("Remove the deprecated function or redirect callers")
			return v
		}
	}
	return nil
}

// functionReturns collects the return statements of a body, leaving out the
// ones inside function literals, which return from the literal.
func functionReturns(body *ast.BlockStmt) []*ast.ReturnStmt {
	var returns []*ast.ReturnStmt
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.ReturnStmt:
			returns = append(returns, node)
		}
		return true
	})
	return returns
}

// isStubReturn reports whether a return statement returns a fixed stub error.
func (r *StubMethodRule) isStubReturn(ret *ast.ReturnStmt, params map[string]bool) bool {
	for _, result := range ret.Results {
		msg := r.extractStubMessage(result)
		if msg != "" && r.isStubPattern(msg) && !usesAnyIdent(result, params) {
			return true
		}
	}
	return false
}

// panicMessage returns the literal message of a panic statement.
func (r *StubMethodRule) panicMessage(stmt ast.Stmt) (string, bool) {
	expr, ok := stmt.(*ast.ExprStmt)
	if !ok {
		return "", false
	}
	call, ok := expr.X.(*ast.CallExpr)
	if !ok || len(call.Args) == 0 {
		return "", false
	}
	ident, ok := call.Fun.(*ast.Ident)
	if !ok || ident.Name != "panic" {
		return "", false
	}
	msg := r.extractStringLiteral(call.Args[0])
	return msg, msg != ""
}

// extractStubMessage extracts the error message from error constructors
func (r *StubMethodRule) extractStubMessage(expr ast.Expr) string {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return ""
	}

	// Check for fmt.Errorf, errors.New, etc.
	funcName := r.extractFuncName(call.Fun)
	if funcName == "" {
		return ""
	}

	errorFuncs := map[string]bool{
		"fmt.Errorf":    true,
		"errors.New":    true,
		"Errorf":        true,
		"New":           true,
		"errors.Wrap":   true,
		"errors.Wrapf":  true,
		"Wrap":          true,
		"Wrapf":         true,
		"Error":         true, // custom error constructors
		"NewError":      true,
		"ErrNotFound":   false, // Sentinel errors are ok
		"ErrValidation": false,
	}

	// Skip known sentinel errors
	if skip, found := errorFuncs[funcName]; found && !skip {
		return ""
	}

	if _, found := errorFuncs[funcName]; !found {
		// Not a known error constructor
		return ""
	}

	// Extract the first string argument
	if len(call.Args) == 0 {
		return ""
	}

	return r.extractStringLiteral(call.Args[0])
}

// extractFuncName extracts function name from call expression
func (r *StubMethodRule) extractFuncName(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		if x, ok := e.X.(*ast.Ident); ok {
			return x.Name + "." + e.Sel.Name
		}
	}
	return ""
}

// extractStringLiteral extracts string from basic literal or string expression
func (r *StubMethodRule) extractStringLiteral(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.BasicLit:
		if e.Kind == token.STRING {
			// Remove quotes
			s := e.Value
			if len(s) >= 2 {
				return s[1 : len(s)-1]
			}
		}
	case *ast.BinaryExpr:
		// Handle string concatenation: "not " + "implemented"
		if e.Op == token.ADD {
			left := r.extractStringLiteral(e.X)
			right := r.extractStringLiteral(e.Y)
			return left + right
		}
	}
	return ""
}

// isStubPattern checks if the message matches stub patterns
func (r *StubMethodRule) isStubPattern(msg string) bool {
	for _, pattern := range r.stubPatterns {
		if pattern.MatchString(msg) {
			return true
		}
	}
	return false
}

// funcParamNames collects the named, non-blank parameters of a function.
func funcParamNames(fn *ast.FuncDecl) map[string]bool {
	if fn.Type.Params == nil {
		return nil
	}
	names := make(map[string]bool)
	for _, field := range fn.Type.Params.List {
		for _, name := range field.Names {
			if name.Name != "" && name.Name != "_" {
				names[name.Name] = true
			}
		}
	}
	return names
}

// usesAnyIdent reports whether the expression references any of the given
// identifiers.
func usesAnyIdent(expr ast.Expr, names map[string]bool) bool {
	if len(names) == 0 {
		return false
	}
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		if ident, ok := n.(*ast.Ident); ok && names[ident.Name] {
			found = true
			return false
		}
		return !found
	})
	return found
}
