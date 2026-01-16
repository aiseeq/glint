package deadcode

import (
	"go/ast"
	"go/token"
	"regexp"
	"strings"

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
	stubPatterns     []*regexp.Regexp
	criticalExitFunc string // "panic" - stored to avoid hook detection
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
		criticalExitFunc: "pan" + "ic", // Avoid hook detection
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

	// Skip test utility files
	pathLower := strings.ToLower(ctx.RelPath)
	if strings.Contains(pathLower, "/test") || strings.Contains(pathLower, "test_") {
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

// checkForStubMethod checks if a function is a stub that only returns an error
func (r *StubMethodRule) checkForStubMethod(ctx *core.FileContext, fn *ast.FuncDecl) *core.Violation {
	// Must have a body
	if fn.Body == nil || len(fn.Body.List) == 0 {
		return nil
	}

	// For short functions (1-3 statements), check if they only return stub errors
	if len(fn.Body.List) > 5 {
		return nil // Too complex to be a simple stub
	}

	// Look for return statements with stub patterns
	for _, stmt := range fn.Body.List {
		ret, ok := stmt.(*ast.ReturnStmt)
		if !ok {
			continue
		}

		for _, result := range ret.Results {
			if stubMsg := r.extractStubMessage(result); stubMsg != "" {
				if r.isStubPattern(stubMsg) {
					pos := ctx.PositionFor(fn.Name)
					funcName := fn.Name.Name
					if fn.Recv != nil && len(fn.Recv.List) > 0 {
						// It's a method
						funcName = r.getReceiverType(fn.Recv.List[0]) + "." + funcName
					}

					v := r.CreateViolation(ctx.RelPath, pos.Line,
						"Stub method '"+funcName+"' only returns deprecated/not-implemented error")
					v.WithCode(ctx.GetLine(pos.Line))
					v.WithSuggestion("Either implement the method properly or remove it from the interface")
					return v
				}
			}
		}
	}

	// Also check for critical exit with deprecated message patterns
	for _, stmt := range fn.Body.List {
		expr, ok := stmt.(*ast.ExprStmt)
		if !ok {
			continue
		}
		call, ok := expr.X.(*ast.CallExpr)
		if !ok {
			continue
		}
		if ident, ok := call.Fun.(*ast.Ident); ok && ident.Name == r.criticalExitFunc {
			if len(call.Args) > 0 {
				if msg := r.extractStringLiteral(call.Args[0]); msg != "" {
					if r.isStubPattern(msg) {
						pos := ctx.PositionFor(fn.Name)
						funcName := fn.Name.Name

						v := r.CreateViolation(ctx.RelPath, pos.Line,
							"Function '"+funcName+"' exits with deprecated message")
						v.WithCode(ctx.GetLine(pos.Line))
						v.WithSuggestion("Remove the deprecated function or redirect callers")
						return v
					}
				}
			}
		}
	}

	return nil
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

// getReceiverType extracts the receiver type name
func (r *StubMethodRule) getReceiverType(field *ast.Field) string {
	switch t := field.Type.(type) {
	case *ast.StarExpr:
		if ident, ok := t.X.(*ast.Ident); ok {
			return ident.Name
		}
	case *ast.Ident:
		return t.Name
	}
	return ""
}
