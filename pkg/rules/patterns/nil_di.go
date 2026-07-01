package patterns

import (
	"go/ast"
	"strconv"
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

// AnalyzeFile checks for nil arguments in constructor calls
func (r *NilDIRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
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
			if !r.isNilIdent(arg) {
				continue
			}

			// Check if this line has suppression comment
			line := r.getLineFromNode(ctx, call)
			if r.hasSuppression(ctx, line) {
				continue
			}

			// Prefer the real parameter name when the constructor is
			// declared in this file; fall back to position heuristics.
			paramName := resolveParamName(ctx.GoAST, funcName, i)
			paramHint := paramName
			message := "Nil " + paramName + " argument to constructor " + funcName
			if paramName == "" {
				paramHint = r.guessParamType(funcName, i, len(call.Args))
				message = "Nil argument #" + strconv.Itoa(i+1) + " to constructor " + funcName +
					" (possibly " + paramHint + ")"
			}

			// Only flag high-risk nil parameters
			if !r.isHighRiskParam(paramHint) {
				continue
			}

			v := r.CreateViolation(ctx.RelPath, line, message)
			v.WithCode(ctx.GetLine(line))
			v.WithSuggestion("Verify this nil is intentional. Add '// nil-di: safe' comment to suppress if safe.")
			v.WithContext("constructor", funcName)
			v.WithContext("param_hint", paramHint)
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

// guessParamType tries to infer what the nil parameter is for based on constructor name and position
func (r *NilDIRule) guessParamType(funcName string, argIndex, totalArgs int) string {
	// Common constructor patterns
	nameLower := strings.ToLower(funcName)

	// For services, common pattern is (config, logger) or (config, repo, logger)
	if strings.Contains(nameLower, "service") {
		if argIndex == totalArgs-1 {
			return "logger"
		}
		if argIndex == 1 {
			return "repo/logger"
		}
	}

	// For repositories, common pattern is (db, ..., logger)
	if strings.Contains(nameLower, "repo") || strings.Contains(nameLower, "repository") {
		if argIndex == 0 {
			return "database"
		}
		if argIndex == totalArgs-1 {
			return "logger"
		}
	}

	// For middleware
	if strings.Contains(nameLower, "middleware") {
		if argIndex == 0 {
			return "logger"
		}
	}

	// For handlers
	if strings.Contains(nameLower, "handler") {
		if argIndex == 1 {
			return "logger"
		}
	}

	// Generic: check position patterns
	// Last arg is often logger in Go constructors
	if argIndex == totalArgs-1 && totalArgs > 1 {
		return "logger (last arg)"
	}

	return "dependency"
}

// hasSuppression checks if the line or previous line has a suppression comment
func (r *NilDIRule) hasSuppression(ctx *core.FileContext, line int) bool {
	// Check current line and previous line for suppression
	for checkLine := line - 1; checkLine <= line; checkLine++ {
		if checkLine < 1 || checkLine > len(ctx.Lines) {
			continue
		}
		lineContent := ctx.Lines[checkLine-1]
		// Check for suppression patterns
		if strings.Contains(lineContent, "nil-di: safe") ||
			strings.Contains(lineContent, "nil-di:safe") ||
			strings.Contains(lineContent, "nolint:nil-di") ||
			strings.Contains(lineContent, "// nil is intentional") ||
			strings.Contains(lineContent, "// nil ok") {
			return true
		}
	}
	return false
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

// isNilIdent checks if expression is the nil identifier
func (r *NilDIRule) isNilIdent(expr ast.Expr) bool {
	ident, ok := expr.(*ast.Ident)
	if !ok {
		return false
	}
	return ident.Name == "nil"
}

func (r *NilDIRule) getLineFromNode(ctx *core.FileContext, node ast.Node) int {
	if node == nil {
		return 1
	}

	pos := node.Pos()
	if pos == 0 {
		return 1
	}

	offset := int(pos) - 1
	if offset < 0 || offset >= len(ctx.Content) {
		return 1
	}

	line := 1
	for i := 0; i < offset && i < len(ctx.Content); i++ {
		if ctx.Content[i] == '\n' {
			line++
		}
	}
	return line
}

// resolveParamName returns the name of the constructor's parameter at
// argIndex when the constructor is declared in the same file, or "" when it
// is declared elsewhere (per-file AST has no cross-file resolution).
func resolveParamName(file *ast.File, funcName string, argIndex int) string {
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name == nil || fn.Name.Name != funcName || fn.Type.Params == nil {
			continue
		}
		idx := 0
		for _, field := range fn.Type.Params.List {
			count := len(field.Names)
			if count == 0 {
				count = 1 // unnamed parameter still occupies a position
			}
			for j := 0; j < count; j++ {
				if idx == argIndex {
					if j < len(field.Names) {
						return field.Names[j].Name
					}
					return ""
				}
				idx++
			}
		}
	}
	return ""
}
