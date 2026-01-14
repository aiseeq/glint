package patterns

import (
	"go/ast"
	"go/token"
	"strconv"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewMagicNumberRule())
}

// MagicNumberRule detects hardcoded numbers that should be named constants
type MagicNumberRule struct {
	*rules.BaseRule
	minValue int // Minimum value to flag (0, 1, -1 are usually OK)
}

// NewMagicNumberRule creates the rule
func NewMagicNumberRule() *MagicNumberRule {
	return &MagicNumberRule{
		BaseRule: rules.NewBaseRule(
			"magic-number",
			"patterns",
			"Detects hardcoded numbers that should be named constants",
			core.SeverityLow,
		),
		minValue: 2, // Default: flag numbers >= 2
	}
}

// Configure allows setting rule options
func (r *MagicNumberRule) Configure(settings map[string]any) error {
	if v, ok := settings["min_value"]; ok {
		if minVal, ok := v.(int); ok {
			r.minValue = minVal
		}
	}
	return nil
}

// shouldSkipFile checks if file should be skipped (config files have many legitimate constants)
func (r *MagicNumberRule) shouldSkipFile(path string) bool {
	pathLower := strings.ToLower(path)
	skipPatterns := []string{
		"config/",    // config directory
		"/config/",   // config in subpath
		"_config.go", // config files
		"config.go",
		"constants/",    // constants directory
		"/constants/",   // constants in subpath
		"_constants.go", // constants files
		"constants.go",
		"blockchain/",  // blockchain code often has chain IDs
		"/blockchain/", // blockchain in subpath
		"crypto2b/",    // crypto provider - chain IDs
		"/crypto2b/",   // crypto in subpath
		"chain/",       // chain-related code
		"/chain/",      // chain in subpath
	}
	for _, pattern := range skipPatterns {
		if strings.Contains(pathLower, pattern) {
			return true
		}
	}
	return false
}

// AnalyzeFile checks for magic numbers
func (r *MagicNumberRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || !ctx.HasGoAST() || ctx.IsTestFile() {
		return nil
	}

	// Skip config files - they legitimately contain many business constants
	if r.shouldSkipFile(ctx.RelPath) {
		return nil
	}

	var violations []*core.Violation

	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		if v := r.checkLiteral(ctx, n); v != nil {
			violations = append(violations, v)
		}
		return true
	})

	return violations
}

func (r *MagicNumberRule) checkLiteral(ctx *core.FileContext, n ast.Node) *core.Violation {
	lit, ok := n.(*ast.BasicLit)
	if !ok || lit.Kind != token.INT {
		return nil
	}

	// Skip hex, octal, binary literals (they already have semantic context)
	if strings.HasPrefix(lit.Value, "0x") || strings.HasPrefix(lit.Value, "0X") ||
		strings.HasPrefix(lit.Value, "0o") || strings.HasPrefix(lit.Value, "0O") ||
		strings.HasPrefix(lit.Value, "0b") || strings.HasPrefix(lit.Value, "0B") {
		return nil
	}

	value, err := strconv.ParseInt(lit.Value, 0, 64)
	if err != nil {
		return nil
	}

	if r.shouldSkipValue(ctx, lit, value) {
		return nil
	}

	pos := ctx.PositionFor(lit)
	v := r.CreateViolation(ctx.RelPath, pos.Line, "Consider using a named constant instead of magic number")
	v.WithCode(lit.Value)
	v.WithSuggestion("Define a const with a descriptive name")
	return v
}

func (r *MagicNumberRule) shouldSkipValue(ctx *core.FileContext, lit *ast.BasicLit, value int64) bool {
	if value >= 0 && value < int64(r.minValue) {
		return true
	}
	if r.isInConstDecl(ctx.GoAST, lit) {
		return true
	}
	if r.isAcceptableValue(value) {
		return true
	}
	if r.isArrayContext(ctx.GoAST, lit) {
		return true
	}
	if r.isTimeDurationContext(ctx.GoAST, lit) {
		return true
	}
	if r.isComparisonContext(ctx.GoAST, lit) {
		return true
	}
	return r.isVarDeclContext(ctx.GoAST, lit)
}

func (r *MagicNumberRule) isInConstDecl(file *ast.File, lit *ast.BasicLit) bool {
	found := false
	ast.Inspect(file, func(n ast.Node) bool {
		genDecl, ok := n.(*ast.GenDecl)
		if !ok || genDecl.Tok != token.CONST {
			return true
		}

		// Check if the literal is within this const declaration
		if lit.Pos() >= genDecl.Pos() && lit.End() <= genDecl.End() {
			found = true
			return false
		}
		return true
	})
	return found
}

func (r *MagicNumberRule) isAcceptableValue(value int64) bool {
	// Common acceptable magic numbers
	acceptable := map[int64]bool{
		// Small numbers (often used for counts, retries, limits)
		2: true, 3: true, 4: true, 5: true, 6: true, 7: true,
		// Numeric bases and bit operations
		8: true, 10: true, 16: true, 32: true, 64: true, 128: true, 256: true, 512: true,
		// Time-related (hours, minutes, seconds, days)
		11: true, 12: true, 14: true, 15: true, 18: true, 20: true, 21: true, 22: true, 23: true,
		24: true, 25: true, 28: true, 30: true, 31: true, 39: true, 42: true, 43: true, 45: true,
		50: true, 59: true, 60: true, 80: true, 90: true, 95: true, 99: true,
		120: true, 180: true, 300: true, 360: true,
		// Seconds in hour/day
		3600: true, 86400: true,
		// Common limits and sizes
		100: true, 200: true, 250: true, 500: true, 1000: true, 1024: true,
		2000: true, 2048: true, 4096: true, 5000: true, 8192: true, 10000: true,
		// Larger limits (transaction limits, buffers)
		100000: true, 1000000: true, 1048576: true,
		// HTTP status codes
		201: true, 204: true, 301: true, 302: true, 304: true,
		400: true, 401: true, 403: true, 404: true, 405: true, 409: true, 422: true, 429: true,
		501: true, 502: true, 503: true, 504: true,
		// Year/date related
		365: true, 366: true,
		// Nanoseconds (end of day, timeouts)
		999999999: true,
		// Port and network related
		1025: true, 65535: true,
		// Test/development network IDs
		1337: true,
	}
	return acceptable[value]
}

func (r *MagicNumberRule) isArrayContext(file *ast.File, lit *ast.BasicLit) bool {
	found := false
	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.ArrayType:
			if node.Len == lit {
				found = true
				return false
			}
		case *ast.IndexExpr:
			if node.Index == lit {
				found = true
				return false
			}
		case *ast.SliceExpr:
			if node.Low == lit || node.High == lit || node.Max == lit {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

// isTimeDurationContext checks if number is used with time.Duration (e.g., 24 * time.Hour)
func (r *MagicNumberRule) isTimeDurationContext(file *ast.File, lit *ast.BasicLit) bool {
	found := false
	ast.Inspect(file, func(n ast.Node) bool {
		binExpr, ok := n.(*ast.BinaryExpr)
		if !ok || binExpr.Op != token.MUL {
			return true
		}

		// Check if lit is part of this multiplication
		if binExpr.X != lit && binExpr.Y != lit {
			return true
		}

		// Check if the other operand is time.Something
		var other ast.Expr
		if binExpr.X == lit {
			other = binExpr.Y
		} else {
			other = binExpr.X
		}

		if sel, ok := other.(*ast.SelectorExpr); ok {
			if ident, ok := sel.X.(*ast.Ident); ok {
				if ident.Name == "time" {
					// time.Hour, time.Minute, time.Second, etc.
					found = true
					return false
				}
			}
		}
		return true
	})
	return found
}

// isComparisonContext checks if number is used in comparison (len(x) > N, value < N, etc.)
func (r *MagicNumberRule) isComparisonContext(file *ast.File, lit *ast.BasicLit) bool {
	found := false
	ast.Inspect(file, func(n ast.Node) bool {
		binExpr, ok := n.(*ast.BinaryExpr)
		if !ok {
			return true
		}

		// Check comparison operators
		switch binExpr.Op {
		case token.LSS, token.GTR, token.LEQ, token.GEQ, token.EQL, token.NEQ:
			// Check if lit is part of this comparison
			if binExpr.X == lit || binExpr.Y == lit {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

// isVarDeclContext checks if number is in variable declaration with descriptive name
func (r *MagicNumberRule) isVarDeclContext(file *ast.File, lit *ast.BasicLit) bool {
	found := false
	ast.Inspect(file, func(n ast.Node) bool {
		// Check var declarations
		valueSpec, ok := n.(*ast.ValueSpec)
		if !ok {
			return true
		}

		// Check if lit is in this value spec
		for _, val := range valueSpec.Values {
			if val == lit {
				// Variable has a name, so the number has context
				found = true
				return false
			}
		}
		return true
	})
	return found
}
