package patterns

import (
	"fmt"
	"go/ast"
	"go/token"
	"math"
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
		// YAML/JSON decoders deliver integers as float64; anything else (or a
		// fractional value) is ambiguous input and must be an error, not a
		// silent fallback to the default.
		switch val := v.(type) {
		case int:
		case float64:
			if val != math.Trunc(val) {
				return fmt.Errorf("magic-number: min_value must be an integer, got %v", val)
			}
		default:
			return fmt.Errorf("magic-number: min_value must be an integer, got %T (%v)", v, v)
		}
	}
	if err := r.BaseRule.Configure(settings); err != nil {
		return err
	}
	r.minValue = r.GetIntSetting("min_value", r.minValue)
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

	// One pass over the file collects every literal's context up front; checking
	// each literal is then O(1) instead of five full traversals per literal.
	contexts := collectLitContexts(ctx.GoAST)

	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		if v := r.checkLiteral(ctx, n, contexts); v != nil {
			violations = append(violations, v)
		}
		return true
	})

	return violations
}

func (r *MagicNumberRule) checkLiteral(ctx *core.FileContext, n ast.Node, contexts *litContexts) *core.Violation {
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
		// Literals above math.MaxInt64 are valid Go (uint64 constants such as
		// hash bases and bit masks). They carry their own meaning and are not
		// what this rule is about, so they are skipped rather than reported.
		if _, uintErr := strconv.ParseUint(lit.Value, 0, 64); uintErr == nil {
			return nil
		}
		return r.invalidMagicNumberLiteral(ctx, lit, err)
	}

	if r.shouldSkipValue(contexts, lit, value) {
		return nil
	}

	pos := ctx.PositionFor(lit)
	v := r.CreateViolation(ctx.RelPath, pos.Line, "Consider using a named constant instead of magic number")
	v.WithCode(lit.Value)
	v.WithSuggestion("Define a const with a descriptive name")
	return v
}

func (r *MagicNumberRule) invalidMagicNumberLiteral(ctx *core.FileContext, lit *ast.BasicLit, err error) *core.Violation {
	line := ctx.PositionFor(lit).Line
	v := r.CreateViolation(ctx.RelPath, line, "Invalid integer literal: "+err.Error())
	v.WithCode(ctx.GetLine(line))
	v.WithSuggestion("Fix the integer literal before magic-number analysis")
	return v
}

func (r *MagicNumberRule) shouldSkipValue(contexts *litContexts, lit *ast.BasicLit, value int64) bool {
	if value >= 0 && value < int64(r.minValue) {
		return true
	}
	if contexts.inConstDecl(lit) {
		return true
	}
	if r.isAcceptableValue(value) {
		return true
	}
	return contexts.array[lit] || contexts.timeDuration[lit] ||
		contexts.comparison[lit] || contexts.varDecl[lit]
}

// litContexts records, per integer literal, the syntactic contexts in which the
// literal is not a magic number. Collected once per file in a single traversal.
type litContexts struct {
	constRanges  [][2]token.Pos
	array        map[*ast.BasicLit]bool // array length, index, slice bound
	timeDuration map[*ast.BasicLit]bool // multiplied by time.Something
	comparison   map[*ast.BasicLit]bool // operand of a comparison
	varDecl      map[*ast.BasicLit]bool // value of a named var declaration
}

func collectLitContexts(file *ast.File) *litContexts {
	contexts := &litContexts{
		array:        make(map[*ast.BasicLit]bool),
		timeDuration: make(map[*ast.BasicLit]bool),
		comparison:   make(map[*ast.BasicLit]bool),
		varDecl:      make(map[*ast.BasicLit]bool),
	}

	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.GenDecl:
			if node.Tok == token.CONST {
				contexts.constRanges = append(contexts.constRanges, [2]token.Pos{node.Pos(), node.End()})
			}
		case *ast.ArrayType:
			markLit(contexts.array, node.Len)
		case *ast.IndexExpr:
			markLit(contexts.array, node.Index)
		case *ast.SliceExpr:
			markLit(contexts.array, node.Low)
			markLit(contexts.array, node.High)
			markLit(contexts.array, node.Max)
		case *ast.BinaryExpr:
			contexts.collectBinaryExpr(node)
		case *ast.ValueSpec:
			for _, val := range node.Values {
				markLit(contexts.varDecl, val)
			}
		}
		return true
	})

	return contexts
}

func (lc *litContexts) collectBinaryExpr(expr *ast.BinaryExpr) {
	switch expr.Op {
	case token.MUL:
		// 24 * time.Hour: the number gets its meaning from the unit.
		if isTimeSelector(expr.Y) {
			markLit(lc.timeDuration, expr.X)
		}
		if isTimeSelector(expr.X) {
			markLit(lc.timeDuration, expr.Y)
		}
	case token.LSS, token.GTR, token.LEQ, token.GEQ, token.EQL, token.NEQ:
		markLit(lc.comparison, expr.X)
		markLit(lc.comparison, expr.Y)
	}
}

func (lc *litContexts) inConstDecl(lit *ast.BasicLit) bool {
	for _, r := range lc.constRanges {
		if lit.Pos() >= r[0] && lit.End() <= r[1] {
			return true
		}
	}
	return false
}

func markLit(set map[*ast.BasicLit]bool, expr ast.Expr) {
	if lit, ok := expr.(*ast.BasicLit); ok {
		set[lit] = true
	}
}

// isTimeSelector reports whether expr is time.Hour, time.Minute, etc.
func isTimeSelector(expr ast.Expr) bool {
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	ident, ok := sel.X.(*ast.Ident)
	return ok && ident.Name == "time"
}

func (r *MagicNumberRule) isAcceptableValue(value int64) bool {
	// Common acceptable magic numbers
	acceptable := map[int64]bool{
		// Small numbers (often used for counts, retries, limits)
		2: true, 3: true, 4: true, 5: true, 6: true, 7: true, 9: true,
		// Numeric bases and bit operations
		8: true, 10: true, 16: true, 32: true, 64: true, 128: true, 256: true, 512: true,
		// Time-related (hours, minutes, seconds, days)
		11: true, 12: true, 13: true, 14: true, 15: true, 18: true, 20: true, 21: true, 22: true, 23: true,
		24: true, 25: true, 28: true, 30: true, 31: true, 39: true, 42: true, 43: true, 45: true,
		50: true, 59: true, 60: true, 80: true, 89: true, 90: true, 95: true, 99: true,
		120: true, 180: true, 300: true, 360: true,
		// Seconds in hour/day
		3600: true, 86400: true,
		// Common limits and sizes
		100: true, 133: true, 200: true, 250: true, 500: true, 1000: true, 1024: true,
		1985: true, 1990: true, 2000: true, 2048: true, 4096: true, 5000: true, 8192: true, 10000: true,
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
