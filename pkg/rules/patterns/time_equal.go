package patterns

import (
	"go/ast"
	"go/token"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewTimeEqualRule())
}

// TimeEqualRule detects time.Time comparisons using == instead of .Equal()
type TimeEqualRule struct {
	*rules.BaseRule
}

// NewTimeEqualRule creates the rule
func NewTimeEqualRule() *TimeEqualRule {
	return &TimeEqualRule{
		BaseRule: rules.NewBaseRule(
			"time-equal",
			"patterns",
			"Detects time.Time comparisons using == (use .Equal() method instead)",
			core.SeverityMedium,
		),
	}
}

// AnalyzeFile checks for time.Time == comparisons
func (r *TimeEqualRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || ctx.IsTestFile() {
		return nil
	}

	if ctx.GoAST == nil {
		return nil
	}

	// Check if time package is imported
	if !r.hasTimeImport(ctx.GoAST) {
		return nil
	}

	// Build type information from declarations
	typeInferrer := NewTypeInferrer(ctx.GoAST)

	var violations []*core.Violation

	// Find == and != comparisons involving time variables
	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		binary, ok := n.(*ast.BinaryExpr)
		if !ok {
			return true
		}

		if binary.Op != token.EQL && binary.Op != token.NEQ {
			return true
		}

		// Skip nil comparisons - these are pointer checks, not time comparisons
		if r.isNilExpr(binary.X) || r.isNilExpr(binary.Y) {
			return true
		}

		// Check if either side is a time expression
		leftIsTime := r.isTimeExpr(binary.X, typeInferrer)
		rightIsTime := r.isTimeExpr(binary.Y, typeInferrer)

		if !leftIsTime && !rightIsTime {
			return true
		}

		line := r.getLineFromNode(ctx, binary)
		var suggestion string
		if binary.Op == token.EQL {
			suggestion = "Use t1.Equal(t2) instead of t1 == t2 for time.Time comparison"
		} else {
			suggestion = "Use !t1.Equal(t2) instead of t1 != t2 for time.Time comparison"
		}

		v := r.CreateViolation(ctx.RelPath, line, "Direct time.Time comparison with ==")
		v.WithCode(ctx.GetLine(line))
		v.WithSuggestion(suggestion)
		v.WithContext("pattern", "time_equal")

		violations = append(violations, v)

		return true
	})

	return violations
}

func (r *TimeEqualRule) hasTimeImport(file *ast.File) bool {
	for _, imp := range file.Imports {
		if imp.Path != nil && imp.Path.Value == "\"time\"" {
			return true
		}
	}
	return false
}

func (r *TimeEqualRule) isNilExpr(expr ast.Expr) bool {
	if ident, ok := expr.(*ast.Ident); ok {
		return ident.Name == "nil"
	}
	return false
}

func (r *TimeEqualRule) isTimeExpr(expr ast.Expr, inferrer *TypeInferrer) bool {
	switch e := expr.(type) {
	case *ast.Ident:
		// Check type inference first
		if inferrer.IsTime(e.Name) {
			return true
		}
		// Fallback to common time variable names
		return r.looksLikeTimeVar(e.Name)

	case *ast.SelectorExpr:
		// Check for field access like obj.CreatedAt
		fieldName := e.Sel.Name

		// Check if the base object has a known time field
		if ident, ok := e.X.(*ast.Ident); ok {
			// Check if we know the type of the base object
			if info, ok := inferrer.GetType(ident.Name); ok && info.TypeName != "" {
				// If we have type info, trust the field name heuristic
				return r.looksLikeTimeField(fieldName)
			}
		}

		// Common time field names
		return r.looksLikeTimeField(fieldName)

	case *ast.CallExpr:
		return r.isTimeCall(e)
	}
	return false
}

func (r *TimeEqualRule) looksLikeTimeVar(name string) bool {
	// Only use specific time variable names to avoid false positives
	// Removed generic names like "t", "start", "end" which are commonly used for other types
	timeVarNames := map[string]bool{
		"timestamp":  true,
		"createdAt":  true,
		"updatedAt":  true,
		"expiresAt":  true,
		"startTime":  true,
		"endTime":    true,
		"deadline":   true,
		"parsedTime": true,
	}
	return timeVarNames[name]
}

func (r *TimeEqualRule) looksLikeTimeField(name string) bool {
	// Only include fields that are typically time.Time (not *time.Time pointers)
	// Fields like DeletedAt, ExpiresAt are typically pointers and compared with nil
	timeFieldNames := map[string]bool{
		"Time":      true,
		"CreatedAt": true,
		"UpdatedAt": true,
		"StartTime": true,
		"EndTime":   true,
		"Timestamp": true,
		"Date":      true,
		"Birthday":  true,
	}
	return timeFieldNames[name]
}

func (r *TimeEqualRule) isTimeCall(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}

	if ident, ok := sel.X.(*ast.Ident); ok {
		if ident.Name == "time" {
			switch sel.Sel.Name {
			case "Now", "Parse", "ParseInLocation", "Date", "Unix", "UnixMilli", "UnixMicro":
				return true
			}
		}
	}
	return false
}

func (r *TimeEqualRule) getLineFromNode(ctx *core.FileContext, node ast.Node) int {
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
