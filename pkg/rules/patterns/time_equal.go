package patterns

import (
	"go/ast"
	"go/token"
	"go/types"

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

// AnalyzeFile checks one file without type information: the fallback the
// project analysis uses for files no type-checked package covers.
func (r *TimeEqualRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	return r.analyze(ctx, nil)
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *TimeEqualRule) RequiresSSA() bool { return false }

// AnalyzeGoProject checks every file; operands declared anywhere in the
// project are judged by their declared type.
func (r *TimeEqualRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	return rules.AnalyzeGoFiles(ctx, r.Name(), r.analyze)
}

// analyze checks for time.Time == comparisons. info is nil for a file
// without type information: then only operands whose type the file itself
// declares are judged, and an operand it does not declare is not guessed
// from its name.
func (r *TimeEqualRule) analyze(ctx *core.FileContext, info *types.Info) []*core.Violation {
	if !ctx.IsGoFile() || ctx.IsTestFile() {
		return nil
	}

	if ctx.GoAST == nil {
		return nil
	}

	// Without types a file that does not import time has no time.Time it
	// could know about.
	if info == nil && !r.hasTimeImport(ctx.GoAST) {
		return nil
	}

	// Build file-level type information for globals and struct fields. Function-local
	// inference below takes precedence to avoid same-name variables leaking across
	// functions in this file-level AST pass.
	var fileInferrer *TypeInferrer
	if info == nil {
		fileInferrer = NewTypeInferrer(ctx.GoAST)
	}

	var violations []*core.Violation

	for _, decl := range ctx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}

		isTime := func(expr ast.Expr) bool { return isTimeTimeType(info.TypeOf(expr)) }
		if info == nil {
			localInferrer := NewTypeInferrerFromNode(fn)
			isTime = func(expr ast.Expr) bool { return r.isTimeExpr(expr, localInferrer, fileInferrer) }
		}
		violations = append(violations, r.analyzeComparisons(ctx, fn.Body, isTime)...)
	}

	return violations
}

// isTimeTimeType reports whether t is time.Time itself - not a pointer to it.
func isTimeTimeType(t types.Type) bool {
	if t == nil {
		return false
	}
	named, ok := types.Unalias(t).(*types.Named)
	if !ok || named.Obj().Pkg() == nil {
		return false
	}
	return named.Obj().Pkg().Path() == "time" && named.Obj().Name() == "Time"
}

func (r *TimeEqualRule) analyzeComparisons(ctx *core.FileContext, node ast.Node, isTime func(ast.Expr) bool) []*core.Violation {
	var violations []*core.Violation

	// Find == and != comparisons involving time variables
	ast.Inspect(node, func(n ast.Node) bool {
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

		// Compare only confirmed time expressions on both sides. A single heuristic
		// match creates false positives for sentinel comparisons such as err == io.EOF.
		if !isTime(binary.X) || !isTime(binary.Y) {
			return true
		}

		line := ctx.LineFor(binary)
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

// isTimeExpr judges an operand by what the file declares about it. A name or
// field the file does not declare is unknown and is not a time.Time: guessing
// from names like CreatedAt flagged int64 fields, and the .Equal() fix for
// them does not compile.
func (r *TimeEqualRule) isTimeExpr(expr ast.Expr, localInferrer, fileInferrer *TypeInferrer) bool {
	switch e := expr.(type) {
	case *ast.Ident:
		info, ok := getScopedType(e.Name, localInferrer, fileInferrer)
		return ok && info.IsTime

	case *ast.SelectorExpr:
		// Field access like obj.CreatedAt: struct fields are collected
		// file-wide, so a field this file declares has a known type.
		info, ok := getScopedType(e.Sel.Name, localInferrer, fileInferrer)
		return ok && info.IsTime

	case *ast.CallExpr:
		return r.isTimeCall(e)
	}
	return false
}

func getScopedType(name string, localInferrer, fileInferrer *TypeInferrer) (TypeInfo, bool) {
	if localInferrer != nil {
		if info, ok := localInferrer.GetType(name); ok {
			return info, true
		}
	}
	if fileInferrer != nil {
		return fileInferrer.GetType(name)
	}
	return TypeInfo{}, false
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
