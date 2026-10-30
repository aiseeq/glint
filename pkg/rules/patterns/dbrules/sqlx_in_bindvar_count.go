package dbrules

import (
	"go/ast"
	"go/constant"
	"go/types"
	"strconv"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
	"golang.org/x/tools/go/types/typeutil"
)

func init() { rules.Register(NewSQLXInBindvarCountRule()) }

// SQLXInBindvarCountRule detects sqlx.In calls whose query has a different
// number of question mark bind variables than arguments.
type SQLXInBindvarCountRule struct{ *rules.BaseRule }

// NewSQLXInBindvarCountRule creates the rule.
func NewSQLXInBindvarCountRule() *SQLXInBindvarCountRule {
	return &SQLXInBindvarCountRule{BaseRule: rules.NewBaseRule(
		"sqlx-in-bindvar-count",
		"patterns",
		"Detects sqlx.In calls with a different number of question mark bind variables than arguments — sqlx.In refuses every call",
		core.SeverityHigh,
	)}
}

// AnalyzeFile is a no-op: identifying sqlx.In requires type information.
func (r *SQLXInBindvarCountRule) AnalyzeFile(_ *core.FileContext) []*core.Violation { return nil }

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *SQLXInBindvarCountRule) RequiresSSA() bool { return false }

// AnalyzeGoProject checks sqlx.In calls with static query strings.
func (r *SQLXInBindvarCountRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(file *core.FileContext, info *types.Info) []*core.Violation {
		staticVars := sqlxInStaticVariables(file.GoAST, info)
		var violations []*core.Violation
		ast.Inspect(file.GoAST, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 || call.Ellipsis.IsValid() {
				return true
			}
			fn, ok := typeutil.Callee(info, call).(*types.Func)
			if !ok || fn.Name() != "In" || fn.Pkg() == nil || fn.Pkg().Path() != patternkit.SqlxPath {
				return true
			}
			query, ok := sqlxInStaticString(call.Args[0], info, staticVars, make(map[types.Object]bool))
			if !ok {
				return true
			}
			bindvars, args := strings.Count(query, "?"), len(call.Args)-1
			if bindvars == args {
				return true
			}
			line := file.LineFor(call)
			if file.IsSuppressed(line, r.Name()) {
				return true
			}
			v := r.CreateViolation(file.RelPath, line,
				"sqlx.In query has "+itoa(bindvars)+" ? bind variables and "+itoa(args)+" arguments — In refuses every call with a bind variable count mismatch")
			v.WithCode(strings.TrimSpace(file.GetLine(line)))
			v.WithSuggestion("Pass all values to sqlx.In; appending arguments after In returns is too late")
			violations = append(violations, v)
			return true
		})
		return violations
	})
}

// sqlxInStaticVariables records local string variables with one statically
// known initializer. Multiple assignments make a variable dynamic.
func sqlxInStaticVariables(file *ast.File, info *types.Info) map[types.Object]ast.Expr {
	vars := make(map[types.Object]ast.Expr)
	ambiguous := make(map[types.Object]bool)
	set := func(id *ast.Ident, value ast.Expr) {
		obj := info.ObjectOf(id)
		if obj == nil || !isStringType(obj.Type()) {
			return
		}
		if _, exists := vars[obj]; exists {
			ambiguous[obj] = true
			delete(vars, obj)
			return
		}
		if !ambiguous[obj] {
			vars[obj] = value
		}
	}
	ast.Inspect(file, func(node ast.Node) bool {
		switch stmt := node.(type) {
		case *ast.ValueSpec:
			for i, name := range stmt.Names {
				if i < len(stmt.Values) {
					set(name, stmt.Values[i])
				}
			}
		case *ast.AssignStmt:
			if len(stmt.Lhs) == len(stmt.Rhs) {
				for i, lhs := range stmt.Lhs {
					if id, ok := lhs.(*ast.Ident); ok {
						set(id, stmt.Rhs[i])
					}
				}
			}
		}
		return true
	})
	return vars
}

func isStringType(t types.Type) bool {
	basic, ok := t.Underlying().(*types.Basic)
	return ok && basic.Kind() == types.String
}

func sqlxInStaticString(expr ast.Expr, info *types.Info, vars map[types.Object]ast.Expr, resolving map[types.Object]bool) (string, bool) {
	switch e := expr.(type) {
	case *ast.BasicLit:
		if tv, ok := info.Types[e]; ok && tv.Value != nil && tv.Value.Kind() == constant.String {
			return constant.StringVal(tv.Value), true
		}
	case *ast.ParenExpr:
		return sqlxInStaticString(e.X, info, vars, resolving)
	case *ast.BinaryExpr:
		if e.Op.String() == "+" {
			left, lok := sqlxInStaticString(e.X, info, vars, resolving)
			right, rok := sqlxInStaticString(e.Y, info, vars, resolving)
			return left + right, lok && rok
		}
	case *ast.Ident:
		obj := info.ObjectOf(e)
		if obj == nil {
			return "", false
		}
		if c, ok := obj.(*types.Const); ok && c.Val().Kind() == constant.String {
			return constant.StringVal(c.Val()), true
		}
		value, ok := vars[obj]
		if !ok || resolving[obj] {
			return "", false
		}
		resolving[obj] = true
		result, known := sqlxInStaticString(value, info, vars, resolving)
		delete(resolving, obj)
		return result, known
	}
	return "", false
}

func itoa(n int) string {
	return strconv.Itoa(n)
}
