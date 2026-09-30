package patterns

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewStringConcatRule())
}

// StringConcatRule detects string concatenation in loops. A loop over a
// handful of entries fixed in the source - an array, a literal, a package
// table nothing reassigns - is left alone: it concatenates a known small
// number of times, and the quadratic copying strings.Builder avoids is not
// there.
type StringConcatRule struct {
	*rules.BaseRule
}

// NewStringConcatRule creates the rule
func NewStringConcatRule() *StringConcatRule {
	return &StringConcatRule{
		BaseRule: rules.NewBaseRule(
			"string-concat",
			"patterns",
			"Detects string concatenation in loops (use strings.Builder)",
			core.SeverityMedium,
		),
	}
}

// AnalyzeFile checks one file without type information: only concatenations
// with a string literal are known to be string concatenations.
func (r *StringConcatRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	return r.analyze(ctx, nil, nil)
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *StringConcatRule) RequiresSSA() bool { return false }

// AnalyzeGoProject checks every file; with type information the accumulator
// is judged by its type.
func (r *StringConcatRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	fixedTables, err := core.SharedLoad(ctx, fixedTablesKey{}, func() (map[*types.Info]map[types.Object]bool, error) {
		fixedTables := make(map[*types.Info]map[types.Object]bool)
		for _, pkg := range ctx.Packages {
			if pkg != nil && pkg.Package != nil && pkg.Package.TypesInfo != nil {
				fixedTables[pkg.Package.TypesInfo] = smallFixedTables(pkg.Package.Syntax, pkg.Package.TypesInfo)
			}
		}
		return fixedTables, nil
	})
	if err != nil {
		return nil, err
	}
	return rules.AnalyzeGoFiles(ctx, r.Name(), func(fileCtx *core.FileContext, info *types.Info) []*core.Violation {
		return r.analyze(fileCtx, info, fixedTables[info])
	})
}

// fixedTablesKey caches the small fixed tables of every loaded package once
// per module load.
type fixedTablesKey struct{}

// maxFixedLoop is the most iterations a loop fixed in the source may have for
// its concatenations to go unreported.
const maxFixedLoop = 16

// smallFixedTables returns the package-level variables of the package whose
// initializer is a composite literal of at most maxFixedLoop entries and that
// nothing in the package reassigns or takes the address of. Only unexported
// ones: another package may grow an exported table.
func smallFixedTables(files []*ast.File, info *types.Info) map[types.Object]bool {
	tables := make(map[types.Object]bool)
	for _, file := range files {
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.VAR {
				continue
			}
			for _, spec := range gen.Specs {
				value, ok := spec.(*ast.ValueSpec)
				if !ok || len(value.Values) != len(value.Names) {
					continue
				}
				for i, name := range value.Names {
					literal, ok := value.Values[i].(*ast.CompositeLit)
					if !ok || name.IsExported() || len(literal.Elts) > maxFixedLoop {
						continue
					}
					if obj := info.Defs[name]; obj != nil {
						tables[obj] = true
					}
				}
			}
		}
	}
	if len(tables) == 0 {
		return tables
	}
	for _, file := range files {
		ast.Inspect(file, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.AssignStmt:
				for _, lhs := range node.Lhs {
					if ident, ok := ast.Unparen(lhs).(*ast.Ident); ok {
						delete(tables, info.Uses[ident])
					}
				}
			case *ast.UnaryExpr:
				if ident, ok := ast.Unparen(node.X).(*ast.Ident); ok && node.Op == token.AND {
					delete(tables, info.Uses[ident])
				}
			}
			return true
		})
	}
	return tables
}

// rangesOverFixedSmall reports whether the range walks a collection whose
// size the source fixes at no more than maxFixedLoop entries: an array, a
// composite literal, a constant count, or one of the fixed package tables.
func rangesOverFixedSmall(info *types.Info, fixedTables map[types.Object]bool, expr ast.Expr) bool {
	if info == nil {
		return false
	}
	expr = ast.Unparen(expr)
	if literal, ok := expr.(*ast.CompositeLit); ok {
		return len(literal.Elts) <= maxFixedLoop
	}
	if ident, ok := expr.(*ast.Ident); ok && fixedTables[info.Uses[ident]] {
		return true
	}
	if tv, ok := info.Types[expr]; ok && tv.Value != nil && tv.Value.Kind() == constant.Int {
		count, exact := constant.Int64Val(tv.Value)
		return exact && count <= maxFixedLoop
	}
	collection := info.TypeOf(expr)
	if collection == nil {
		return false
	}
	if pointer, ok := collection.Underlying().(*types.Pointer); ok {
		collection = pointer.Elem()
	}
	array, ok := collection.Underlying().(*types.Array)
	return ok && array.Len() <= maxFixedLoop
}

// analyze checks for string concatenation in loops. info is nil for a file
// without type information; fixedTables are the package tables of fixed small
// size.
func (r *StringConcatRule) analyze(ctx *core.FileContext, info *types.Info, fixedTables map[types.Object]bool) []*core.Violation {
	if !ctx.IsGoFile() || ctx.IsTestFile() {
		return nil
	}

	if ctx.GoAST == nil {
		return nil
	}

	var violations []*core.Violation

	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		// Check for loops
		switch loop := n.(type) {
		case *ast.ForStmt:
			r.checkLoop(ctx, info, loop.Body, &violations)
		case *ast.RangeStmt:
			if !rangesOverFixedSmall(info, fixedTables, loop.X) {
				r.checkLoop(ctx, info, loop.Body, &violations)
			}
		}

		return true
	})

	return violations
}

func (r *StringConcatRule) checkLoop(ctx *core.FileContext, info *types.Info, body *ast.BlockStmt, violations *[]*core.Violation) {
	if body == nil {
		return
	}

	ast.Inspect(body, func(n ast.Node) bool {
		// Skip nested function literals
		if _, ok := n.(*ast.FuncLit); ok {
			return false
		}

		// Look for s += "..." or s = s + "..."
		assign, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}

		// Check for += with string
		if assign.Tok == token.ADD_ASSIGN {
			if len(assign.Lhs) == 1 && len(assign.Rhs) == 1 && r.isStringAccumulation(info, assign.Lhs[0], assign.Rhs[0]) {
				if !r.variableResetBefore(body, assign) {
					r.reportConcatViolation(ctx, assign, violations)
				}
			}
			return true
		}

		// Check for s = s + "..."
		if assign.Tok == token.ASSIGN && len(assign.Lhs) == 1 && len(assign.Rhs) == 1 {
			if r.isAssignPlusPattern(info, assign) {
				if !r.variableResetBefore(body, assign) {
					r.reportConcatViolation(ctx, assign, violations)
				}
			}
		}

		return true
	})
}

func (r *StringConcatRule) variableResetBefore(body *ast.BlockStmt, target *ast.AssignStmt) bool {
	targetIdent, ok := target.Lhs[0].(*ast.Ident)
	if !ok {
		return false
	}

	reset := false
	ast.Inspect(body, func(n ast.Node) bool {
		if n == nil {
			return false
		}
		block, ok := n.(*ast.BlockStmt)
		if !ok || block.Pos() > target.Pos() || block.End() < target.End() {
			return true
		}
		for _, stmt := range block.List {
			if stmt.End() >= target.Pos() {
				break
			}
			assign, ok := stmt.(*ast.AssignStmt)
			if !ok || (assign.Tok != token.DEFINE && assign.Tok != token.ASSIGN) {
				continue
			}
			for _, lhs := range assign.Lhs {
				if ident, ok := lhs.(*ast.Ident); ok && ident.Name == targetIdent.Name {
					reset = true
					return false
				}
			}
		}
		return !reset
	})
	return reset
}

// isAssignPlusPattern matches `s = s + x` on a string accumulator.
func (r *StringConcatRule) isAssignPlusPattern(info *types.Info, assign *ast.AssignStmt) bool {
	binary, ok := assign.Rhs[0].(*ast.BinaryExpr)
	if !ok || binary.Op != token.ADD {
		return false
	}
	if types.ExprString(assign.Lhs[0]) != types.ExprString(binary.X) {
		return false
	}
	if info != nil {
		return isStringKind(info.TypeOf(assign.Lhs[0]))
	}
	return isStringBasicLit(binary.Y)
}

func (r *StringConcatRule) reportConcatViolation(ctx *core.FileContext, assign *ast.AssignStmt, violations *[]*core.Violation) {
	line := ctx.LineFor(assign)
	v := r.CreateViolation(ctx.RelPath, line, "String concatenation in loop - use strings.Builder")
	v.WithCode(ctx.GetLine(line))
	v.WithSuggestion("Use var sb strings.Builder; sb.WriteString(...)")
	v.WithContext("pattern", "string_concat_loop")
	*violations = append(*violations, v)
}

// isStringAccumulation reports `lhs += rhs` on a string. With type
// information the type of the accumulator decides; without it only a string
// literal on the right says the operands are strings.
func (r *StringConcatRule) isStringAccumulation(info *types.Info, lhs, rhs ast.Expr) bool {
	if info != nil {
		return isStringKind(info.TypeOf(lhs))
	}
	if isStringBasicLit(rhs) {
		return true
	}
	binary, ok := rhs.(*ast.BinaryExpr)
	return ok && binary.Op == token.ADD && (isStringBasicLit(binary.X) || isStringBasicLit(binary.Y))
}

func isStringBasicLit(expr ast.Expr) bool {
	lit, ok := expr.(*ast.BasicLit)
	return ok && lit.Kind == token.STRING
}

// isStringKind reports a string type, named string types included.
func isStringKind(t types.Type) bool {
	if t == nil {
		return false
	}
	basic, ok := t.Underlying().(*types.Basic)
	return ok && basic.Info()&types.IsString != 0
}
