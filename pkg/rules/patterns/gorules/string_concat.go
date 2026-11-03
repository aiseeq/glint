package gorules

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
)

func init() {
	rules.Register(NewStringConcatRule())
}

// StringConcatRule detects string concatenation in loops. A loop over a
// handful of entries fixed in the source - an array, a literal, a package
// table nothing reassigns - is left alone: it concatenates a known small
// number of times, and the quadratic copying strings.Builder avoids is not
// there. Nor is a concatenation onto the element the loop picks by its own
// key (out[i].Message += s in for i := range out): each iteration grows a
// string of its own.
type StringConcatRule struct {
	rules.GoFileFindingRule
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
	return rules.AnalyzeGoRunFiles(ctx, r.Name(), func(fileCtx *core.FileContext, info *types.Info) []*core.Violation {
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
			r.checkLoop(ctx, info, loop.Body, forCounter(info, loop), &violations)
		case *ast.RangeStmt:
			if !rangesOverFixedSmall(info, fixedTables, loop.X) {
				r.checkLoop(ctx, info, loop.Body, rangeKey(info, loop), &violations)
			}
		}

		return true
	})

	return violations
}

// rangeKey returns the key a range statement declares when no two
// iterations share it: an index of a slice, array or string, a map key, an
// integer. A channel or an iterator may repeat its values; nil then, and for
// no key.
func rangeKey(info *types.Info, loop *ast.RangeStmt) *ast.Ident {
	key, ok := loop.Key.(*ast.Ident)
	if !ok || loop.Tok != token.DEFINE || info == nil {
		return nil
	}
	ranged := info.TypeOf(loop.X)
	if ranged == nil {
		return nil
	}
	if pointer, ok := ranged.Underlying().(*types.Pointer); ok {
		ranged = pointer.Elem()
	}
	switch t := ranged.Underlying().(type) {
	case *types.Slice, *types.Array, *types.Map:
		return key
	case *types.Basic:
		if t.Info()&(types.IsString|types.IsInteger) != 0 {
			return key
		}
	}
	return nil
}

// forCounter returns the variable a for statement declares in its init,
// bounds in its condition and steps in its post statement (for i := 0; i < n;
// i++), nil otherwise. A step of a constant zero is no step: continue comes
// back to the same i; with no condition a counter may wrap around.
func forCounter(info *types.Info, loop *ast.ForStmt) *ast.Ident {
	init, ok := loop.Init.(*ast.AssignStmt)
	if !ok || init.Tok != token.DEFINE || len(init.Lhs) != 1 || loop.Cond == nil {
		return nil
	}
	counter, ok := init.Lhs[0].(*ast.Ident)
	if !ok {
		return nil
	}
	var stepped ast.Expr
	switch post := loop.Post.(type) {
	case *ast.IncDecStmt:
		stepped = post.X
	case *ast.AssignStmt:
		if len(post.Lhs) == 1 && (post.Tok == token.ADD_ASSIGN || post.Tok == token.SUB_ASSIGN) && !constantZero(info, post.Rhs[0]) {
			stepped = post.Lhs[0]
		}
	}
	if ident, ok := stepped.(*ast.Ident); !ok || ident.Name != counter.Name {
		return nil
	}
	return counter
}

// elementOfIteration reports a target that is the element the loop picks by
// key: out[key], out[key].Message. A field behind a pointer is not the
// element's own: elements may share what it points to. Only types tell the
// key from a variable of its name.
func elementOfIteration(info *types.Info, target ast.Expr, key *ast.Ident) bool {
	if key == nil || info == nil {
		return false
	}
	expr := ast.Unparen(target)
	for selector, ok := expr.(*ast.SelectorExpr); ok; selector, ok = expr.(*ast.SelectorExpr) {
		if selection := info.Selections[selector]; selection == nil || selection.Indirect() {
			return false
		}
		expr = ast.Unparen(selector.X)
	}
	element, ok := expr.(*ast.IndexExpr)
	if !ok {
		return false
	}
	index, ok := ast.Unparen(element.Index).(*ast.Ident)
	return ok && sameVariable(info, index, key)
}

// keyMoves reports a body that moves the loop's key, or a part of it, or
// jumps back with goto: then an iteration may come back to an element.
func keyMoves(info *types.Info, body *ast.BlockStmt, key *ast.Ident) bool {
	moved := false
	ast.Inspect(body, func(n ast.Node) bool {
		var targets []ast.Expr
		switch node := n.(type) {
		case *ast.AssignStmt:
			targets = node.Lhs
		case *ast.RangeStmt:
			if node.Tok == token.ASSIGN {
				targets = []ast.Expr{node.Key, node.Value}
			}
		case *ast.IncDecStmt:
			targets = []ast.Expr{node.X}
		case *ast.UnaryExpr:
			if node.Op == token.AND {
				targets = []ast.Expr{node.X}
			}
		case *ast.SelectorExpr:
			// A method of a pointer receiver takes the key's address.
			if selection := info.Selections[node]; selection != nil && selection.Kind() == types.MethodVal {
				if method, ok := selection.Obj().(*types.Func); ok {
					if _, ok := method.Signature().Recv().Type().(*types.Pointer); ok {
						targets = []ast.Expr{node.X}
					}
				}
			}
		case *ast.BranchStmt:
			moved = moved || node.Tok == token.GOTO
		}
		for _, target := range targets {
			if ident, ok := variableOf(target).(*ast.Ident); ok && sameVariable(info, ident, key) {
				moved = true
			}
		}
		return !moved
	})
	return moved
}

// variableOf returns the variable an expression writes a part of: k of
// k.Field and k[1].
func variableOf(expr ast.Expr) ast.Expr {
	for {
		switch part := ast.Unparen(expr).(type) {
		case *ast.SelectorExpr:
			expr = part.X
		case *ast.IndexExpr:
			expr = part.X
		default:
			return part
		}
	}
}

// constantZero reports an expression of the constant value zero: a number,
// or an empty string.
func constantZero(info *types.Info, expr ast.Expr) bool {
	if info == nil {
		return false
	}
	value := info.Types[expr].Value
	if value == nil {
		return false
	}
	switch value.Kind() {
	case constant.Int, constant.Float:
		return constant.Sign(value) == 0
	case constant.String:
		return constant.StringVal(value) == ""
	}
	return false
}

// sameVariable reports an identifier that names the variable key declares.
func sameVariable(info *types.Info, ident, key *ast.Ident) bool {
	declared := info.Defs[key]
	return declared != nil && info.Uses[ident] == declared
}

func (r *StringConcatRule) checkLoop(ctx *core.FileContext, info *types.Info, body *ast.BlockStmt, key *ast.Ident, violations *[]*core.Violation) {
	if body == nil {
		return
	}

	// ownElement reports a concatenation onto the element the iteration picks
	// by its key: each iteration grows a string of its own. Whether the body
	// moves the key is read once per loop.
	var moves *bool
	ownElement := func(target ast.Expr) bool {
		if !elementOfIteration(info, target, key) {
			return false
		}
		if moves == nil {
			moved := keyMoves(info, body, key)
			moves = &moved
		}
		return !*moves
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
				if !ownElement(assign.Lhs[0]) && !r.variableResetBefore(body, assign) {
					r.reportConcatViolation(ctx, assign, violations)
				}
			}
			return true
		}

		// Check for s = s + "..."
		if assign.Tok == token.ASSIGN && len(assign.Lhs) == 1 && len(assign.Rhs) == 1 {
			if r.isAssignPlusPattern(info, assign) {
				if !ownElement(assign.Lhs[0]) && !r.variableResetBefore(body, assign) {
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
		return patternkit.IsStringType(info.TypeOf(assign.Lhs[0]))
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
		return patternkit.IsStringType(info.TypeOf(lhs))
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
