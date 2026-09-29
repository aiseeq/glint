package patterns

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewReimplementedStdlibRule())
}

// ReimplementedStdlibRule detects small helpers that redo what the standard
// library already does:
//
//	func itoa(i int) string {          // strconv.Itoa
//	    s := ""
//	    for i > 0 { s = string(rune('0'+i%10)) + s; i /= 10 }
//	    return s
//	}
//
// The copy is not merely redundant: it is the version nobody tested. glint
// carried four such itoa helpers, and they all shared the same bug — a negative
// number came back as the empty string.
//
// The rule recognizes the shapes it can name with certainty: digit-by-digit
// integer formatting and parsing, a linear search for an element, absolute
// value, the smaller/larger of two values, and reversing a slice in place.
type ReimplementedStdlibRule struct {
	*rules.BaseRule
}

// NewReimplementedStdlibRule creates the rule
func NewReimplementedStdlibRule() *ReimplementedStdlibRule {
	return &ReimplementedStdlibRule{
		BaseRule: rules.NewBaseRule(
			"reimplemented-stdlib",
			"patterns",
			"Detects hand-written helpers that duplicate the standard library — the copy is the version nobody tested",
			core.SeverityMedium,
		),
	}
}

// AnalyzeFile checks one file without type information: the fallback the
// project analysis uses for files no type-checked package covers.
func (r *ReimplementedStdlibRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	return r.analyze(ctx, nil)
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *ReimplementedStdlibRule) RequiresSSA() bool { return false }

// AnalyzeGoProject checks every file; the collections and result types the
// shapes depend on are resolved wherever the project declares them.
func (r *ReimplementedStdlibRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	return rules.AnalyzeGoFiles(ctx, r.Name(), r.analyze)
}

// analyze checks every function declared in the file. info is nil for a file
// without type information.
func (r *ReimplementedStdlibRule) analyze(ctx *core.FileContext, info *types.Info) []*core.Violation {
	if !ctx.IsGoFile() || !ctx.HasGoAST() || ctx.IsTestFile() {
		return nil
	}

	operands := stdlibOperands{info: info, file: ctx.GoAST}
	var violations []*core.Violation
	for _, decl := range ctx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		replacement, ok := stdlibEquivalent(fn, operands)
		if !ok {
			continue
		}

		line := ctx.LineFor(fn)
		v := r.CreateViolation(ctx.RelPath, line,
			fmt.Sprintf("%s does by hand what %s already does — the hand-written copy is the one without tests behind it",
				fn.Name.Name, replacement))
		v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
		if wrapsOwnData(fn) {
			v.WithSuggestion(fmt.Sprintf("Replace the body of %s with a call to %s over its own list", fn.Name.Name, replacement))
		} else {
			v.WithSuggestion(fmt.Sprintf("Delete %s and call %s at its call sites", fn.Name.Name, replacement))
		}
		v.WithContext("pattern", "reimplemented_stdlib")
		v.WithContext("replacement", replacement)
		violations = append(violations, v)
	}

	return violations
}

// wrapsOwnData reports whether the helper searches a collection of its own
// rather than one handed to it: then the function is a named question about the
// package's data, and only its body should change.
func wrapsOwnData(fn *ast.FuncDecl) bool {
	params := make(map[string]bool)
	if fn.Type.Params != nil {
		for _, param := range fn.Type.Params.List {
			for _, name := range param.Names {
				params[name.Name] = true
			}
		}
	}

	ownData := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		rangeStmt, ok := n.(*ast.RangeStmt)
		if !ok {
			return true
		}
		if ident, ok := rangeStmt.X.(*ast.Ident); !ok || !params[ident.Name] {
			ownData = true
		}
		return false
	})
	return ownData
}

// stdlibOperands answers the type questions some shapes depend on. With type
// information the checker answers, wherever the type is declared. Without it
// only what the file itself declares is known, and an unknown type is not a
// slice: a map or a string declared in another file looked like one.
type stdlibOperands struct {
	info *types.Info
	file *ast.File
}

// rangesOverSlice reports whether target, ranged over in fn, is a slice or an
// array - the collections slices.Contains can search.
func (o stdlibOperands) rangesOverSlice(fn *ast.FuncDecl, target ast.Expr) bool {
	if o.info != nil {
		t := o.info.TypeOf(target)
		if t == nil {
			return false
		}
		switch u := t.Underlying().(type) {
		case *types.Slice, *types.Array:
			return true
		case *types.Pointer:
			_, isArray := u.Elem().Underlying().(*types.Array)
			return isArray
		}
		return false
	}

	ident, ok := target.(*ast.Ident)
	if !ok {
		return false
	}
	for _, fields := range []*ast.FieldList{fn.Recv, fn.Type.Params} {
		if fields == nil {
			continue
		}
		for _, field := range fields.List {
			for _, name := range field.Names {
				if name.Name == ident.Name {
					return o.declaresSliceType(field.Type)
				}
			}
		}
	}
	for _, decl := range o.file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.VAR {
			continue
		}
		for _, spec := range gen.Specs {
			valueSpec, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range valueSpec.Names {
				if name.Name != ident.Name {
					continue
				}
				if valueSpec.Type != nil {
					return o.declaresSliceType(valueSpec.Type)
				}
				if i < len(valueSpec.Values) {
					lit, ok := valueSpec.Values[i].(*ast.CompositeLit)
					return ok && o.declaresSliceType(lit.Type)
				}
				return false
			}
		}
	}
	return false
}

// declaresSliceType reports whether a type expression is a slice or array
// type, spelled out or named by a type this file declares.
func (o stdlibOperands) declaresSliceType(expr ast.Expr) bool {
	switch t := expr.(type) {
	case *ast.ArrayType:
		return true
	case *ast.Ident:
		for _, decl := range o.file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.TYPE {
				continue
			}
			for _, spec := range gen.Specs {
				typeSpec, ok := spec.(*ast.TypeSpec)
				if ok && typeSpec.Name.Name == t.Name {
					_, isArray := typeSpec.Type.(*ast.ArrayType)
					return isArray
				}
			}
		}
	}
	return false
}

// returnsFloat reports whether fn returns a single floating-point value.
func (o stdlibOperands) returnsFloat(fn *ast.FuncDecl) bool {
	if o.info == nil {
		return returnsBasicType(fn, "float64") || returnsBasicType(fn, "float32")
	}
	obj, ok := o.info.Defs[fn.Name].(*types.Func)
	if !ok {
		return false
	}
	results := obj.Signature().Results()
	if results.Len() != 1 {
		return false
	}
	basic, ok := results.At(0).Type().Underlying().(*types.Basic)
	return ok && basic.Info()&types.IsFloat != 0
}

// stdlibEquivalent names the standard-library call a function duplicates.
func stdlibEquivalent(fn *ast.FuncDecl, operands stdlibOperands) (string, bool) {
	switch {
	case formatsDigitByDigit(fn):
		return "strconv.Itoa", true
	case parsesDigitByDigit(fn):
		return "strconv.Atoi", true
	case searchesLinearly(fn, operands):
		return "slices.Contains", true
	case negatesWhenNegative(fn):
		// Go has no built-in abs: math.Abs covers floats, integer copies
		// should collapse into one shared helper.
		if operands.returnsFloat(fn) {
			return "math.Abs", true
		}
		return "a single shared abs helper (Go has no integer abs)", true
	case returnsSmallerOrLarger(fn):
		return "the built-in min/max", true
	case reversesInPlace(fn):
		return "slices.Reverse", true
	}
	return "", false
}

// formatsDigitByDigit recognizes building a decimal string from the last digit
// up: the body divides by ten, takes the remainder of ten, and turns the digit
// into a character. The last part is what separates printing a number from
// merely reading it digit by digit — spelling a number in words divides the same
// way but uses each digit as an index into a table of words, and replacing that
// with strconv.Itoa would be nonsense.
func formatsDigitByDigit(fn *ast.FuncDecl) bool {
	return returnsBasicType(fn, "string") && hasDecimalDigitLoop(fn.Body) &&
		rendersDigitAsCharacter(fn.Body) && !mentionsPackage(fn.Body, "strconv")
}

// rendersDigitAsCharacter reports whether the body turns a digit into its ASCII
// character, written either as `'0' + d` or as an index into a literal "0123…".
func rendersDigitAsCharacter(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if found {
			return false
		}
		switch node := n.(type) {
		case *ast.BinaryExpr:
			if node.Op != token.ADD {
				return true
			}
			for _, operand := range []ast.Expr{node.X, node.Y} {
				if lit, ok := operand.(*ast.BasicLit); ok && lit.Kind == token.CHAR && lit.Value == `'0'` {
					found = true
					return false
				}
			}
		case *ast.IndexExpr:
			lit, ok := node.X.(*ast.BasicLit)
			if ok && lit.Kind == token.STRING && strings.Contains(lit.Value, "0123456789") {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

// parsesDigitByDigit recognizes accumulating a number as `n = n*10 + digit`.
func parsesDigitByDigit(fn *ast.FuncDecl) bool {
	if !returnsBasicType(fn, "int") || mentionsPackage(fn.Body, "strconv") {
		return false
	}

	found := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if found {
			return false
		}
		binary, ok := n.(*ast.BinaryExpr)
		if !ok || binary.Op != token.ADD {
			return true
		}
		multiply, ok := binary.X.(*ast.BinaryExpr)
		if !ok || multiply.Op != token.MUL {
			return true
		}
		if isIntLiteral(multiply.Y, 10) && subtractsZeroRune(binary.Y) {
			found = true
			return false
		}
		return true
	})
	return found
}

// hasDecimalDigitLoop reports whether the body both divides by ten and takes a
// remainder of ten — the two halves of printing a number by hand.
func hasDecimalDigitLoop(body *ast.BlockStmt) bool {
	divides, remainders := false, false

	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.BinaryExpr:
			if isIntLiteral(node.Y, 10) {
				divides = divides || node.Op == token.QUO
				remainders = remainders || node.Op == token.REM
			}
		case *ast.AssignStmt:
			// `i /= 10` is an assignment, not a binary expression.
			if node.Tok == token.QUO_ASSIGN && len(node.Rhs) == 1 && isIntLiteral(node.Rhs[0], 10) {
				divides = true
			}
		}
		return true
	})

	return divides && remainders
}

// searchesLinearly recognizes ranging over a collection to answer "is it there".
func searchesLinearly(fn *ast.FuncDecl, operands stdlibOperands) bool {
	if !returnsBasicType(fn, "bool") || len(fn.Body.List) == 0 {
		return false
	}

	rangeStmt, ok := fn.Body.List[0].(*ast.RangeStmt)
	if !ok || rangeStmt.Value == nil {
		return false
	}
	// Ranging over a map or a string looks identical to ranging over a
	// slice, but slices.Contains cannot search either — the advice would be
	// unactionable.
	if !operands.rangesOverSlice(fn, rangeStmt.X) {
		return false
	}
	element, ok := rangeStmt.Value.(*ast.Ident)
	if !ok || !returnsLiteral(fn.Body.List[len(fn.Body.List)-1], "false") {
		return false
	}

	// The loop must do nothing but compare the element itself: a body that also
	// unpacks or converts is asking a question slices.Contains cannot answer.
	if len(rangeStmt.Body.List) != 1 {
		return false
	}
	ifStmt, ok := rangeStmt.Body.List[0].(*ast.IfStmt)
	if !ok || ifStmt.Else != nil || len(ifStmt.Body.List) != 1 {
		return false
	}
	comparison, ok := ifStmt.Cond.(*ast.BinaryExpr)
	if !ok || comparison.Op != token.EQL {
		return false
	}
	if !isIdent(comparison.X, element.Name) && !isIdent(comparison.Y, element.Name) {
		return false
	}
	return returnsLiteral(ifStmt.Body.List[0], "true")
}

// negatesWhenNegative recognizes `if x < 0 { return -x }; return x`.
func negatesWhenNegative(fn *ast.FuncDecl) bool {
	if len(fn.Body.List) != 2 {
		return false
	}
	ifStmt, ok := fn.Body.List[0].(*ast.IfStmt)
	if !ok || ifStmt.Else != nil || len(ifStmt.Body.List) != 1 {
		return false
	}
	comparison, ok := ifStmt.Cond.(*ast.BinaryExpr)
	if !ok || comparison.Op != token.LSS || !isIntLiteral(comparison.Y, 0) {
		return false
	}
	subject, ok := comparison.X.(*ast.Ident)
	if !ok {
		return false
	}

	negated, ok := returnedExpr(ifStmt.Body.List[0])
	if !ok {
		return false
	}
	unary, ok := negated.(*ast.UnaryExpr)
	if !ok || unary.Op != token.SUB || !isIdent(unary.X, subject.Name) {
		return false
	}
	plain, ok := returnedExpr(fn.Body.List[1])
	return ok && isIdent(plain, subject.Name)
}

// returnsSmallerOrLarger recognizes `if a < b { return a }; return b`.
func returnsSmallerOrLarger(fn *ast.FuncDecl) bool {
	if len(fn.Body.List) != 2 || countParams(fn) != 2 {
		return false
	}
	ifStmt, ok := fn.Body.List[0].(*ast.IfStmt)
	if !ok || ifStmt.Else != nil || len(ifStmt.Body.List) != 1 {
		return false
	}
	comparison, ok := ifStmt.Cond.(*ast.BinaryExpr)
	if !ok || !isOrderComparison(comparison.Op) {
		return false
	}
	left, leftOK := comparison.X.(*ast.Ident)
	right, rightOK := comparison.Y.(*ast.Ident)
	if !leftOK || !rightOK {
		return false
	}

	first, ok := returnedExpr(ifStmt.Body.List[0])
	if !ok {
		return false
	}
	second, ok := returnedExpr(fn.Body.List[1])
	if !ok {
		return false
	}
	return (isIdent(first, left.Name) && isIdent(second, right.Name)) ||
		(isIdent(first, right.Name) && isIdent(second, left.Name))
}

// reversesInPlace recognizes swapping elements from both ends towards the middle.
func reversesInPlace(fn *ast.FuncDecl) bool {
	swaps := false

	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if swaps {
			return false
		}
		forStmt, ok := n.(*ast.ForStmt)
		if !ok || forStmt.Post == nil {
			return true
		}
		post, ok := forStmt.Post.(*ast.AssignStmt)
		if !ok || len(post.Lhs) != 2 {
			return true
		}
		for _, stmt := range forStmt.Body.List {
			assign, ok := stmt.(*ast.AssignStmt)
			if !ok || len(assign.Lhs) != 2 || len(assign.Rhs) != 2 {
				continue
			}
			if isIndexExpr(assign.Lhs[0]) && isIndexExpr(assign.Lhs[1]) &&
				isIndexExpr(assign.Rhs[0]) && isIndexExpr(assign.Rhs[1]) {
				swaps = true
				return false
			}
		}
		return true
	})

	return swaps
}

func returnsBasicType(fn *ast.FuncDecl, name string) bool {
	if fn.Type.Results == nil || len(fn.Type.Results.List) != 1 {
		return false
	}
	ident, ok := fn.Type.Results.List[0].Type.(*ast.Ident)
	return ok && ident.Name == name
}

func countParams(fn *ast.FuncDecl) int {
	if fn.Type.Params == nil {
		return 0
	}
	count := 0
	for _, param := range fn.Type.Params.List {
		count += max(len(param.Names), 1)
	}
	return count
}

func returnedExpr(stmt ast.Stmt) (ast.Expr, bool) {
	ret, ok := stmt.(*ast.ReturnStmt)
	if !ok || len(ret.Results) != 1 {
		return nil, false
	}
	return ret.Results[0], true
}

func returnsLiteral(stmt ast.Stmt, literal string) bool {
	expr, ok := returnedExpr(stmt)
	return ok && isIdent(expr, literal)
}

// isIdent reports whether the expression is exactly the named identifier,
// parentheses aside. An empty name matches nothing: callers pass the name of a
// binding that may be absent (a blank range key, for one).
func isIdent(expr ast.Expr, name string) bool {
	if expr == nil || name == "" {
		return false
	}
	ident, ok := ast.Unparen(expr).(*ast.Ident)
	return ok && ident.Name == name
}

func isIntLiteral(expr ast.Expr, value int) bool {
	lit, ok := expr.(*ast.BasicLit)
	return ok && lit.Kind == token.INT && lit.Value == fmt.Sprint(value)
}

func isIndexExpr(expr ast.Expr) bool {
	_, ok := expr.(*ast.IndexExpr)
	return ok
}

func isOrderComparison(op token.Token) bool {
	return op == token.LSS || op == token.GTR || op == token.LEQ || op == token.GEQ
}

// subtractsZeroRune recognizes the digit extraction `c - '0'`, in any of the
// forms it is written in.
func subtractsZeroRune(expr ast.Expr) bool {
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		if found {
			return false
		}
		binary, ok := n.(*ast.BinaryExpr)
		if !ok || binary.Op != token.SUB {
			return true
		}
		lit, ok := binary.Y.(*ast.BasicLit)
		if ok && lit.Kind == token.CHAR && lit.Value == `'0'` {
			found = true
			return false
		}
		return true
	})
	return found
}

// mentionsPackage reports whether the body already calls into a package, which
// means the author knows about it and is doing something else.
func mentionsPackage(body *ast.BlockStmt, pkg string) bool {
	mentions := false
	ast.Inspect(body, func(n ast.Node) bool {
		if mentions {
			return false
		}
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if isIdent(sel.X, pkg) {
			mentions = true
			return false
		}
		return true
	})
	return mentions
}
