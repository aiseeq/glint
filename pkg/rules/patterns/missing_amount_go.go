package patterns

import (
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
)

// analyzeGoMissingAmounts reports the Go forms of a missing amount turned
// into zero: a decimal parser that answers empty or unreadable text with
// decimal.Zero applied to money fields, and a nil *decimal replaced with
// decimal.Zero.
func (r *MissingAmountCoercedToZeroRule) analyzeGoMissingAmounts(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || ctx.IsTestFile() {
		return nil
	}
	parsers := zeroAnsweringDecimalParsers(ctx.GoAST)
	var violations []*core.Violation
	report := func(node ast.Node, message, suggestion string) {
		line := ctx.LineFor(node)
		v := r.CreateViolation(ctx.RelPath, line, message)
		v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
		v.WithSuggestion(suggestion)
		violations = append(violations, v)
	}
	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CallExpr:
			name := callName(node)
			if !parsers[name] || len(node.Args) != 1 {
				return true
			}
			if field, ok := node.Args[0].(*ast.SelectorExpr); ok && hasWordFrom(field.Sel.Name, moneyWords) {
				report(node, name+" answers an empty or unreadable "+field.Sel.Name+" with zero - a missing amount goes on as an amount of 0",
					"Keep the amount missing (a nullable value) or refuse the payload without it")
			}
		case *ast.BlockStmt:
			for i := 0; i+1 < len(node.List); i++ {
				if name := zeroPresetOverNilAmount(node.List[i], node.List[i+1]); name != "" {
					report(node.List[i], "Missing "+name+" replaced with decimal.Zero - the receiver reads 0 for an amount nobody knows",
						"Send the amount as absent (null) or refuse to build the message without it")
				}
			}
		}
		return true
	})
	return violations
}

// zeroAnsweringDecimalParsers returns the functions of the file that take a
// string and answer an empty or unreadable one with decimal.Zero and no
// error.
func zeroAnsweringDecimalParsers(file *ast.File) map[string]bool {
	parsers := make(map[string]bool)
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || fn.Recv != nil || fn.Type.Results == nil || len(fn.Type.Results.List) == 0 {
			continue
		}
		if !isDecimalType(fn.Type.Results.List[0].Type) || !hasStringParam(fn) {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			ifStmt, ok := n.(*ast.IfStmt)
			if !ok || errNilCheckName(ifStmt.Cond) == "" && !comparesToEmptyString(ifStmt.Cond) {
				return true
			}
			for _, stmt := range ifStmt.Body.List {
				if ret, ok := stmt.(*ast.ReturnStmt); ok && returnsZeroDecimalWithoutError(ret) {
					parsers[fn.Name.Name] = true
				}
			}
			return true
		})
	}
	return parsers
}

func isDecimalType(expr ast.Expr) bool {
	sel, ok := expr.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "Decimal" && isIdentNamed(sel.X, "decimal")
}

func isDecimalZeroSyntax(expr ast.Expr) bool {
	sel, ok := expr.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "Zero" && isIdentNamed(sel.X, "decimal")
}

func hasStringParam(fn *ast.FuncDecl) bool {
	for _, field := range fn.Type.Params.List {
		if isIdentNamed(field.Type, "string") {
			return true
		}
	}
	return false
}

// comparesToEmptyString reports `s == ""`.
func comparesToEmptyString(cond ast.Expr) bool {
	bin, ok := cond.(*ast.BinaryExpr)
	if !ok || bin.Op != token.EQL {
		return false
	}
	lit, ok := bin.Y.(*ast.BasicLit)
	return ok && lit.Kind == token.STRING && lit.Value == `""`
}

// returnsZeroDecimalWithoutError reports `return decimal.Zero` and
// `return decimal.Zero, nil`.
func returnsZeroDecimalWithoutError(ret *ast.ReturnStmt) bool {
	switch len(ret.Results) {
	case 1:
		return isDecimalZeroSyntax(ret.Results[0])
	case 2:
		return isDecimalZeroSyntax(ret.Results[0]) && isNilIdent(ret.Results[1])
	}
	return false
}

// zeroPresetOverNilAmount returns the money variable of
//
//	payout := decimal.Zero
//	if desired.payoutAmount != nil { payout = *desired.payoutAmount }
func zeroPresetOverNilAmount(first, second ast.Stmt) string {
	preset, ok := first.(*ast.AssignStmt)
	if !ok || preset.Tok != token.DEFINE || len(preset.Lhs) != 1 || len(preset.Rhs) != 1 || !isDecimalZeroSyntax(preset.Rhs[0]) {
		return ""
	}
	target, ok := preset.Lhs[0].(*ast.Ident)
	if !ok {
		return ""
	}
	ifStmt, ok := second.(*ast.IfStmt)
	if !ok || ifStmt.Else != nil || len(ifStmt.Body.List) != 1 {
		return ""
	}
	cond, ok := ifStmt.Cond.(*ast.BinaryExpr)
	if !ok || cond.Op != token.NEQ || !isNilIdent(cond.Y) {
		return ""
	}
	assign, ok := ifStmt.Body.List[0].(*ast.AssignStmt)
	if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 || !isIdentNamed(assign.Lhs[0], target.Name) {
		return ""
	}
	star, ok := assign.Rhs[0].(*ast.StarExpr)
	source := types.ExprString(cond.X)
	if !ok || types.ExprString(star.X) != source {
		return ""
	}
	last := source[strings.LastIndex(source, ".")+1:]
	if !hasWordFrom(target.Name, moneyWords) && !hasWordFrom(last, moneyWords) {
		return ""
	}
	return target.Name
}
