package patterns

import (
	"go/ast"
	"go/token"
	"go/types"
	"slices"
	"strings"

	"github.com/aiseeq/glint/pkg/rules/helpers"
)

// zeroPlaceholderWords name a money metric a calculation is expected to fill.
var zeroPlaceholderWords = append(slices.Clone(sqlMetricWords),
	"liability", "liabilities", "debt", "debts", "cost", "costs", "total", "tax", "taxes",
	"commission", "commissions", "spread", "nav", "gav", "loss", "losses", "discount", "rebate", "charge", "charges")

// zeroMetricPlaceholders returns the locals of the file's functions that are
// defined as a zero (0, T(0), a call of a *Zero* constructor, pkg.Zero,
// NewFromInt(0)), named as a money metric, never assigned again nor taken
// by address, and used as an operand of arithmetic (+, -, *, / or an
// Add/Sub/Mul/Div method).
func zeroMetricPlaceholders(file *ast.File, info *types.Info) []*ast.Ident {
	var found []*ast.Ident
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		candidates := zeroMetricLocals(fn.Body)
		if len(candidates) == 0 {
			continue
		}
		reassigned, inArithmetic := zeroLocalUses(fn.Body, candidates, info)
		for name, def := range candidates {
			if inArithmetic[name] && !reassigned[name] {
				found = append(found, def)
			}
		}
	}
	slices.SortFunc(found, func(a, b *ast.Ident) int { return int(a.Pos() - b.Pos()) })
	return found
}

// zeroMetricLocals returns the locals of body defined as a zero and named
// as a money metric.
func zeroMetricLocals(body *ast.BlockStmt) map[string]*ast.Ident {
	candidates := make(map[string]*ast.Ident)
	ast.Inspect(body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || assign.Tok != token.DEFINE || len(assign.Lhs) != len(assign.Rhs) {
			return true
		}
		for i, lhs := range assign.Lhs {
			id, ok := lhs.(*ast.Ident)
			if ok && zeroValueExpr(assign.Rhs[i]) && metricPlaceholderName(id.Name) {
				candidates[id.Name] = id
			}
		}
		return true
	})
	return candidates
}

// zeroLocalUses reports, by name, the candidates assigned again or taken by
// address, and the ones used as an operand of arithmetic.
func zeroLocalUses(body *ast.BlockStmt, candidates map[string]*ast.Ident, info *types.Info) (reassigned, inArithmetic map[string]bool) {
	same := func(expr ast.Expr, def *ast.Ident) bool {
		id, ok := ast.Unparen(expr).(*ast.Ident)
		if !ok || id.Name != def.Name {
			return false
		}
		if info == nil {
			return true
		}
		obj := info.Uses[id]
		return obj == nil || obj == info.Defs[def]
	}
	reassigned = make(map[string]bool)
	inArithmetic = make(map[string]bool)
	ast.Inspect(body, func(n ast.Node) bool {
		for name, def := range candidates {
			if zeroLocalWritten(n, def, same) {
				reassigned[name] = true
			}
			if zeroLocalInArithmetic(n, def, same) {
				inArithmetic[name] = true
			}
		}
		return true
	})
	return reassigned, inArithmetic
}

// zeroLocalWritten reports a node that assigns def again or takes its address.
func zeroLocalWritten(n ast.Node, def *ast.Ident, same func(ast.Expr, *ast.Ident) bool) bool {
	switch node := n.(type) {
	case *ast.AssignStmt:
		return slices.ContainsFunc(node.Lhs, func(lhs ast.Expr) bool { return lhs != ast.Expr(def) && same(lhs, def) })
	case *ast.IncDecStmt:
		return same(node.X, def)
	case *ast.UnaryExpr:
		return node.Op == token.AND && same(node.X, def)
	}
	return false
}

// zeroLocalInArithmetic reports a node that uses def as an operand of +, -,
// *, / or of an Add/Sub/Mul/Div method.
func zeroLocalInArithmetic(n ast.Node, def *ast.Ident, same func(ast.Expr, *ast.Ident) bool) bool {
	switch node := n.(type) {
	case *ast.BinaryExpr:
		switch node.Op {
		case token.ADD, token.SUB, token.MUL, token.QUO:
			return same(node.X, def) || same(node.Y, def)
		}
	case *ast.CallExpr:
		sel, ok := node.Fun.(*ast.SelectorExpr)
		if !ok || !slices.Contains([]string{"Add", "Sub", "Mul", "Div"}, sel.Sel.Name) {
			return false
		}
		return same(sel.X, def) || slices.ContainsFunc(node.Args, func(arg ast.Expr) bool { return same(arg, def) })
	}
	return false
}

// zeroValueExpr reports an expression that is a zero amount by construction.
func zeroValueExpr(expr ast.Expr) bool {
	switch e := ast.Unparen(expr).(type) {
	case *ast.BasicLit:
		return (e.Kind == token.INT || e.Kind == token.FLOAT) && strings.Trim(e.Value, "0._") == ""
	case *ast.SelectorExpr:
		return e.Sel.Name == "Zero"
	case *ast.CallExpr:
		name := ""
		switch fun := e.Fun.(type) {
		case *ast.Ident:
			name = fun.Name
		case *ast.SelectorExpr:
			name = fun.Sel.Name
		}
		if len(e.Args) == 0 {
			return strings.Contains(name, "Zero")
		}
		// A conversion int64(0), or NewFromInt(0) / NewFromFloat(0) / New(0, exp).
		return (len(e.Args) == 1 || strings.HasPrefix(name, "New")) && zeroValueExpr(e.Args[0]) && !strings.Contains(name, "Zero")
	}
	return false
}

func metricPlaceholderName(name string) bool {
	return slices.ContainsFunc(helpers.IdentifierWords(strings.ToLower(name)), func(w string) bool { return slices.Contains(zeroPlaceholderWords, w) }) ||
		slices.ContainsFunc(helpers.IdentifierWords(name), func(w string) bool { return slices.Contains(zeroPlaceholderWords, strings.ToLower(w)) })
}
