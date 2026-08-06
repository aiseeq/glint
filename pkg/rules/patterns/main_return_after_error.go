package patterns

import (
	"go/ast"
	"go/token"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewMainReturnAfterErrorRule())
}

// MainReturnAfterErrorRule detects func main returning normally from an error
// branch:
//
//	func main() {
//	    if err := run(); err != nil {
//	        log.Printf("Error: %v", err)
//	        return // the process exits 0 — scripts and CI see success
//	    }
//	}
//
// A bare return in main ends the process with exit code 0, so every caller —
// shell scripts, CI, cron — treats the failed run as successful. The honest
// endings are os.Exit(1), log.Fatal or panic; those forms are not flagged.
//
// Родилось из ревью projectD 2026-08 (№27): шесть cmd-утилит логировали ошибку и
// выходили из main обычным return, отчитываясь кодом 0.
type MainReturnAfterErrorRule struct {
	*rules.BaseRule
}

// NewMainReturnAfterErrorRule creates the rule
func NewMainReturnAfterErrorRule() *MainReturnAfterErrorRule {
	return &MainReturnAfterErrorRule{
		BaseRule: rules.NewBaseRule(
			"main-return-after-error",
			"patterns",
			"Detects bare return in an error branch of func main — the process exits 0 and callers see success",
			core.SeverityHigh,
		),
	}
}

// AnalyzeFile checks func main of package main for returns from error branches
func (r *MainReturnAfterErrorRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.HasGoAST() || ctx.IsTestFile() {
		return nil
	}
	if ctx.GoAST.Name == nil || ctx.GoAST.Name.Name != "main" {
		return nil
	}

	var violations []*core.Violation
	seen := map[token.Pos]bool{}
	for _, decl := range ctx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv != nil || fn.Name.Name != "main" || fn.Body == nil {
			continue
		}
		forEachErrorBranch(fn.Body, func(branch *ast.BlockStmt) {
			for _, ret := range bareReturnsIn(branch) {
				if seen[ret.Pos()] {
					continue
				}
				seen[ret.Pos()] = true
				pos := ctx.PositionFor(ret)
				v := r.CreateViolation(ctx.RelPath, pos.Line,
					"func main returns after handling an error — the process exits 0 and scripts, CI and cron see a successful run")
				v.WithCode(strings.TrimSpace(ctx.GetLine(pos.Line)))
				v.WithSuggestion("End the error branch with os.Exit(1) (or log.Fatal) so failed runs report a non-zero exit code")
				violations = append(violations, v)
			}
		})
	}
	return violations
}

// forEachErrorBranch visits every block that executes when an error is
// non-nil: the body of `if err != nil` and the else of `if err == nil`.
// Nested function literals are pruned — their returns do not leave main.
func forEachErrorBranch(body *ast.BlockStmt, visit func(*ast.BlockStmt)) {
	ast.Inspect(body, func(n ast.Node) bool {
		if _, ok := n.(*ast.FuncLit); ok {
			return false
		}
		ifStmt, ok := n.(*ast.IfStmt)
		if !ok {
			return true
		}
		switch errCondOp(ifStmt.Cond) {
		case token.NEQ:
			visit(ifStmt.Body)
		case token.EQL:
			if elseBlock, ok := ifStmt.Else.(*ast.BlockStmt); ok {
				visit(elseBlock)
			}
		}
		return true
	})
}

// errCondOp classifies a condition as an error-nil comparison and returns its
// operator; token.ILLEGAL means the condition is not about an error. Файловое
// правило без типов, поэтому ошибку узнаём по имени идентификатора.
func errCondOp(cond ast.Expr) token.Token {
	binary, ok := cond.(*ast.BinaryExpr)
	if !ok || (binary.Op != token.NEQ && binary.Op != token.EQL) {
		return token.ILLEGAL
	}
	value, isNilCompare := binary.X, exprIsNil(binary.Y)
	if !isNilCompare {
		value, isNilCompare = binary.Y, exprIsNil(binary.X)
	}
	ident, isIdent := value.(*ast.Ident)
	if !isNilCompare || !isIdent || !strings.Contains(strings.ToLower(ident.Name), "err") {
		return token.ILLEGAL
	}
	return binary.Op
}

// exprIsNil reports whether the expression is the nil identifier.
func exprIsNil(expr ast.Expr) bool {
	ident, ok := expr.(*ast.Ident)
	return ok && ident.Name == "nil"
}

// bareReturnsIn collects the bare return statements of a branch, pruning
// nested function literals. Any such return ends main with exit code 0 no
// matter what else the branch contains.
func bareReturnsIn(branch *ast.BlockStmt) []*ast.ReturnStmt {
	var returns []*ast.ReturnStmt
	ast.Inspect(branch, func(n ast.Node) bool {
		if _, ok := n.(*ast.FuncLit); ok {
			return false
		}
		if ret, ok := n.(*ast.ReturnStmt); ok && len(ret.Results) == 0 {
			returns = append(returns, ret)
		}
		return true
	})
	return returns
}
