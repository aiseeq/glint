package patterns

import (
	"go/ast"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewConstructorNilReturnRule())
}

// ConstructorNilReturnRule detects constructors (New*) without an error
// result that can return nil:
//
//	func NewWalletRepository(userRepo interface{}) WalletRepository {
//	    repo, ok := userRepo.(*UserRepository)
//	    if !ok {
//	        return nil // callers silently receive a nil dependency
//	    }
//	    ...
//	}
//
// Callers rarely nil-check constructor results, so the failure surfaces much
// later as a panic far from its cause. CLAUDE.md: initialization failures
// must be explicit — change the signature to (T, error).
//
// Scope is kept narrow for precision: plain functions named New* with a
// single non-error result. Comma-ok contracts (T, bool), methods on
// factories, and closures are out of scope.
type ConstructorNilReturnRule struct {
	*rules.BaseRule
}

// NewConstructorNilReturnRule creates the rule
func NewConstructorNilReturnRule() *ConstructorNilReturnRule {
	return &ConstructorNilReturnRule{
		BaseRule: rules.NewBaseRule(
			"constructor-nil-return",
			"patterns",
			"Detects New* constructors without error result that can return nil",
			core.SeverityHigh,
		),
	}
}

// AnalyzeFile checks Go constructors for silent nil returns
func (r *ConstructorNilReturnRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.HasGoAST() || ctx.IsTestFile() {
		return nil
	}

	var violations []*core.Violation

	for _, decl := range ctx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || !isPlainConstructor(fn) || !hasSingleNonErrorResult(fn) {
			continue
		}

		forEachOwnStatement(fn.Body, func(stmt ast.Stmt) {
			ret, ok := stmt.(*ast.ReturnStmt)
			if !ok || len(ret.Results) != 1 || !isNilIdent(ret.Results[0]) {
				return
			}
			pos := ctx.PositionFor(ret)
			v := r.CreateViolation(ctx.RelPath, pos.Line,
				"Constructor "+fn.Name.Name+" returns nil instead of an error — callers silently receive a nil dependency")
			v.WithCode(ctx.GetLine(pos.Line))
			v.WithSuggestion("Change the signature to (" + fn.Name.Name + " result, error) and return an explicit initialization error")
			violations = append(violations, v)
		})
	}

	return violations
}

// isPlainConstructor reports whether fn is a plain function (no receiver)
// named New or New<Something> with a body.
func isPlainConstructor(fn *ast.FuncDecl) bool {
	if fn.Recv != nil || fn.Body == nil || fn.Name == nil {
		return false
	}
	name := fn.Name.Name
	if name == "New" {
		return true
	}
	if len(name) > 3 && name[:3] == "New" && name[3] >= 'A' && name[3] <= 'Z' {
		return true
	}
	return false
}

// hasSingleNonErrorResult reports whether the function returns exactly one
// value that is not error and not bool (comma-ok style contracts excluded).
func hasSingleNonErrorResult(fn *ast.FuncDecl) bool {
	results := fn.Type.Results
	if results == nil || len(results.List) != 1 || len(results.List[0].Names) > 1 {
		return false
	}
	if ident, ok := results.List[0].Type.(*ast.Ident); ok {
		if ident.Name == "error" || ident.Name == "bool" {
			return false
		}
	}
	return true
}
