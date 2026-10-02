package patterns

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewValidatorFillsDefaultsOnUpdateRule())
}

// NewValidatorFillsDefaultsOnUpdateRule creates
// validator-fills-defaults-on-update: a validator that fills defaults into
// the zero fields of what it checks is right for a create, and wrong for an
// update - the field the operator cleared, or the client left out, comes
// back as the default:
//
//	func validateLimits(p *Portfolio) error {
//		if p.MaxShare == 0 { p.MaxShare = 30 }   // the update's 0 becomes 30
//		...
//	}
//	func (s *Service) UpdatePortfolio(p *Portfolio) error {
//		if err := validateLimits(p); err != nil { ... }
//
// Reported at the update's call of a validate*, check* or verify* function
// that assigns a literal or a constant to a field of its parameter when the
// field is zero.
func NewValidatorFillsDefaultsOnUpdateRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"validator-fills-defaults-on-update",
			"patterns",
			"Detects an Update* path calling a validator that fills defaults into zero fields — a field the update cleared or left out comes back as the default",
			core.SeverityMedium,
		),
		suggestion: "Fill defaults only on create (a separate applyDefaults), and let the validator reject the zero value on update",
	}
	r.check = func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		if !helpers.HasLeadingWord(fn.Name.Name, "Update") {
			return nil
		}
		var findings []funcFinding
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			decl, ok := scope.callee(call)
			if !ok || !validatorName(decl.decl.Name.Name) {
				return true
			}
			if field := filledDefault(decl); field != "" {
				findings = append(findings, funcFinding{node: call, message: "The update calls " + decl.decl.Name.Name + ", which fills a default into " + field + " when it is zero — a value the update cleared or left out comes back as the default"})
			}
			return true
		})
		return findings
	}
	return r
}

func validatorName(name string) bool {
	return helpers.HasLeadingWord(name, "validate") || helpers.HasLeadingWord(name, "check") || helpers.HasLeadingWord(name, "verify")
}

// filledDefault returns the field a function assigns a default to when it is
// zero (`if p.Limit == 0 { p.Limit = 30 }`), p a parameter; "" for none.
func filledDefault(decl typedFuncDecl) string {
	params := make(map[types.Object]bool)
	for _, field := range decl.decl.Type.Params.List {
		for _, name := range field.Names {
			params[decl.info.ObjectOf(name)] = true
		}
	}
	found := ""
	ast.Inspect(decl.decl.Body, func(n ast.Node) bool {
		check, ok := n.(*ast.IfStmt)
		if !ok || found != "" {
			return found == ""
		}
		cond, ok := ast.Unparen(check.Cond).(*ast.BinaryExpr)
		if !ok || cond.Op != token.EQL || !isZeroLiteral(cond.Y) {
			return true
		}
		field, ok := ast.Unparen(cond.X).(*ast.SelectorExpr)
		if !ok {
			return true
		}
		holder, ok := ast.Unparen(field.X).(*ast.Ident)
		if !ok || !params[decl.info.ObjectOf(holder)] {
			return true
		}
		for _, stmt := range check.Body.List {
			assign, ok := stmt.(*ast.AssignStmt)
			if !ok || assign.Tok != token.ASSIGN || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
				continue
			}
			if types.ExprString(assign.Lhs[0]) == types.ExprString(field) && constantValue(decl.info, assign.Rhs[0]) {
				found = types.ExprString(field)
			}
		}
		return true
	})
	return found
}

// constantValue reports a literal or a named constant.
func constantValue(info *types.Info, expr ast.Expr) bool {
	tv, ok := info.Types[expr]
	return ok && tv.Value != nil
}
