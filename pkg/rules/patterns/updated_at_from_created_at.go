package patterns

import (
	"go/ast"
	"go/types"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewUpdatedAtFromCreatedAtRule())
}

// UpdatedAtFromCreatedAtRule detects a composite literal that fills the
// update time from the creation time of the same object:
//
//	Resp{
//		CreatedAt: i.CreatedAt,
//		UpdatedAt: updatedAt(i), // func updatedAt(i *Inv) time.Time { return i.CreatedAt }
//	}
//
// The client reads that the record never changed since it was made: a
// status change or a payout is invisible to sorting and caching by the update
// time. The value is read directly or through a function of the file whose
// whole body returns the creation time.
type UpdatedAtFromCreatedAtRule struct {
	*rules.BaseRule
}

// NewUpdatedAtFromCreatedAtRule creates the rule
func NewUpdatedAtFromCreatedAtRule() *UpdatedAtFromCreatedAtRule {
	return &UpdatedAtFromCreatedAtRule{BaseRule: rules.NewBaseRule(
		"updated-at-from-created-at",
		"patterns",
		"Detects an update time filled from the creation time of the same object — the record looks unchanged since it was made",
		core.SeverityMedium,
	)}
}

// updateTimeKeys are the field names of an update time.
var updateTimeKeys = map[string]bool{"UpdatedAt": true, "ModifiedAt": true, "LastModified": true, "UpdatedOn": true}

// AnalyzeFile reports the literals whose update time is the creation time.
func (r *UpdatedAtFromCreatedAtRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !productionGoFile(ctx) {
		return nil
	}
	getters := createdAtGetters(ctx.GoAST)
	var violations []*core.Violation
	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		created := map[string]bool{}
		for _, elt := range lit.Elts {
			if kv, ok := elt.(*ast.KeyValueExpr); ok && keyName(kv.Key) == "CreatedAt" {
				if owner, ok := createdAtOwner(kv.Value, nil); ok {
					created[owner] = true
				}
			}
		}
		for _, elt := range lit.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok || !updateTimeKeys[keyName(kv.Key)] {
				continue
			}
			if owner, ok := createdAtOwner(kv.Value, getters); !ok || !created[owner] {
				continue
			}
			line := ctx.LineFor(kv)
			if ctx.IsSuppressed(line, r.Name()) {
				continue
			}
			violations = append(violations, sqlViolation(r.BaseRule, ctx, line,
				keyName(kv.Key)+" is the creation time of the same object — the record looks unchanged since it was made",
				"Read the update time the store keeps, or leave the field out of the response"))
		}
		return true
	})
	return violations
}

// createdAtOwner returns the object whose CreatedAt the expression reads:
// x.CreatedAt, or a call of a getter with x as its only argument.
func createdAtOwner(expr ast.Expr, getters map[string]bool) (string, bool) {
	switch e := ast.Unparen(expr).(type) {
	case *ast.SelectorExpr:
		if e.Sel.Name == "CreatedAt" {
			return types.ExprString(e.X), true
		}
	case *ast.CallExpr:
		if id, ok := e.Fun.(*ast.Ident); ok && getters[id.Name] && len(e.Args) == 1 {
			return types.ExprString(e.Args[0]), true
		}
	}
	return "", false
}

// createdAtGetters returns the functions of the file with one parameter whose
// whole body returns that parameter's CreatedAt.
func createdAtGetters(file *ast.File) map[string]bool {
	getters := map[string]bool{}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv != nil || fn.Body == nil || len(fn.Body.List) != 1 ||
			len(fn.Type.Params.List) != 1 || len(fn.Type.Params.List[0].Names) != 1 {
			continue
		}
		ret, ok := fn.Body.List[0].(*ast.ReturnStmt)
		if !ok || len(ret.Results) != 1 {
			continue
		}
		if owner, ok := createdAtOwner(ret.Results[0], nil); ok && owner == fn.Type.Params.List[0].Names[0].Name {
			getters[fn.Name.Name] = true
		}
	}
	return getters
}
