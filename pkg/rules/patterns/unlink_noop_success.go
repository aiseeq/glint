package patterns

import (
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewUnlinkNoopReportsSuccessRule())
}

// unlinkVerbs open the names of the methods that remove a link.
var unlinkVerbs = []string{"Unlink", "Detach", "Unassign", "Disconnect", "Remove", "Clear"}

// writeVerbs open the names of the calls that change stored state.
var writeVerbs = wordSet("unlink", "detach", "unassign", "disconnect", "remove", "clear", "update", "delete",
	"save", "set", "insert", "create", "exec", "upsert", "put", "store", "write", "mark")

// NewUnlinkNoopReportsSuccessRule creates unlink-noop-reports-success: a
// method that removes a link (UnlinkTxFromPosition) and returns the entity
// unchanged with a nil error when a secondary record is missing, before any
// write and without looking at the entity's own link field, answers
// "unlinked" while the entity still carries the link:
//
//	tx, err := s.GetTx(ctx, id)
//	rec, err := s.GetRecord(ctx, id)
//	if rec == nil { return tx, nil }   // tx.PositionID is still set
//
// The link field is the entity's field named after the method's target
// (Position → PositionID).
func NewUnlinkNoopReportsSuccessRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"unlink-noop-reports-success",
			"patterns",
			"Detects an unlink that returns the entity unchanged as success when a secondary record is missing, without checking the entity's own link — the link stays and the caller is told it is gone",
			core.SeverityMedium,
		),
		suggestion: "Clear the entity's own link field on that path, or return an error when the link cannot be removed",
	}
	r.check = func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		target := unlinkTarget(fn.Name.Name)
		if target == "" || fn.Type.Results == nil || fn.Type.Results.NumFields() != 2 {
			return nil
		}
		var findings []funcFinding
		for _, ret := range noopUnlinkReturns(scope.info, fn.Body, target) {
			findings = append(findings, funcFinding{node: ret, message: "The unlink returns the entity unchanged as success while its own " + target + " link is never looked at on this path — the link stays and the caller is told it is gone"})
		}
		return findings
	}
	return r
}

// unlinkTarget returns what an unlink method removes the link to: the word
// after "From" (UnlinkTxFromPosition), or the rest of the name after the verb.
func unlinkTarget(name string) string {
	for _, verb := range unlinkVerbs {
		rest, ok := strings.CutPrefix(name, verb)
		if !ok || rest == "" {
			continue
		}
		if _, after, found := strings.Cut(rest, "From"); found && after != "" {
			return after
		}
		return rest
	}
	return ""
}

// noopUnlinkReturns returns the early `return entity, nil` statements of an
// unlink body that come before any write and before any read of the entity's
// link field.
func noopUnlinkReturns(info *types.Info, body *ast.BlockStmt, target string) []*ast.ReturnStmt {
	var entity *types.Var
	var field *types.Var
	var returns []*ast.ReturnStmt
	for _, stmt := range body.List {
		if entity == nil {
			entity, field = loadedEntity(info, stmt, target)
			continue
		}
		if writesState(stmt) || readsField(info, stmt, entity, field) {
			return returns
		}
		if ret := noopReturn(info, stmt, entity); ret != nil {
			returns = append(returns, ret)
		}
	}
	return nil
}

// loadedEntity returns the variable a statement loads from a call when its
// struct type has the link field of the target (TargetID or Target).
func loadedEntity(info *types.Info, stmt ast.Stmt, target string) (*types.Var, *types.Var) {
	assign, ok := stmt.(*ast.AssignStmt)
	if !ok || len(assign.Rhs) != 1 || len(assign.Lhs) == 0 {
		return nil, nil
	}
	if _, isCall := ast.Unparen(assign.Rhs[0]).(*ast.CallExpr); !isCall {
		return nil, nil
	}
	ident, ok := assign.Lhs[0].(*ast.Ident)
	if !ok {
		return nil, nil
	}
	v, ok := info.ObjectOf(ident).(*types.Var)
	if !ok {
		return nil, nil
	}
	st := structUnder(v.Type())
	if st == nil {
		return nil, nil
	}
	for i := 0; i < st.NumFields(); i++ {
		f := st.Field(i)
		if f.Name() == target+"ID" || f.Name() == target+"Id" || f.Name() == target {
			return v, f
		}
	}
	return nil, nil
}

// structUnder returns the struct under a type or a pointer to it.
func structUnder(t types.Type) *types.Struct {
	if pointer, ok := types.Unalias(t).(*types.Pointer); ok {
		t = pointer.Elem()
	}
	st, _ := t.Underlying().(*types.Struct)
	return st
}

// writesState reports a statement calling something that changes stored
// state (Update, Delete, Unlink...).
func writesState(stmt ast.Stmt) bool {
	found := false
	ast.Inspect(stmt, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			words := helpers.IdentifierWords(callName(call))
			found = found || (len(words) > 0 && writeVerbs[words[0]])
		}
		return !found
	})
	return found
}

// readsField reports a statement reading entity.field.
func readsField(info *types.Info, stmt ast.Stmt, entity, field *types.Var) bool {
	found := false
	ast.Inspect(stmt, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return !found
		}
		if ident, isIdent := ast.Unparen(sel.X).(*ast.Ident); isIdent && info.ObjectOf(ident) == entity && info.ObjectOf(sel.Sel) == field {
			found = true
		}
		return !found
	})
	return found
}

// noopReturn returns the `return entity, nil` of an `if <other> == nil`
// statement that does not look at the entity.
func noopReturn(info *types.Info, stmt ast.Stmt, entity *types.Var) *ast.ReturnStmt {
	check, ok := stmt.(*ast.IfStmt)
	if !ok || check.Init != nil || check.Else != nil || len(check.Body.List) != 1 {
		return nil
	}
	cond, ok := check.Cond.(*ast.BinaryExpr)
	if !ok || cond.Op != token.EQL || !isNilIdent(cond.Y) || mentionsVar(info, cond.X, entity) {
		return nil
	}
	ret, ok := check.Body.List[0].(*ast.ReturnStmt)
	if !ok || len(ret.Results) != 2 || !isNilIdent(ret.Results[1]) {
		return nil
	}
	if ident, isIdent := ast.Unparen(ret.Results[0]).(*ast.Ident); isIdent && info.ObjectOf(ident) == entity {
		return ret
	}
	return nil
}
