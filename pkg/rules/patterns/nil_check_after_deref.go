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
	rules.Register(NewNilCheckAfterDereferenceRule())
}

// NilCheckAfterDereferenceRule detects a pointer checked for nil after an
// earlier statement of the same block already read through it:
//
//	log.Info(fmt.Sprintf("processing %s", order.ID))
//	if order == nil {
//	    return
//	}
//
// The check says the pointer can be nil, and then the read above it panics
// first; either the check is dead or it comes too late. A read guarded by
// x != nil, a read inside a function literal and a pointer assigned again
// between the read and the check are not reported.
type NilCheckAfterDereferenceRule struct {
	*rules.BaseRule
}

// NewNilCheckAfterDereferenceRule creates the rule
func NewNilCheckAfterDereferenceRule() *NilCheckAfterDereferenceRule {
	return &NilCheckAfterDereferenceRule{BaseRule: rules.NewBaseRule(
		"nil-check-after-dereference",
		"patterns",
		"Detects a pointer checked for nil after an earlier statement of the same block already dereferenced it — the read panics before the check runs",
		core.SeverityHigh,
	)}
}

// AnalyzeFile is a no-op: field reads through a pointer are known only with
// type information.
func (r *NilCheckAfterDereferenceRule) AnalyzeFile(_ *core.FileContext) []*core.Violation { return nil }

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *NilCheckAfterDereferenceRule) RequiresSSA() bool { return false }

// AnalyzeGoProject reports the late nil checks of every block.
func (r *NilCheckAfterDereferenceRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(file *core.FileContext, info *types.Info) []*core.Violation {
		var violations []*core.Violation
		ast.Inspect(file.GoAST, func(n ast.Node) bool {
			var list []ast.Stmt
			switch block := n.(type) {
			case *ast.BlockStmt:
				list = block.List
			case *ast.CaseClause:
				list = block.Body
			case *ast.CommClause:
				list = block.Body
			default:
				return true
			}
			for i, stmt := range list {
				ifStmt, ok := stmt.(*ast.IfStmt)
				if !ok || ifStmt.Init != nil {
					continue
				}
				pointer := nilCheckedPointer(info, ifStmt.Cond)
				if pointer == nil {
					continue
				}
				deref, ok := firstUnguardedDeref(info, list[:i], pointer)
				if !ok {
					continue
				}
				line := file.LineFor(ifStmt)
				if file.IsSuppressed(line, r.Name()) {
					continue
				}
				v := r.CreateViolation(file.RelPath, line, fmt.Sprintf(
					"%s is checked for nil after line %d already read through it — a nil %s panics there before this check runs",
					pointer.Name(), file.LineFor(deref), pointer.Name()))
				v.WithCode(strings.TrimSpace(file.GetLine(line)))
				v.WithSuggestion("Move the nil check above the first use of the pointer, or drop it if the pointer cannot be nil")
				violations = append(violations, v)
			}
			return true
		})
		return violations
	})
}

// nilCheckedPointer returns the local pointer variable a condition tests
// for nil: x == nil, alone or as an operand of ||.
func nilCheckedPointer(info *types.Info, cond ast.Expr) *types.Var {
	bin, ok := ast.Unparen(cond).(*ast.BinaryExpr)
	if !ok {
		return nil
	}
	switch bin.Op {
	case token.LOR:
		if v := nilCheckedPointer(info, bin.X); v != nil {
			return v
		}
		return nilCheckedPointer(info, bin.Y)
	case token.EQL:
		return comparedPointer(info, bin)
	}
	return nil
}

// comparedPointer returns the local pointer variable compared with nil.
func comparedPointer(info *types.Info, bin *ast.BinaryExpr) *types.Var {
	operand := bin.X
	if isNilIdent(operand) {
		operand = bin.Y
	} else if !isNilIdent(bin.Y) {
		return nil
	}
	ident, ok := ast.Unparen(operand).(*ast.Ident)
	if !ok {
		return nil
	}
	v, ok := info.Uses[ident].(*types.Var)
	if !ok || v.Pkg() == nil || v.Parent() == v.Pkg().Scope() {
		return nil
	}
	if _, ok := v.Type().Underlying().(*types.Pointer); !ok {
		return nil
	}
	return v
}

// firstUnguardedDeref returns the first read through the pointer, in the
// statements before the check, of the value the check is about. A statement
// that assigns the pointer outright starts over: the reads before it were of
// another value. A read that follows an assignment nested in the same
// statement (a branch that fetches the pointer first) reads the fresh value
// and does not count; reads before it still do.
func firstUnguardedDeref(info *types.Info, stmts []ast.Stmt, pointer *types.Var) (ast.Node, bool) {
	scan := &derefScan{info: info, pointer: pointer}
	var reads []ast.Node
	for _, stmt := range stmts {
		scan.derefs, scan.firstAssign = nil, token.NoPos
		ast.Inspect(stmt, scan.visit)
		if assign, ok := stmt.(*ast.AssignStmt); ok && scan.firstAssign.IsValid() && scan.firstAssign == assign.TokPos {
			reads = nil
			continue
		}
		for _, deref := range scan.derefs {
			if !scan.firstAssign.IsValid() || deref.Pos() < scan.firstAssign {
				reads = append(reads, deref)
			}
		}
	}
	if len(reads) == 0 {
		return nil, false
	}
	return reads[0], true
}

// derefScan collects, in one statement, the unguarded reads through a
// pointer and the first place the pointer changes.
type derefScan struct {
	info        *types.Info
	pointer     *types.Var
	derefs      []ast.Node
	firstAssign token.Pos
}

func (d *derefScan) is(expr ast.Expr) bool {
	ident, ok := ast.Unparen(expr).(*ast.Ident)
	return ok && d.info.Uses[ident] == d.pointer
}

func (d *derefScan) assigned(pos token.Pos) {
	if !d.firstAssign.IsValid() || pos < d.firstAssign {
		d.firstAssign = pos
	}
}

// tests reports whether expr compares the pointer with nil by op.
func (d *derefScan) tests(expr ast.Expr, op token.Token) bool {
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		if bin, ok := n.(*ast.BinaryExpr); ok && bin.Op == op && comparedPointer(d.info, bin) == d.pointer {
			found = true
		}
		return !found
	})
	return found
}

func (d *derefScan) visit(n ast.Node) bool {
	switch node := n.(type) {
	case *ast.FuncLit:
		return false
	case *ast.IfStmt:
		return d.visitIf(node)
	case *ast.BinaryExpr:
		// x != nil && x.F, x == nil || x.F
		if (node.Op == token.LAND && d.tests(node.X, token.NEQ)) || (node.Op == token.LOR && d.tests(node.X, token.EQL)) {
			ast.Inspect(node.X, d.visit)
			return false
		}
	case *ast.AssignStmt:
		for _, lhs := range node.Lhs {
			if d.is(lhs) {
				// The right side is evaluated before the pointer changes.
				d.assigned(node.TokPos)
			}
		}
	case *ast.UnaryExpr:
		if node.Op == token.AND && d.is(node.X) {
			d.assigned(node.Pos())
		}
	case *ast.StarExpr:
		if d.is(node.X) {
			d.derefs = append(d.derefs, node)
		}
	case *ast.SelectorExpr:
		if sel := d.info.Selections[node]; sel != nil && sel.Kind() == types.FieldVal && d.is(node.X) {
			d.derefs = append(d.derefs, node)
		}
	}
	return true
}

// visitIf skips the branch the condition guards: the body of
// if x != nil, the else of if x == nil.
func (d *derefScan) visitIf(node *ast.IfStmt) bool {
	var guarded ast.Node
	switch {
	case node.Cond != nil && d.tests(node.Cond, token.NEQ):
		guarded = node.Body
	case node.Cond != nil && node.Else != nil && d.tests(node.Cond, token.EQL):
		guarded = node.Else
	default:
		return true
	}
	for _, part := range []ast.Node{node.Init, node.Cond, node.Body, node.Else} {
		if part != nil && part != guarded {
			ast.Inspect(part, d.visit)
		}
	}
	return false
}
