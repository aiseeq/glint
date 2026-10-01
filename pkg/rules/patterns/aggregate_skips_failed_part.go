package patterns

import (
	"go/ast"
	"go/token"
	"path/filepath"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewAggregateSkipsFailedPartRule())
}

// AggregateSkipsFailedPartRule detects a loop over a fixed list - currencies,
// networks, providers - that sums or collects a result per item, and on a
// failed load logs and continues:
//
//	for _, cur := range stablecoins {
//		txs, err := repo.ByCurrency(ctx, user, cur)
//		if err != nil {
//			log.Error("load failed", "error", err)
//			continue
//		}
//		all = append(all, txs...)
//	}
//	return balanceOf(all), nil
//
// Every item of the list is part of the answer: the balance computed without
// one currency is shown as the balance, and the function that could return
// the error reports success. Reported in a function returning an error, for
// a range over a literal list or a package variable holding one; a loop over
// rows or request items, where skipping a bad one is a decision about the
// data, is left alone.
type AggregateSkipsFailedPartRule struct {
	*rules.BaseRule
	// lists maps a directory to its package variables holding a literal list.
	lists map[string]map[string]bool
}

// NewAggregateSkipsFailedPartRule creates the rule
func NewAggregateSkipsFailedPartRule() *AggregateSkipsFailedPartRule {
	return &AggregateSkipsFailedPartRule{BaseRule: rules.NewBaseRule(
		"aggregate-skips-failed-part",
		"patterns",
		"Detects a loop over a fixed list (currencies, networks) that logs a failed load and continues, then returns the sum or collection as complete",
		core.SeverityHigh,
	)}
}

// UseProjectFiles collects the package variables holding literal lists.
func (r *AggregateSkipsFailedPartRule) UseProjectFiles(files []*core.FileContext) {
	r.lists = make(map[string]map[string]bool)
	for _, ctx := range files {
		if !ctx.IsGoFile() || !ctx.HasGoAST() {
			continue
		}
		dir := filepath.Dir(ctx.Path)
		for _, name := range literalListVars(ctx.GoAST) {
			if r.lists[dir] == nil {
				r.lists[dir] = make(map[string]bool)
			}
			r.lists[dir][name] = true
		}
	}
}

// literalListVars returns the file's package variables holding a literal list.
func literalListVars(file *ast.File) []string {
	var names []string
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.VAR {
			continue
		}
		for _, spec := range gen.Specs {
			value, ok := spec.(*ast.ValueSpec)
			if !ok || len(value.Names) != len(value.Values) {
				continue
			}
			for i, name := range value.Names {
				if literalList(value.Values[i]) {
					names = append(names, name.Name)
				}
			}
		}
	}
	return names
}

// ResetState drops the lists of the previous root.
func (r *AggregateSkipsFailedPartRule) ResetState() { r.lists = nil }

// literalList reports a slice or array literal of literals and constants.
func literalList(expr ast.Expr) bool {
	lit, ok := ast.Unparen(expr).(*ast.CompositeLit)
	if !ok || len(lit.Elts) == 0 {
		return false
	}
	if _, isArray := lit.Type.(*ast.ArrayType); !isArray {
		return false
	}
	for _, elt := range lit.Elts {
		switch e := elt.(type) {
		case *ast.BasicLit, *ast.Ident:
		case *ast.SelectorExpr:
			if _, ok := e.X.(*ast.Ident); !ok {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// AnalyzeFile reports the skipped failures of loops over fixed lists.
func (r *AggregateSkipsFailedPartRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || !ctx.HasGoAST() || ctx.IsTestFile() {
		return nil
	}
	lists := r.lists[filepath.Dir(ctx.Path)]
	var violations []*core.Violation
	for _, body := range errorFunctions(ctx.GoAST) {
		ast.Inspect(body, func(n ast.Node) bool {
			if _, nested := n.(*ast.FuncLit); nested {
				return false // checked with its own results
			}
			loop, ok := n.(*ast.RangeStmt)
			if !ok || !fixedList(loop.X, lists) {
				return true
			}
			if skip := skippedFailure(loop); skip != nil {
				line := ctx.LineFor(skip)
				if !ctx.IsSuppressed(line, r.Name()) {
					v := r.CreateViolation(ctx.RelPath, line,
						"A failed item of a fixed list is logged and skipped while the loop builds a total — the result is computed from part of the list and returned as complete")
					v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
					v.WithSuggestion("Return the error (wrapped with the item), or report the result as partial to the caller")
					violations = append(violations, v)
				}
			}
			return true
		})
	}
	return violations
}

// fixedList reports a range over a literal list or a package variable of one.
func fixedList(expr ast.Expr, lists map[string]bool) bool {
	if literalList(expr) {
		return true
	}
	id, ok := ast.Unparen(expr).(*ast.Ident)
	if !ok || !lists[id.Name] {
		return false
	}
	// A local of the same name shadows the package variable.
	if id.Obj != nil {
		if spec, ok := id.Obj.Decl.(*ast.ValueSpec); !ok || len(spec.Values) == 0 || !literalList(spec.Values[0]) {
			return false
		}
	}
	return true
}

// skippedFailure returns the if of the loop body that continues past a
// failed call whose result the loop then accumulates into a variable from
// outside the loop, nil when there is none.
func skippedFailure(loop *ast.RangeStmt) *ast.IfStmt {
	list := loop.Body.List
	for i := 0; i+1 < len(list); i++ {
		assign, ok := list[i].(*ast.AssignStmt)
		if !ok || len(assign.Rhs) != 1 || len(assign.Lhs) < 2 {
			continue
		}
		if _, isCall := ast.Unparen(assign.Rhs[0]).(*ast.CallExpr); !isCall {
			continue
		}
		errVar, ok := assign.Lhs[len(assign.Lhs)-1].(*ast.Ident)
		if !ok || !isErrorVarName(errVar.Name) {
			continue
		}
		values := make(map[string]bool)
		for _, lhs := range assign.Lhs[:len(assign.Lhs)-1] {
			if id, ok := lhs.(*ast.Ident); ok && id.Name != "_" {
				values[id.Name] = true
			}
		}
		check, ok := list[i+1].(*ast.IfStmt)
		if !ok || !errNotNil(check.Cond, errVar.Name) || !continuesOnly(check.Body) {
			continue
		}
		for _, stmt := range list[i+2:] {
			if accumulates(stmt, values, loop.Pos()) {
				return check
			}
		}
	}
	return nil
}

// errNotNil reports the condition err != nil.
func errNotNil(cond ast.Expr, name string) bool {
	bin, ok := ast.Unparen(cond).(*ast.BinaryExpr)
	if !ok || bin.Op != token.NEQ || !isNilIdent(bin.Y) {
		return false
	}
	id, ok := bin.X.(*ast.Ident)
	return ok && id.Name == name
}

// continuesOnly reports a branch that continues and never returns.
func continuesOnly(body *ast.BlockStmt) bool {
	continues, returns := false, false
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.ReturnStmt:
			returns = true
		case *ast.BranchStmt:
			if node.Tok == token.CONTINUE {
				continues = true
			}
		}
		return true
	})
	return continues && !returns
}

// accumulates reports acc = append(acc, v...), acc = acc.Add(v) or acc += v
// for a variable declared before the loop.
func accumulates(stmt ast.Stmt, values map[string]bool, loopPos token.Pos) bool {
	assign, ok := stmt.(*ast.AssignStmt)
	if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 || assign.Tok == token.DEFINE {
		return false
	}
	acc, ok := assign.Lhs[0].(*ast.Ident)
	if !ok || (acc.Obj != nil && acc.Obj.Pos() > loopPos) {
		return false
	}
	usesValue, usesAcc := false, assign.Tok == token.ADD_ASSIGN
	ast.Inspect(assign.Rhs[0], func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok {
			usesValue = usesValue || values[id.Name]
			usesAcc = usesAcc || id.Name == acc.Name
		}
		return true
	})
	return usesValue && usesAcc
}
