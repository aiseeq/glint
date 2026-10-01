package patterns

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/types"
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewPaginatedCallFirstPageOnlyRule())
	rules.Register(NewPaginatedTotalRecountedRule())
}

// pageCapMin is the smallest literal page size read as "all of it" rather
// than as a deliberate few.
const pageCapMin = 100

// smallPageFuncName names a function that wants a few rows on purpose.
var smallPageFuncName = regexp.MustCompile(`(?i)recent|latest|newest|oldest|top|first|last|preview|sample|head|peek|exist|has|any|count`)

// PaginatedCallFirstPageOnlyRule detects a paged call asked once for its
// first page with a literal size, by a function that wants the whole list:
//
//	func (s *Source) Members(ctx context.Context) ([]*Member, error) {
//	    members, _, err := s.repo.ListMembers(ctx, Filter{}, 1, 0)      // limit 0: no rows
//	    members, _, err := s.repo.ListMembers(ctx, Filter{}, 1, 10000)  // the rest is dropped
//	}
//	transfers, err := s.client.ListTransfers(ctx, from, to, 0, 100)    // never page 2
//
// Limit 0 reads as "no limit" to the caller and as LIMIT 0 to the query: the
// list comes back empty. A large cap works until the data outgrows it, then
// rows past it vanish without an error.
type PaginatedCallFirstPageOnlyRule struct {
	*rules.BaseRule
}

// NewPaginatedCallFirstPageOnlyRule creates the rule
func NewPaginatedCallFirstPageOnlyRule() *PaginatedCallFirstPageOnlyRule {
	return &PaginatedCallFirstPageOnlyRule{BaseRule: rules.NewBaseRule(
		"paginated-call-first-page-only",
		"patterns",
		"Detects a paged call read once with a literal page size (0 or a large cap) where the whole list is wanted — rows past the first page are lost",
		core.SeverityHigh,
	)}
}

// AnalyzeFile is a no-op: the callee's parameter names decide.
func (r *PaginatedCallFirstPageOnlyRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *PaginatedCallFirstPageOnlyRule) RequiresSSA() bool { return false }

// AnalyzeGoProject reports the single first-page reads of paged calls.
func (r *PaginatedCallFirstPageOnlyRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(file *core.FileContext, info *types.Info) []*core.Violation {
		var violations []*core.Violation
		for _, decl := range file.GoAST.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || smallPageFuncName.MatchString(fn.Name.Name) || takesPage(fn, info) {
				continue
			}
			loops := pageLoops(fn.Body)
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || insidePageLoop(call, loops) || !listsRows(call, info) {
					return true
				}
				size, ok := firstPageSize(call, info)
				if !ok || (size != 0 && size < pageCapMin) || pageCapWatched(fn.Body, call, info) {
					return true
				}
				line := file.LineFor(call)
				if file.IsSuppressed(line, r.Name()) {
					return true
				}
				message := fmt.Sprintf("One page of %d read as the whole list — rows past it are dropped without a trace", size)
				if size == 0 {
					message = "Page size 0 asked for the whole list — a query reads it as LIMIT 0 and returns no rows"
				}
				v := r.CreateViolation(file.RelPath, line, message)
				v.WithCode(strings.TrimSpace(file.GetLine(line)))
				v.WithSuggestion("Page through until the reported total or an empty page, or fail loudly when a cap is reached")
				violations = append(violations, v)
				return true
			})
		}
		return violations
	})
}

// takesPage reports a function with a page of its own: it passes the page on.
func takesPage(fn *ast.FuncDecl, info *types.Info) bool {
	for _, field := range fn.Type.Params.List {
		for _, name := range field.Names {
			if isPageFieldName(name.Name) {
				return true
			}
			if param, ok := info.Defs[name].(*types.Var); ok && isPaginationType(param.Type()) {
				return true
			}
		}
	}
	return false
}

// pageLoops returns the for and range statements of a body.
func pageLoops(body *ast.BlockStmt) []ast.Node {
	var loops []ast.Node
	ast.Inspect(body, func(n ast.Node) bool {
		switch n.(type) {
		case *ast.ForStmt, *ast.RangeStmt:
			loops = append(loops, n)
		}
		return true
	})
	return loops
}

func insidePageLoop(n ast.Node, outer []ast.Node) bool {
	for _, o := range outer {
		if o.Pos() <= n.Pos() && n.End() <= o.End() {
			return true
		}
	}
	return false
}

// firstPageSize returns the literal page size of a call to a function with a
// page-size parameter, when its page-position argument, if any, is the first
// page.
func firstPageSize(call *ast.CallExpr, info *types.Info) (int64, bool) {
	sig, ok := info.TypeOf(call.Fun).(*types.Signature)
	if !ok || sig.Variadic() || sig.Params().Len() != len(call.Args) {
		return 0, false
	}
	size, sized := int64(0), false
	for i := 0; i < sig.Params().Len(); i++ {
		name := sig.Params().At(i).Name()
		value, literal := pageIntConstant(call.Args[i], info)
		switch {
		case pageSizeName.MatchString(name):
			// A named constant is a size someone chose; a bare number in
			// the call is the "all of it" guess.
			if _, written := ast.Unparen(call.Args[i]).(*ast.BasicLit); !literal || !written {
				return 0, false
			}
			size, sized = value, true
		case pagePositionName.MatchString(name):
			if !literal || value > 1 {
				return 0, false
			}
		}
	}
	return size, sized
}

// pageListName names a call that reads rows.
var pageListName = regexp.MustCompile(`(?i)^(list|get|find|fetch|load|query|select|search|read|all)`)

// listsRows reports a call reading rows: named as a read, its first result
// a slice of something other than bytes.
func listsRows(call *ast.CallExpr, info *types.Info) bool {
	if !pageListName.MatchString(callName(call)) {
		return false
	}
	t := info.TypeOf(call)
	if tuple, ok := t.(*types.Tuple); ok {
		if tuple.Len() == 0 {
			return false
		}
		t = tuple.At(0).Type()
	}
	if t == nil {
		return false
	}
	slice, ok := t.Underlying().(*types.Slice)
	if !ok {
		return false
	}
	elem, ok := slice.Elem().Underlying().(*types.Basic)
	return !ok || elem.Kind() != types.Byte
}

// pageCapWatched reports a capped read whose caller can tell the cap was
// hit: it keeps the total returned with the rows, or compares the length of
// the rows it got.
func pageCapWatched(body *ast.BlockStmt, call *ast.CallExpr, info *types.Info) bool {
	var assign *ast.AssignStmt
	ast.Inspect(body, func(n ast.Node) bool {
		if a, ok := n.(*ast.AssignStmt); ok && len(a.Rhs) == 1 && ast.Unparen(a.Rhs[0]) == call {
			assign = a
		}
		return assign == nil
	})
	if assign == nil {
		return false
	}
	var rows types.Object
	for i, lhs := range assign.Lhs {
		id, ok := lhs.(*ast.Ident)
		if !ok || id.Name == "_" {
			continue
		}
		obj := info.ObjectOf(id)
		if obj == nil {
			continue
		}
		if i == 0 {
			rows = obj
			continue
		}
		if basic, ok := obj.Type().Underlying().(*types.Basic); ok && basic.Info()&types.IsInteger != 0 {
			return true
		}
	}
	if rows == nil {
		return false
	}
	watched := false
	ast.Inspect(body, func(n ast.Node) bool {
		cmp, ok := n.(*ast.BinaryExpr)
		if !ok || !isComparisonOp(cmp.Op) {
			return !watched
		}
		for _, side := range []ast.Expr{cmp.X, cmp.Y} {
			if lenOf, ok := ast.Unparen(side).(*ast.CallExpr); ok && callName(lenOf) == "len" && len(lenOf.Args) == 1 {
				if id, ok := ast.Unparen(lenOf.Args[0]).(*ast.Ident); ok && info.Uses[id] == rows {
					watched = true
				}
			}
		}
		return !watched
	})
	return watched
}

func pageIntConstant(expr ast.Expr, info *types.Info) (int64, bool) {
	tv, ok := info.Types[expr]
	if !ok || tv.Value == nil || tv.Value.Kind() != constant.Int {
		return 0, false
	}
	return constant.Int64Val(tv.Value)
}

// PaginatedTotalRecountedRule detects a list call whose own total is
// dropped and counted again by a separate query:
//
//	transactions, _, err := repo.ListTransactions(ctx, filter)
//	total, err := repo.GetTransactionsCount(ctx, req.Status, req.UserID, req.Type)
//
// The list honours every field of the filter, the count only the ones
// passed to it: the pager shows 40 pages for 3 rows. Even with the same
// arguments the two queries see different moments.
type PaginatedTotalRecountedRule struct {
	*rules.BaseRule
}

// NewPaginatedTotalRecountedRule creates the rule
func NewPaginatedTotalRecountedRule() *PaginatedTotalRecountedRule {
	return &PaginatedTotalRecountedRule{BaseRule: rules.NewBaseRule(
		"paginated-total-recounted",
		"patterns",
		"Detects a list call's own total dropped and counted again by a separate query — the count can follow another filter than the list",
		core.SeverityMedium,
	)}
}

// AnalyzeFile is a no-op: the call's results decide.
func (r *PaginatedTotalRecountedRule) AnalyzeFile(_ *core.FileContext) []*core.Violation { return nil }

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *PaginatedTotalRecountedRule) RequiresSSA() bool { return false }

var countCallName = regexp.MustCompile(`(?i)count|total`)

// AnalyzeGoProject reports the count calls that replace a dropped list total.
func (r *PaginatedTotalRecountedRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(file *core.FileContext, info *types.Info) []*core.Violation {
		var violations []*core.Violation
		for _, decl := range file.GoAST.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			dropped := droppedListTotal(fn.Body, info)
			if dropped == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || call.Pos() < dropped.End() || !countCallName.MatchString(callName(call)) || !returnsPageCount(call, info) {
					return true
				}
				line := file.LineFor(call)
				if file.IsSuppressed(line, r.Name()) {
					return true
				}
				v := r.CreateViolation(file.RelPath, line, "Total counted by a separate query while the list call's own total is dropped — the count can follow another filter than the list, and the pager lies")
				v.WithCode(strings.TrimSpace(file.GetLine(line)))
				v.WithSuggestion("Use the total the list call returns for the same filter")
				violations = append(violations, v)
				return false
			})
		}
		return violations
	})
}

// droppedListTotal returns the first assignment that takes a list and drops
// the integer total returned with it.
func droppedListTotal(body *ast.BlockStmt, info *types.Info) *ast.AssignStmt {
	var found *ast.AssignStmt
	ast.Inspect(body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || found != nil || len(assign.Rhs) != 1 {
			return found == nil
		}
		call, ok := ast.Unparen(assign.Rhs[0]).(*ast.CallExpr)
		if !ok {
			return true
		}
		results, ok := info.TypeOf(call).(*types.Tuple)
		if !ok || results.Len() != len(assign.Lhs) {
			return true
		}
		list := false
		for i := 0; i < results.Len(); i++ {
			switch t := results.At(i).Type().Underlying().(type) {
			case *types.Slice:
				list = true
			case *types.Basic:
				if blank, ok := assign.Lhs[i].(*ast.Ident); ok && blank.Name == "_" && list && t.Info()&types.IsInteger != 0 {
					found = assign
				}
			}
		}
		return found == nil
	})
	return found
}

// returnsPageCount reports a call whose first result is an integer.
func returnsPageCount(call *ast.CallExpr, info *types.Info) bool {
	t := info.TypeOf(call)
	if tuple, ok := t.(*types.Tuple); ok {
		if tuple.Len() == 0 {
			return false
		}
		t = tuple.At(0).Type()
	}
	basic, ok := t.Underlying().(*types.Basic)
	return ok && basic.Info()&types.IsInteger != 0
}
