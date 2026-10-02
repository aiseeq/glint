package patterns

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
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
		report := func(node ast.Node, message, suggestion string) {
			line := file.LineFor(node)
			if file.IsSuppressed(line, r.Name()) {
				return
			}
			v := r.CreateViolation(file.RelPath, line, message)
			v.WithCode(strings.TrimSpace(file.GetLine(line)))
			v.WithSuggestion(suggestion)
			violations = append(violations, v)
		}
		for _, decl := range file.GoAST.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || smallPageFuncName.MatchString(fn.Name.Name) {
				continue
			}
			if takesPage(fn, info) {
				if call := firstPageWrapped(fn, info); call != nil {
					report(call, fn.Name.Name+" hands out the first page of "+callName(call)+" and drops its total — a caller asking for more rows than the page cap gets fewer without a sign",
						"Return the total with the rows, or read the rows without the pager's cap")
				}
				continue
			}
			loops := pageLoops(fn.Body)
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				switch node := n.(type) {
				case *ast.CallExpr:
					if insidePageLoop(node, loops) || !listsRows(node, info) {
						return true
					}
					size, ok, inFilter := firstPageSize(node, fn.Body, info)
					if !ok || (size != 0 && size < pageCapMin) || pageCapWatched(fn.Body, node, info) ||
						inFilter && !dropsTotal(node, fn.Body, info) {
						return true
					}
					message := fmt.Sprintf("One page of %d read as the whole list — rows past it are dropped without a trace", size)
					if size == 0 {
						message = "Page size 0 asked for the whole list — a query reads it as LIMIT 0 and returns no rows"
					}
					report(node, message, "Page through until the reported total or an empty page, or fail loudly when a cap is reached")
				case *ast.CompositeLit:
					if insidePageLoop(node, loops) {
						return true
					}
					if key, size, ok := requestPageSize(node, info); ok && !requestCapWatched(fn.Body, size, info) {
						report(key, fmt.Sprintf("One request asks for a page of %d and takes the items as the whole list — the rest never arrives, and nothing says so", size),
							"Page with the cursor or offset the API returns, or fail loudly when a full page comes back")
					}
				}
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

// firstPageSize returns the page size a call to a paged function asks for —
// as an argument bound to a page-size parameter, or as the page-size field
// of a filter literal passed to it — when the page asked for is the first.
func firstPageSize(call *ast.CallExpr, body *ast.BlockStmt, info *types.Info) (size int64, sized, inFilter bool) {
	sig, ok := info.TypeOf(call.Fun).(*types.Signature)
	if !ok || sig.Variadic() || sig.Params().Len() != len(call.Args) {
		return 0, false, false
	}
	for i := 0; i < sig.Params().Len(); i++ {
		name := sig.Params().At(i).Name()
		switch {
		case pageSizeName.MatchString(name):
			value, ok := pageCapArgument(call.Args[i], info)
			if !ok {
				return 0, false, false
			}
			size, sized = value, true
		case pagePositionName.MatchString(name):
			if value, literal := pageIntConstant(call.Args[i], info); !literal || value > 1 {
				return 0, false, false
			}
		default:
			if lit := filterLiteral(call.Args[i], body, info); lit != nil {
				value, ok, first := literalPageSize(lit, info)
				if !first {
					return 0, false, false
				}
				if ok {
					size, sized, inFilter = value, true, true
				}
			}
		}
	}
	return size, sized, inFilter
}

// dropsTotal reports a call returning rows with an integer total that the
// caller throws away: a callee reporting no total may check its cap itself.
func dropsTotal(call *ast.CallExpr, body *ast.BlockStmt, info *types.Info) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if assign, ok := n.(*ast.AssignStmt); ok && len(assign.Rhs) == 1 && ast.Unparen(assign.Rhs[0]) == call {
			found = droppedListTotal(&ast.BlockStmt{List: []ast.Stmt{assign}}, info) != nil
		}
		return !found
	})
	return found
}

// pageCapName names a constant that caps a read rather than sizing a page:
// the pager's maximum, a limit someone set high enough for "all of it".
var pageCapName = regexp.MustCompile(`(?i)max|limit|cap`)

// pageMaxName names the pager's maximum.
var pageMaxName = regexp.MustCompile(`(?i)max`)

// namedCapMin is the smallest named limit read as "all of it": a smaller
// one sizes a list for a screen.
const namedCapMin = 500

// pageCapArgument returns a page size written as a number in the call, or
// as a constant named as a cap: the pager's maximum, or a limit of at least
// namedCapMin. A constant named as a page size is a page someone chose.
func pageCapArgument(expr ast.Expr, info *types.Info) (int64, bool) {
	value, ok := pageIntConstant(expr, info)
	if !ok {
		return 0, false
	}
	var name string
	switch e := ast.Unparen(expr).(type) {
	case *ast.BasicLit:
		return value, true
	case *ast.Ident:
		name = e.Name
	case *ast.SelectorExpr:
		name = e.Sel.Name
	default:
		return 0, false
	}
	return value, pageMaxName.MatchString(name) || pageCapName.MatchString(name) && value >= namedCapMin
}

// filterLiteral returns the struct literal an argument is: written in the
// call, or held by a local variable it was assigned to.
func filterLiteral(expr ast.Expr, body *ast.BlockStmt, info *types.Info) *ast.CompositeLit {
	expr = ast.Unparen(expr)
	if unary, ok := expr.(*ast.UnaryExpr); ok && unary.Op == token.AND {
		expr = ast.Unparen(unary.X)
	}
	switch e := expr.(type) {
	case *ast.CompositeLit:
		if _, ok := info.TypeOf(e).Underlying().(*types.Struct); ok {
			return e
		}
	case *ast.Ident:
		obj := info.Uses[e]
		if obj == nil {
			return nil
		}
		var found *ast.CompositeLit
		ast.Inspect(body, func(n ast.Node) bool {
			assign, ok := n.(*ast.AssignStmt)
			if !ok || found != nil || len(assign.Lhs) != len(assign.Rhs) {
				return found == nil
			}
			for i, lhs := range assign.Lhs {
				if id, ok := lhs.(*ast.Ident); ok && info.Defs[id] == obj {
					found = filterLiteral(assign.Rhs[i], body, info)
				}
			}
			return found == nil
		})
		return found
	}
	return nil
}

// literalPageSize returns the page size a filter literal sets; first is
// false when it sets a page position past the first one.
func literalPageSize(lit *ast.CompositeLit, info *types.Info) (size int64, sized, first bool) {
	first = true
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok {
			continue
		}
		switch {
		case pageSizeName.MatchString(key.Name):
			size, sized = pageCapArgument(kv.Value, info)
		case pagePositionName.MatchString(key.Name):
			if value, literal := pageIntConstant(kv.Value, info); !literal || value > 1 {
				first = false
			}
		}
	}
	return size, sized, first
}

// requestPageKey names a page cursor or position in a request body.
var requestPageKey = regexp.MustCompile(`(?i)^(page|page_?num(ber)?|offset|skip|cursor|after|before|page_?token|next_?(cursor|page|token)|starting_?after|continuation)$`)

// requestPageSize returns the page-size entry of a map literal that reads as
// a request body ("limit": 1000), when the body names no further page.
func requestPageSize(lit *ast.CompositeLit, info *types.Info) (ast.Node, int64, bool) {
	m, ok := info.TypeOf(lit).Underlying().(*types.Map)
	if !ok {
		return nil, 0, false
	}
	if key, ok := m.Key().Underlying().(*types.Basic); !ok || key.Kind() != types.String {
		return nil, 0, false
	}
	var found ast.Node
	var size int64
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		tv, ok := info.Types[kv.Key]
		if !ok || tv.Value == nil || tv.Value.Kind() != constant.String {
			continue
		}
		key := constant.StringVal(tv.Value)
		switch {
		case responseListKey.MatchString(key):
			// A page written out as a response, not asked for.
			return nil, 0, false
		case pageSizeName.MatchString(key):
			value, ok := pageCapArgument(kv.Value, info)
			if !ok || value < pageCapMin {
				return nil, 0, false
			}
			found, size = kv, value
		case requestPageKey.MatchString(key):
			if value, literal := pageIntConstant(kv.Value, info); !literal || value > 1 {
				return nil, 0, false
			}
		}
	}
	return found, size, found != nil
}

// responseListKey names what a response carries: the rows and their count.
var responseListKey = regexp.MustCompile(`(?i)^(items|data|results|records|rows|total(_?count)?)$`)

// requestCapWatched reports a function that can tell a full page came back:
// it compares a length with the page size, or reads the total or the next
// page the response reports.
func requestCapWatched(body *ast.BlockStmt, size int64, info *types.Info) bool {
	watched := false
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.BinaryExpr:
			if !isComparisonOp(node.Op) {
				break
			}
			for _, side := range []ast.Expr{node.X, node.Y} {
				if value, ok := pageIntConstant(side, info); ok && value == size {
					watched = true
				}
			}
		case *ast.SelectorExpr:
			if responsePageField.MatchString(node.Sel.Name) {
				if _, field := info.Selections[node]; field {
					watched = true
				}
			}
		}
		return !watched
	})
	return watched
}

// responsePageField names what a response says about the rest of the list.
var responsePageField = regexp.MustCompile(`(?i)^(total(count)?|has_?more|has_?next(_?page)?|next_?(cursor|page|page_?token|token)|cursor)$`)

// firstPageWrapped returns the call by which a function with a page size of
// its own and no page position hands out the first page of a paged call and
// drops the total that call returns: its callers cannot tell the callee's
// cap cut their rows.
func firstPageWrapped(fn *ast.FuncDecl, info *types.Info) *ast.CallExpr {
	sizeParams := make(map[types.Object]bool)
	for _, field := range fn.Type.Params.List {
		for _, name := range field.Names {
			if pagePositionName.MatchString(name.Name) {
				return nil
			}
			if param, ok := info.Defs[name].(*types.Var); ok && isPaginationType(param.Type()) {
				return nil
			}
			if pageSizeName.MatchString(name.Name) {
				sizeParams[info.Defs[name]] = true
			}
		}
	}
	if len(sizeParams) == 0 {
		return nil
	}
	var found *ast.CallExpr
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || found != nil || len(assign.Rhs) != 1 {
			return found == nil
		}
		call, ok := ast.Unparen(assign.Rhs[0]).(*ast.CallExpr)
		if !ok || droppedListTotal(&ast.BlockStmt{List: []ast.Stmt{assign}}, info) == nil {
			return true
		}
		sig, ok := info.TypeOf(call.Fun).(*types.Signature)
		if !ok || sig.Variadic() || sig.Params().Len() != len(call.Args) {
			return true
		}
		passesSize, firstPage := false, false
		for i := 0; i < sig.Params().Len(); i++ {
			name := sig.Params().At(i).Name()
			switch {
			case pageSizeName.MatchString(name):
				if id, ok := ast.Unparen(call.Args[i]).(*ast.Ident); ok && sizeParams[info.Uses[id]] {
					passesSize = true
				}
			case pagePositionName.MatchString(name):
				if value, literal := pageIntConstant(call.Args[i], info); literal && value <= 1 {
					firstPage = true
				}
			}
		}
		if passesSize && firstPage {
			found = call
		}
		return found == nil
	})
	return found
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

// AnalyzeGoProject reports the count calls that replace a dropped list total,
// and the totals functions mapping a list filter by hand.
func (r *PaginatedTotalRecountedRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%s: nil Go project context", r.Name())
	}
	handMapped := make(map[*core.FileContext][]handMapped)
	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil || pkg.Package.TypesInfo == nil {
			continue
		}
		for file, found := range handMappedFilters(pkg) {
			handMapped[file] = append(handMapped[file], found...)
		}
	}
	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(file *core.FileContext, info *types.Info) []*core.Violation {
		var violations []*core.Violation
		for _, found := range handMapped[file] {
			line := file.LineFor(found.node)
			if file.IsSuppressed(line, r.Name()) {
				continue
			}
			v := r.CreateViolation(file.RelPath, line, handMappedMessage(found))
			v.WithCode(strings.TrimSpace(file.GetLine(line)))
			v.WithSuggestion("Map the filter once and use that mapping for the list and its totals")
			violations = append(violations, v)
		}
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
