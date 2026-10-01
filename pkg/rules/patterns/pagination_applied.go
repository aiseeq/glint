package patterns

import (
	"go/ast"
	"go/token"
	"go/types"
	"regexp"
	"strings"

	"golang.org/x/tools/go/ast/astutil"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewPaginationParamNotAppliedRule())
	rules.Register(NewPaginationInMemoryRule())
}

var (
	// pageSizeName names the size of a page: a struct field or a parameter.
	pageSizeName = regexp.MustCompile(`(?i)^(limit|page_?size|per_?page|page_?limit|take|max_?results)$`)
	// pagePositionName names where a page starts.
	pagePositionName = regexp.MustCompile(`(?i)^(page|page_?num(ber)?|page_?no|offset|skip)$`)
	// pageResponseName names the type a page of rows goes out in.
	pageResponseName = regexp.MustCompile(`(?i)response|paginat|page|result|envelope`)
	// pageLogName names a log or format call: it only reports the page.
	pageLogName = regexp.MustCompile(`^(Debug|Info|Warn|Warning|Error|Fatal|Trace|Log|Print|Sprint|Errorf)`)
)

func isPageFieldName(name string) bool {
	return pageSizeName.MatchString(name) || pagePositionName.MatchString(name)
}

// isPaginationType reports a struct (or a pointer to one) carrying both the
// size and the position of a page.
func isPaginationType(t types.Type) bool {
	if t == nil {
		return false
	}
	if ptr, ok := t.Underlying().(*types.Pointer); ok {
		t = ptr.Elem()
	}
	st, ok := t.Underlying().(*types.Struct)
	if !ok {
		return false
	}
	size, position := false, false
	for i := 0; i < st.NumFields(); i++ {
		name := st.Field(i).Name()
		size = size || pageSizeName.MatchString(name)
		position = position || pagePositionName.MatchString(name)
	}
	return size && position
}

// PaginationParamNotAppliedRule detects a function taking a page that hands
// it only to the response:
//
//	func (s *Service) ListAll(ctx context.Context, p *Pagination) (*Page, error) {
//	    items, err := s.repo.ListAll(ctx)
//	    ...
//	    return NewPageResponse(items, p.Page, p.Limit, len(items)), nil
//	}
//
// The response says "page 2 of 20 per page" and carries every row: the
// client renders the whole table on each page, and the next page repeats it.
type PaginationParamNotAppliedRule struct {
	*rules.BaseRule
}

// NewPaginationParamNotAppliedRule creates the rule
func NewPaginationParamNotAppliedRule() *PaginationParamNotAppliedRule {
	return &PaginationParamNotAppliedRule{BaseRule: rules.NewBaseRule(
		"pagination-param-not-applied",
		"patterns",
		"Detects a page parameter that reaches only the response — the list is never cut and every page returns all rows",
		core.SeverityHigh,
	)}
}

// AnalyzeFile is a no-op: the parameter's type decides.
func (r *PaginationParamNotAppliedRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *PaginationParamNotAppliedRule) RequiresSSA() bool { return false }

// AnalyzeGoProject reports the page parameters that only label the response.
func (r *PaginationParamNotAppliedRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(file *core.FileContext, info *types.Info) []*core.Violation {
		var violations []*core.Violation
		for _, decl := range file.GoAST.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			for _, field := range fn.Type.Params.List {
				for _, name := range field.Names {
					param, ok := info.Defs[name].(*types.Var)
					if !ok || !isPaginationType(param.Type()) {
						continue
					}
					response := pageOnlyLabelsResponse(file.GoAST, fn.Body, param, info)
					if response == nil {
						continue
					}
					line := file.LineFor(response)
					if file.IsSuppressed(line, r.Name()) {
						continue
					}
					v := r.CreateViolation(file.RelPath, line, "Page "+name.Name+" reaches only the response — the list is never cut to it, and every page returns all rows")
					v.WithCode(strings.TrimSpace(file.GetLine(line)))
					v.WithSuggestion("Pass the page to the query (LIMIT/OFFSET) and count the total separately")
					violations = append(violations, v)
				}
			}
		}
		return violations
	})
}

// pageOnlyLabelsResponse returns the response call that receives the page
// when nothing else applies it, or nil.
func pageOnlyLabelsResponse(file *ast.File, body *ast.BlockStmt, param *types.Var, info *types.Info) ast.Node {
	var response ast.Node
	applied := false
	ast.Inspect(body, func(n ast.Node) bool {
		id, ok := n.(*ast.Ident)
		if !ok || info.Uses[id] != param || applied {
			return true
		}
		path, _ := astutil.PathEnclosingInterval(file, id.Pos(), id.End())
		use, labels := pageUse(path, info)
		switch use {
		case pageUseApplied:
			applied = true
		case pageUseResponse:
			if response == nil {
				response = labels
			}
		}
		return true
	})
	if applied {
		return nil
	}
	return response
}

type pageUseKind int

const (
	pageUseNeutral pageUseKind = iota
	pageUseApplied
	pageUseResponse
)

// pageUse classifies one use of a page parameter by the expression around
// it: path[0] is the identifier, the rest its parents. The whole value handed
// to a call may be applied by the callee; only its fields can be seen to
// reach nothing but a response.
func pageUse(path []ast.Node, info *types.Info) (pageUseKind, ast.Node) {
	expr := ast.Node(path[0])
	field := false
	i := 1
	if sel, ok := path[i].(*ast.SelectorExpr); ok && sel.X == path[0] {
		if !isPageFieldName(sel.Sel.Name) {
			return pageUseNeutral, nil
		}
		expr, field = sel, true
		i++
	}
	for ; i < len(path); i++ {
		switch parent := path[i].(type) {
		case *ast.ParenExpr, *ast.StarExpr:
			expr = parent
			continue
		case *ast.UnaryExpr:
			if parent.Op == token.AND {
				expr = parent
				continue
			}
			return pageUseApplied, nil
		case *ast.BinaryExpr:
			if isComparisonOp(parent.Op) {
				return pageUseNeutral, nil
			}
			return pageUseApplied, nil
		case *ast.AssignStmt:
			for _, lhs := range parent.Lhs {
				if lhs == expr {
					return pageUseNeutral, nil // a default for the page
				}
			}
			return pageUseApplied, nil
		case *ast.IncDecStmt:
			return pageUseNeutral, nil
		case *ast.CallExpr:
			switch {
			case parent.Fun == expr:
				return pageUseApplied, nil
			case pageLogName.MatchString(callName(parent)):
				return pageUseNeutral, nil
			case field && isPageResponseType(info.TypeOf(parent)):
				return pageUseResponse, parent
			}
			return pageUseApplied, nil
		case *ast.KeyValueExpr:
			expr = parent
			continue
		case *ast.CompositeLit:
			if field && isPageResponseType(info.TypeOf(parent)) {
				return pageUseResponse, parent
			}
			return pageUseApplied, nil
		}
		return pageUseApplied, nil
	}
	return pageUseApplied, nil
}

// isPageResponseType reports a named struct (or a pointer to one) named as a
// response or a page: what a list is wrapped in on its way out.
func isPageResponseType(t types.Type) bool {
	if t == nil {
		return false
	}
	if ptr, ok := t.(*types.Pointer); ok {
		t = ptr.Elem()
	}
	named, ok := types.Unalias(t).(*types.Named)
	if !ok {
		return false
	}
	if _, ok := named.Underlying().(*types.Struct); !ok {
		return false
	}
	return pageResponseName.MatchString(named.Obj().Name())
}

// PaginationInMemoryRule detects a page cut in memory from a list loaded
// whole:
//
//	items, err := s.repo.ListAll(ctx)
//	start := (p.Page - 1) * p.Limit
//	return items[start:end]
//
// Every request reads the whole table to return twenty rows of it: the cost
// grows with the table, not with the page, and so does the memory.
type PaginationInMemoryRule struct {
	*rules.BaseRule
}

// NewPaginationInMemoryRule creates the rule
func NewPaginationInMemoryRule() *PaginationInMemoryRule {
	return &PaginationInMemoryRule{BaseRule: rules.NewBaseRule(
		"pagination-in-memory",
		"patterns",
		"Detects a page sliced in memory from a list loaded whole — every request reads all rows to return one page",
		core.SeverityMedium,
	)}
}

// AnalyzeFile is a no-op: the slice's source decides.
func (r *PaginationInMemoryRule) AnalyzeFile(_ *core.FileContext) []*core.Violation { return nil }

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *PaginationInMemoryRule) RequiresSSA() bool { return false }

// AnalyzeGoProject reports the page slices of lists loaded without the page.
func (r *PaginationInMemoryRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(file *core.FileContext, info *types.Info) []*core.Violation {
		var violations []*core.Violation
		for _, decl := range file.GoAST.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			derived := pageDerivedVars(fn, info)
			if len(derived) == 0 {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				slice, ok := n.(*ast.SliceExpr)
				if !ok || (!mentionsPage(slice.Low, derived, info) && !mentionsPage(slice.High, derived, info)) {
					return true
				}
				if !loadedWithoutPage(fn, slice.X, derived, info) {
					return true
				}
				line := file.LineFor(slice)
				if file.IsSuppressed(line, r.Name()) {
					return true
				}
				v := r.CreateViolation(file.RelPath, line, "Page cut in memory from a list loaded whole — every request reads all rows to return one page")
				v.WithCode(strings.TrimSpace(file.GetLine(line)))
				v.WithSuggestion("Pass the page to the query (LIMIT/OFFSET or a keyset) and load only its rows")
				violations = append(violations, v)
				return true
			})
		}
		return violations
	})
}

// pageDerivedVars returns the page parameters of fn and the local variables
// computed from a page.
func pageDerivedVars(fn *ast.FuncDecl, info *types.Info) map[*types.Var]bool {
	derived := make(map[*types.Var]bool)
	paged := false
	for _, field := range fn.Type.Params.List {
		for _, name := range field.Names {
			param, ok := info.Defs[name].(*types.Var)
			if !ok {
				continue
			}
			if isPaginationType(param.Type()) {
				paged = true
			}
			if isPageFieldName(name.Name) {
				derived[param] = true
			}
			// A size alone truncates; a page also has a position.
			if pagePositionName.MatchString(name.Name) {
				paged = true
			}
		}
	}
	if !paged {
		return nil
	}
	for changed := true; changed; {
		changed = false
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			assign, ok := n.(*ast.AssignStmt)
			if !ok {
				return true
			}
			fromPage := false
			for _, rhs := range assign.Rhs {
				fromPage = fromPage || mentionsPage(rhs, derived, info)
			}
			if !fromPage {
				return true
			}
			for _, lhs := range assign.Lhs {
				id, ok := lhs.(*ast.Ident)
				if !ok {
					continue
				}
				obj, ok := info.ObjectOf(id).(*types.Var)
				if ok && !derived[obj] {
					derived[obj] = true
					changed = true
				}
			}
			return true
		})
	}
	return derived
}

// mentionsPage reports an expression reading a page field of a pagination
// value or a variable derived from a page.
func mentionsPage(expr ast.Expr, derived map[*types.Var]bool, info *types.Info) bool {
	if expr == nil {
		return false
	}
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.SelectorExpr:
			if isPageFieldName(node.Sel.Name) && isPaginationType(info.TypeOf(node.X)) {
				found = true
			}
		case *ast.Ident:
			if obj, ok := info.Uses[node].(*types.Var); ok && derived[obj] {
				found = true
			}
		}
		return !found
	})
	return found
}

// loadedWithoutPage reports a local slice assigned from a call that is not
// given the page.
func loadedWithoutPage(fn *ast.FuncDecl, expr ast.Expr, derived map[*types.Var]bool, info *types.Info) bool {
	id, ok := ast.Unparen(expr).(*ast.Ident)
	if !ok {
		return false
	}
	obj, ok := info.Uses[id].(*types.Var)
	if !ok || obj.Parent() == nil || pageParamOf(fn, obj, info) {
		return false
	}
	loaded, paged := false, false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Rhs) != 1 {
			return true
		}
		call, ok := ast.Unparen(assign.Rhs[0]).(*ast.CallExpr)
		if !ok || !pageAssigns(assign, obj, info) {
			return true
		}
		if _, builtin := info.Uses[pageCalleeIdent(call)].(*types.Builtin); builtin || info.Types[call.Fun].IsType() {
			return true // made here, not loaded
		}
		loaded = true
		for _, arg := range call.Args {
			paged = paged || mentionsPage(arg, derived, info)
		}
		return true
	})
	return loaded && !paged
}

func pageAssigns(assign *ast.AssignStmt, obj *types.Var, info *types.Info) bool {
	for _, lhs := range assign.Lhs {
		if id, ok := lhs.(*ast.Ident); ok && info.ObjectOf(id) == obj {
			return true
		}
	}
	return false
}

func pageParamOf(fn *ast.FuncDecl, obj *types.Var, info *types.Info) bool {
	for _, field := range fn.Type.Params.List {
		for _, name := range field.Names {
			if info.Defs[name] == obj {
				return true
			}
		}
	}
	return false
}

// pageCalleeIdent returns the identifier naming a call's function.
func pageCalleeIdent(call *ast.CallExpr) *ast.Ident {
	switch fun := ast.Unparen(call.Fun).(type) {
	case *ast.Ident:
		return fun
	case *ast.SelectorExpr:
		return fun.Sel
	}
	return nil
}
