package patterns

import (
	"go/ast"
	"go/token"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewPaginationBoundaryTruncationRule())
}

// PaginationBoundaryTruncationRule detects silent page caps on time-bounded history walks.
type PaginationBoundaryTruncationRule struct {
	*rules.BaseRule
}

// NewPaginationBoundaryTruncationRule creates the rule.
func NewPaginationBoundaryTruncationRule() *PaginationBoundaryTruncationRule {
	return &PaginationBoundaryTruncationRule{BaseRule: rules.NewBaseRule(
		"pagination-boundary-truncation",
		"patterns",
		"Detects pagination that can silently stop at a page cap before reaching its time boundary",
		core.SeverityMedium,
	)}
}

// AnalyzeFile finds loops with both a temporal completion boundary and a silent page-cap break.
func (r *PaginationBoundaryTruncationRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || ctx.IsTestFile() || ctx.GoAST == nil {
		return nil
	}
	var violations []*core.Violation
	ast.Inspect(ctx.GoAST, func(node ast.Node) bool {
		fn, ok := node.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			return true
		}
		boundaryNames := temporalBoundaryNames(fn)
		if len(boundaryNames) == 0 {
			return false
		}
		labels := loopLabels(fn.Body)
		ast.Inspect(fn.Body, func(child ast.Node) bool {
			loop, ok := child.(*ast.ForStmt)
			if !ok {
				return true
			}
			exit := paginationLoopExit{label: labels[loop]}
			if !loopHasTemporalBreak(loop, boundaryNames, exit) {
				return true
			}
			if cap := silentPageCap(fn.Body, loop, boundaryNames, exit); cap != nil {
				line := ctx.GoFileSet.Position(cap.Pos()).Line
				v := r.CreateViolation(ctx.RelPath, line, "page cap can silently truncate history before the temporal boundary is reached")
				v.WithCode(ctx.GetLine(line))
				v.WithSuggestion("Walk until the time boundary, or return an explicit truncation error/status when the page cap is reached")
				v.WithContext("pattern", "pagination_boundary_truncation")
				v.WithContext("function", fn.Name.Name)
				violations = append(violations, v)
			}
			return false
		})
		return false
	})
	return violations
}

func temporalBoundaryNames(fn *ast.FuncDecl) map[string]bool {
	names := make(map[string]bool)
	ast.Inspect(fn, func(node ast.Node) bool {
		ident, ok := node.(*ast.Ident)
		if !ok {
			return true
		}
		lower := strings.ToLower(ident.Name)
		for _, marker := range []string{"mintime", "minedat", "since", "cutoff", "notbefore", "fromtime", "until"} {
			if strings.Contains(lower, marker) {
				names[ident.Name] = true
			}
		}
		return true
	})
	return names
}

// loopLabels maps every labeled for statement of a body to its label.
func loopLabels(body *ast.BlockStmt) map[*ast.ForStmt]string {
	labels := make(map[*ast.ForStmt]string)
	ast.Inspect(body, func(node ast.Node) bool {
		labeled, ok := node.(*ast.LabeledStmt)
		if !ok {
			return true
		}
		if loop, isLoop := labeled.Stmt.(*ast.ForStmt); isLoop {
			labels[loop] = labeled.Label.Name
		}
		return true
	})
	return labels
}

// paginationLoopExit says which statements leave the pagination loop: an
// unlabeled break, a break naming the loop's label, and (for the temporal
// boundary) a return.
type paginationLoopExit struct {
	label string
}

// breaks reports whether the branch statement is a break of the loop.
func (e paginationLoopExit) breaks(stmt *ast.BranchStmt) bool {
	if stmt.Tok != token.BREAK {
		return false
	}
	return stmt.Label == nil || (e.label != "" && stmt.Label.Name == e.label)
}

func loopHasTemporalBreak(loop *ast.ForStmt, boundaryNames map[string]bool, exit paginationLoopExit) bool {
	found := false
	ast.Inspect(loop.Body, func(node ast.Node) bool {
		if found {
			return false
		}
		if _, nested := node.(*ast.FuncLit); nested {
			return false
		}
		ifStmt, ok := node.(*ast.IfStmt)
		if !ok || !containsIdentifier(ifStmt.Cond, boundaryNames) || !blockEndsWalk(ifStmt.Body, exit) {
			return true
		}
		found = true
		return false
	})
	return found
}

func silentPageCap(body *ast.BlockStmt, loop *ast.ForStmt, boundaryNames map[string]bool, exit paginationLoopExit) ast.Node {
	if containsPageCapName(loop.Cond) && !reportsExhaustion(statementAfter(body, loop)) {
		return loop
	}
	var result *ast.IfStmt
	ast.Inspect(loop.Body, func(node ast.Node) bool {
		if result != nil {
			return false
		}
		ifStmt, ok := node.(*ast.IfStmt)
		if !ok || !containsPageCapName(ifStmt.Cond) || !blockHasUnsafeCapBreak(ifStmt.Body, boundaryNames, exit) {
			return true
		}
		result = ifStmt
		return false
	})
	if result == nil {
		return nil
	}
	return result
}

// statementAfter returns the statement that follows the loop in its block, or
// nil when the loop is the last one.
func statementAfter(body *ast.BlockStmt, loop *ast.ForStmt) ast.Stmt {
	var next ast.Stmt
	ast.Inspect(body, func(node ast.Node) bool {
		if next != nil {
			return false
		}
		var list []ast.Stmt
		switch block := node.(type) {
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
			if labeled, ok := stmt.(*ast.LabeledStmt); ok {
				stmt = labeled.Stmt
			}
			if stmt == loop && i+1 < len(list) {
				next = list[i+1]
				return false
			}
		}
		return true
	})
	return next
}

// reportsExhaustion reports whether the statement tells the caller that the
// walk ran out of pages: a return of a freshly built or sentinel error, or a
// panic. A loop whose condition carries the page cap falls out into it only
// when the cap is reached, the boundary returning from inside the loop.
func reportsExhaustion(stmt ast.Stmt) bool {
	switch node := stmt.(type) {
	case *ast.ReturnStmt:
		if len(node.Results) == 0 {
			return false
		}
		switch last := ast.Unparen(node.Results[len(node.Results)-1]).(type) {
		case *ast.CallExpr:
			return isErrorConstruction(last)
		case *ast.Ident:
			return isSentinelErrorName(last.Name)
		case *ast.SelectorExpr:
			return isSentinelErrorName(last.Sel.Name)
		}
	case *ast.ExprStmt:
		call, ok := node.X.(*ast.CallExpr)
		if !ok {
			return false
		}
		switch name := mutationCalleeName(call.Fun); name {
		case "panic", "Fatal", "Fatalf", "Panic", "Panicf":
			return true
		}
	}
	return false
}

// blockHasUnsafeCapBreak reports whether the cap block leaves the loop through
// a break. A return is not silent: it hands the caller what it returns,
// typically an explicit truncation error.
func blockHasUnsafeCapBreak(block *ast.BlockStmt, boundaryNames map[string]bool, exit paginationLoopExit) bool {
	for _, stmt := range block.List {
		if ifStmt, ok := stmt.(*ast.IfStmt); ok && boundaryAbsentCondition(ifStmt.Cond, boundaryNames) {
			continue
		}
		switch node := stmt.(type) {
		case *ast.BranchStmt:
			if exit.breaks(node) {
				return true
			}
		case *ast.BlockStmt:
			if blockHasUnsafeCapBreak(node, boundaryNames, exit) {
				return true
			}
		case *ast.IfStmt:
			if blockHasUnsafeCapBreak(node.Body, boundaryNames, exit) {
				return true
			}
			if elseBlock, ok := node.Else.(*ast.BlockStmt); ok && blockHasUnsafeCapBreak(elseBlock, boundaryNames, exit) {
				return true
			}
		}
	}
	return false
}

func boundaryAbsentCondition(expr ast.Expr, boundaryNames map[string]bool) bool {
	binary, ok := expr.(*ast.BinaryExpr)
	if !ok || binary.Op.String() != "==" {
		return false
	}
	left, leftOK := binary.X.(*ast.Ident)
	right, rightOK := binary.Y.(*ast.Ident)
	return leftOK && rightOK && ((boundaryNames[left.Name] && right.Name == "nil") || (left.Name == "nil" && boundaryNames[right.Name]))
}

func containsIdentifier(node ast.Node, names map[string]bool) bool {
	found := false
	ast.Inspect(node, func(child ast.Node) bool {
		if ident, ok := child.(*ast.Ident); ok && names[ident.Name] {
			found = true
			return false
		}
		return !found
	})
	return found
}

func containsPageCapName(node ast.Node) bool {
	if node == nil {
		return false
	}
	found := false
	ast.Inspect(node, func(child ast.Node) bool {
		ident, ok := child.(*ast.Ident)
		if !ok {
			return true
		}
		lower := strings.ToLower(ident.Name)
		found = strings.Contains(lower, "maxpage") || strings.Contains(lower, "pagelimit")
		return !found
	})
	return found
}

// blockEndsWalk reports whether the block ends the pagination walk: a break of
// the loop or a return.
func blockEndsWalk(block *ast.BlockStmt, exit paginationLoopExit) bool {
	for _, stmt := range block.List {
		switch node := stmt.(type) {
		case *ast.ReturnStmt:
			return true
		case *ast.BranchStmt:
			if exit.breaks(node) {
				return true
			}
		case *ast.BlockStmt:
			if blockEndsWalk(node, exit) {
				return true
			}
		case *ast.IfStmt:
			if blockEndsWalk(node.Body, exit) {
				return true
			}
			if elseBlock, ok := node.Else.(*ast.BlockStmt); ok && blockEndsWalk(elseBlock, exit) {
				return true
			}
		}
	}
	return false
}
