package patterns

import (
	"go/ast"
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
		ast.Inspect(fn.Body, func(child ast.Node) bool {
			loop, ok := child.(*ast.ForStmt)
			if !ok {
				return true
			}
			if !loopHasTemporalBreak(loop, boundaryNames) {
				return true
			}
			if cap := silentPageCap(loop, boundaryNames); cap != nil {
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

func loopHasTemporalBreak(loop *ast.ForStmt, boundaryNames map[string]bool) bool {
	found := false
	ast.Inspect(loop.Body, func(node ast.Node) bool {
		if found {
			return false
		}
		ifStmt, ok := node.(*ast.IfStmt)
		if !ok || !containsIdentifier(ifStmt.Cond, boundaryNames) || !blockBreaksCurrentLoop(ifStmt.Body) {
			return true
		}
		found = true
		return false
	})
	return found
}

func silentPageCap(loop *ast.ForStmt, boundaryNames map[string]bool) ast.Node {
	if containsPageCapName(loop.Cond) {
		return loop
	}
	var result *ast.IfStmt
	ast.Inspect(loop.Body, func(node ast.Node) bool {
		if result != nil {
			return false
		}
		ifStmt, ok := node.(*ast.IfStmt)
		if !ok || !containsPageCapName(ifStmt.Cond) || !blockHasUnsafeCapBreak(ifStmt.Body, boundaryNames) {
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

func blockHasUnsafeCapBreak(block *ast.BlockStmt, boundaryNames map[string]bool) bool {
	for _, stmt := range block.List {
		if ifStmt, ok := stmt.(*ast.IfStmt); ok && boundaryAbsentCondition(ifStmt.Cond, boundaryNames) {
			continue
		}
		switch node := stmt.(type) {
		case *ast.BranchStmt:
			if node.Tok.String() == "break" && node.Label == nil {
				return true
			}
		case *ast.BlockStmt:
			if blockHasUnsafeCapBreak(node, boundaryNames) {
				return true
			}
		case *ast.IfStmt:
			if blockHasUnsafeCapBreak(node.Body, boundaryNames) {
				return true
			}
			if elseBlock, ok := node.Else.(*ast.BlockStmt); ok && blockHasUnsafeCapBreak(elseBlock, boundaryNames) {
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

func blockBreaksCurrentLoop(block *ast.BlockStmt) bool {
	for _, stmt := range block.List {
		switch node := stmt.(type) {
		case *ast.BranchStmt:
			if node.Tok.String() == "break" && node.Label == nil {
				return true
			}
		case *ast.BlockStmt:
			if blockBreaksCurrentLoop(node) {
				return true
			}
		case *ast.IfStmt:
			if blockBreaksCurrentLoop(node.Body) {
				return true
			}
			if elseBlock, ok := node.Else.(*ast.BlockStmt); ok && blockBreaksCurrentLoop(elseBlock) {
				return true
			}
		}
	}
	return false
}
