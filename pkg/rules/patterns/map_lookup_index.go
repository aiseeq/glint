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
	rules.Register(NewIndexIntoMapLookupRule())
}

// IndexIntoMapLookupRule detects a fixed element of a slice taken straight
// from a map lookup:
//
//	url := cfg.Networks["local"].Endpoints[0]
//
// A key missing from the map yields the zero value, whose slice is empty,
// and the index panics with "index out of range" — a configuration without
// that network brings the request down. Look the key up with comma-ok and
// check the length first. A slice whose length the function checks is not
// reported.
type IndexIntoMapLookupRule struct {
	*rules.BaseRule
}

// NewIndexIntoMapLookupRule creates the rule
func NewIndexIntoMapLookupRule() *IndexIntoMapLookupRule {
	return &IndexIntoMapLookupRule{BaseRule: rules.NewBaseRule(
		"index-into-map-lookup",
		"patterns",
		"Detects a fixed slice element taken straight from a map lookup (m[k].List[0]) — a missing key gives an empty slice and the index panics",
		core.SeverityMedium,
	)}
}

// AnalyzeFile is a no-op: the project run checks every file, with map and
// slice types where the package has them.
func (r *IndexIntoMapLookupRule) AnalyzeFile(_ *core.FileContext) []*core.Violation { return nil }

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *IndexIntoMapLookupRule) RequiresSSA() bool { return false }

// AnalyzeGoProject reports the unchecked indexes into map lookups.
func (r *IndexIntoMapLookupRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	return rules.AnalyzeGoFiles(ctx, r.Name(), func(file *core.FileContext, info *types.Info) []*core.Violation {
		if file.IsTestFile() {
			return nil
		}
		var violations []*core.Violation
		for _, decl := range file.GoAST.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			measured := lengthsTaken(fn.Body)
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				index, ok := n.(*ast.IndexExpr)
				if !ok || !indexesMapLookup(info, index) || measured[types.ExprString(index.X)] {
					return true
				}
				line := file.LineFor(index)
				if file.IsSuppressed(line, r.Name()) {
					return true
				}
				v := r.CreateViolation(file.RelPath, line, fmt.Sprintf(
					"%s indexes a slice read from a map lookup — a missing key gives an empty slice and the index panics",
					types.ExprString(index)))
				v.WithCode(strings.TrimSpace(file.GetLine(line)))
				v.WithSuggestion("Look the key up with comma-ok (v, ok := m[k]) and check the slice length before taking an element")
				violations = append(violations, v)
				return true
			})
		}
		return violations
	})
}

// indexesMapLookup reports a constant index into a slice that a map lookup
// yields, directly or through fields of the looked-up value. Without type
// information only the unmistakable form counts: an integer literal into
// what a string-literal key looks up.
func indexesMapLookup(info *types.Info, index *ast.IndexExpr) bool {
	if info == nil {
		return untypedMapLookupIndex(index)
	}
	if tv, ok := info.Types[index.Index]; !ok || tv.Value == nil {
		return false
	}
	if _, ok := underlyingOf(info, index.X).(*types.Slice); !ok {
		return false
	}
	expr := ast.Unparen(index.X)
	for {
		switch node := expr.(type) {
		case *ast.SelectorExpr:
			if sel := info.Selections[node]; sel == nil || sel.Kind() != types.FieldVal {
				return false
			}
			expr = ast.Unparen(node.X)
		case *ast.IndexExpr:
			_, isMap := underlyingOf(info, node.X).(*types.Map)
			return isMap
		default:
			return false
		}
	}
}

func untypedMapLookupIndex(index *ast.IndexExpr) bool {
	if lit, ok := ast.Unparen(index.Index).(*ast.BasicLit); !ok || lit.Kind != token.INT {
		return false
	}
	expr := ast.Unparen(index.X)
	for {
		switch node := expr.(type) {
		case *ast.SelectorExpr:
			expr = ast.Unparen(node.X)
		case *ast.IndexExpr:
			lit, ok := ast.Unparen(node.Index).(*ast.BasicLit)
			return ok && lit.Kind == token.STRING
		default:
			return false
		}
	}
}

func underlyingOf(info *types.Info, expr ast.Expr) types.Type {
	t := info.TypeOf(expr)
	if t == nil {
		return nil
	}
	return t.Underlying()
}

// lengthsTaken returns the expressions whose length the body takes.
func lengthsTaken(body *ast.BlockStmt) map[string]bool {
	measured := make(map[string]bool)
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 1 {
			return true
		}
		if ident, ok := call.Fun.(*ast.Ident); ok && ident.Name == "len" {
			measured[types.ExprString(call.Args[0])] = true
		}
		return true
	})
	return measured
}
