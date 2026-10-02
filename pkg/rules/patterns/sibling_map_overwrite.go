package patterns

import (
	"go/ast"
	"go/token"
	"go/types"
	"slices"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewSiblingMapOverwritesOnCollisionRule())
}

// NewSiblingMapOverwritesOnCollisionRule creates
// sibling-map-overwrites-on-collision: one loop fills two maps of the same
// value type, merges the entries of a colliding key in one and plainly
// assigns in the other, so a second entry of a key in the other map
// silently replaces the first:
//
//	if existing, ok := wallet[k]; ok { t.Value = existing.Value.Add(t.Value) }
//	wallet[k] = t
//	...
//	protocol[pk] = t            // two legs of one token in one protocol: one is lost
//
// The loop itself shows that keys collide; the plain assignment drops the
// amount of the earlier entry.
func NewSiblingMapOverwritesOnCollisionRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"sibling-map-overwrites-on-collision",
			"patterns",
			"Detects a loop that merges colliding keys in one map but plainly assigns them in a sibling map of the same value type — the earlier entry is silently replaced",
			core.SeverityMedium,
		),
		suggestion: "Merge the colliding entry as the sibling map does, or make the key unique for every entry",
	}
	r.check = func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		var findings []funcFinding
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			loop, ok := n.(*ast.RangeStmt)
			if !ok {
				return true
			}
			for _, assign := range overwritingSiblings(scope.info, loop.Body) {
				findings = append(findings, funcFinding{node: assign, message: "This map is assigned plainly while the same loop merges colliding keys of a sibling map of the same value type — an earlier entry with this key is silently replaced"})
			}
			return true
		})
		return findings
	}
	return r
}

// overwritingSiblings returns the plain map assignments of a loop body whose
// map is never looked up there, while a map of the same value type is merged
// on a colliding key.
func overwritingSiblings(info *types.Info, body *ast.BlockStmt) []*ast.AssignStmt {
	// merged lists the maps merged on a colliding key, in source order.
	type mergedMap struct {
		obj  types.Object
		elem types.Type
	}
	var merged []mergedMap
	lookedUp := make(map[types.Object]bool)
	var writes []*ast.AssignStmt
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncLit, *ast.RangeStmt, *ast.ForStmt:
			return false
		case *ast.IfStmt:
			if m, elem := mergedLookup(info, node); m != nil {
				merged = append(merged, mergedMap{obj: m, elem: elem})
			}
		case *ast.AssignStmt:
			if m, _ := mapWritten(info, node); m != nil {
				writes = append(writes, node)
			}
			for _, rhs := range node.Rhs {
				if index, ok := ast.Unparen(rhs).(*ast.IndexExpr); ok {
					if m, _ := mapObject(info, index.X); m != nil {
						lookedUp[m] = true
					}
				}
			}
		}
		return true
	})
	var reported []*ast.AssignStmt
	for _, write := range writes {
		m, elem := mapWritten(info, write)
		if lookedUp[m] {
			continue
		}
		if slices.ContainsFunc(merged, func(other mergedMap) bool { return other.obj != m && types.Identical(elem, other.elem) }) {
			reported = append(reported, write)
		}
	}
	return reported
}

// mergedLookup returns the map of `if existing, ok := m[k]; ok { ...Add... }`
// and its value type.
func mergedLookup(info *types.Info, check *ast.IfStmt) (types.Object, types.Type) {
	init, ok := check.Init.(*ast.AssignStmt)
	if !ok || len(init.Lhs) != 2 || len(init.Rhs) != 1 {
		return nil, nil
	}
	index, ok := ast.Unparen(init.Rhs[0]).(*ast.IndexExpr)
	if !ok {
		return nil, nil
	}
	m, elem := mapObject(info, index.X)
	if m == nil {
		return nil, nil
	}
	adds := false
	ast.Inspect(check.Body, func(n ast.Node) bool {
		if call, isCall := n.(*ast.CallExpr); isCall && callName(call) == "Add" {
			adds = true
		}
		return !adds
	})
	if !adds {
		return nil, nil
	}
	return m, elem
}

// mapWritten returns the map of a plain `m[k] = v` assignment and its value
// type.
func mapWritten(info *types.Info, assign *ast.AssignStmt) (types.Object, types.Type) {
	if assign.Tok != token.ASSIGN || len(assign.Lhs) != 1 {
		return nil, nil
	}
	index, ok := assign.Lhs[0].(*ast.IndexExpr)
	if !ok {
		return nil, nil
	}
	return mapObject(info, index.X)
}

// mapObject returns the variable of a map expression and its value type.
func mapObject(info *types.Info, expr ast.Expr) (types.Object, types.Type) {
	ident, ok := ast.Unparen(expr).(*ast.Ident)
	if !ok {
		return nil, nil
	}
	obj := info.ObjectOf(ident)
	if obj == nil {
		return nil, nil
	}
	m, ok := obj.Type().Underlying().(*types.Map)
	if !ok {
		return nil, nil
	}
	return obj, m.Elem()
}
