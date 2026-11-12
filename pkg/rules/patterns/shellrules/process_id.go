package shellrules

import (
	"go/ast"
	"go/token"
	"go/types"
	"maps"

	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
)

type processIDPredicate func(ast.Expr, *types.Info) bool

func isProcessID(expr ast.Expr, info *types.Info, parent bool) bool {
	if info == nil {
		return false
	}
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok {
		return false
	}
	if len(call.Args) == 1 && info.Types[call.Fun].IsType() {
		return isProcessID(call.Args[0], info, parent)
	}
	name := "Getpid"
	if parent {
		name = "Getppid"
	}
	return patternkit.IsPkgFunc(info, call, "os", name) || patternkit.IsPkgFunc(info, call, "syscall", name) || patternkit.IsPkgFunc(info, call, "golang.org/x/sys/unix", name)
}

func isCurrentProcessID(expr ast.Expr, info *types.Info) bool { return isProcessID(expr, info, false) }
func isParentProcessID(expr ast.Expr, info *types.Info) bool  { return isProcessID(expr, info, true) }

func findProcessFor(expr ast.Expr, info *types.Info, target processIDPredicate, pids map[types.Object]bool) bool {
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok {
		return false
	}
	return patternkit.IsPkgFunc(info, call, "os", "FindProcess") && len(call.Args) > 0 && (target(call.Args[0], info) || pidsFrom(call.Args[0], info, pids))
}

type processAliases struct {
	PIDs    map[types.Object]bool
	Handles map[types.Object]bool
}

// aliasWrites holds every value written to a variable; nil is a write whose
// value is unknown (a second result, ++, range, a declaration without value,
// its address taken).
type aliasWrites map[types.Object][]ast.Expr

// collectAliasWrites adds the writes under root to the variables declared at
// package level (packageLevel) or inside a function (!packageLevel).
func collectAliasWrites(root ast.Node, info *types.Info, packageLevel bool, writes aliasWrites) {
	add := func(lhs, rhs []ast.Expr) {
		for i, target := range lhs {
			id, ok := ast.Unparen(target).(*ast.Ident)
			if !ok {
				continue
			}
			v, ok := infoObject(info, id).(*types.Var)
			if !ok || v.Pkg() == nil || (v.Parent() == v.Pkg().Scope()) != packageLevel {
				continue
			}
			var value ast.Expr
			if i < len(rhs) {
				value = rhs[i]
			}
			writes[v] = append(writes[v], value)
		}
	}
	ast.Inspect(root, func(node ast.Node) bool {
		switch n := node.(type) {
		case *ast.AssignStmt:
			add(n.Lhs, n.Rhs)
		case *ast.ValueSpec:
			names := make([]ast.Expr, len(n.Names))
			for i, id := range n.Names {
				names[i] = id
			}
			add(names, n.Values)
		case *ast.IncDecStmt:
			add([]ast.Expr{n.X}, nil)
		case *ast.RangeStmt:
			add([]ast.Expr{n.Key, n.Value}, nil)
		case *ast.UnaryExpr:
			if n.Op == token.AND {
				add([]ast.Expr{n.X}, nil)
			}
		}
		return true
	})
}

// resolveAliases adds to result each variable whose every write has a value:
// one write of another value and the variable is not an alias.
func resolveAliases[V comparable](writes aliasWrites, result map[types.Object]V, value func(ast.Expr) V) {
	var zero V
	for changed := true; changed; {
		changed = false
		for obj, values := range writes {
			if result[obj] != zero {
				continue
			}
			first := value(values[0])
			every := first != zero
			for _, write := range values[1:] {
				every = every && value(write) != zero
			}
			if every {
				result[obj] = first
				changed = true
			}
		}
	}
}

func resolveProcessAliases(writes aliasWrites, info *types.Info, target processIDPredicate, base processAliases) processAliases {
	out := processAliases{PIDs: maps.Clone(base.PIDs), Handles: maps.Clone(base.Handles)}
	if out.PIDs == nil {
		out.PIDs, out.Handles = make(map[types.Object]bool), make(map[types.Object]bool)
	}
	resolveAliases(writes, out.PIDs, func(e ast.Expr) bool { return target(e, info) || pidsFrom(e, info, out.PIDs) })
	resolveAliases(writes, out.Handles, func(e ast.Expr) bool {
		return findProcessFor(e, info, target, out.PIDs) || pidsFrom(e, info, out.Handles)
	})
	return out
}
