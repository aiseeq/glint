package shellrules

import (
	"go/ast"
	"go/token"
	"go/types"
	"maps"
	"slices"

	"github.com/aiseeq/glint/pkg/rules/helpers"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
)

type processIDPredicate func(ast.Expr, *types.Info) bool

// unconverted is expr without its parentheses and type conversions:
// uintptr(pid) is pid.
func unconverted(expr ast.Expr, info *types.Info) ast.Expr {
	for {
		call, ok := ast.Unparen(expr).(*ast.CallExpr)
		if !ok || len(call.Args) != 1 || !info.Types[call.Fun].IsType() {
			return ast.Unparen(expr)
		}
		expr = call.Args[0]
	}
}

func isProcessID(expr ast.Expr, info *types.Info, parent bool) bool {
	if info == nil {
		return false
	}
	call, ok := unconverted(expr, info).(*ast.CallExpr)
	if !ok {
		return false
	}
	name := "Getpid"
	if parent {
		name = "Getppid"
	}
	return patternkit.IsPkgFunc(info, call, "os", name) || patternkit.IsPkgFunc(info, call, "syscall", name) || patternkit.IsPkgFunc(info, call, "golang.org/x/sys/unix", name)
}

func isCurrentProcessID(expr ast.Expr, info *types.Info) bool { return isProcessID(expr, info, false) }
func isParentProcessID(expr ast.Expr, info *types.Info) bool  { return isProcessID(expr, info, true) }

// isOwnProcessGroup reports the caller's process group: Getpgrp(), or
// Getpgid of 0 or of its own PID.
func isOwnProcessGroup(expr ast.Expr, info *types.Info) bool {
	call, ok := unconverted(expr, info).(*ast.CallExpr)
	if !ok {
		return false
	}
	fn := helpers.CalledFunc(call, info)
	if fn == nil || fn.Pkg() == nil || !signalPackages[fn.Pkg().Path()] {
		return false
	}
	switch fn.Name() {
	case "Getpgrp":
		return true
	case "Getpgid":
		if len(call.Args) != 1 {
			return false
		}
		value, known := pidValue(call.Args[0], info)
		return known && value == 0 || isCurrentProcessID(call.Args[0], info)
	}
	return false
}

func findProcessFor(expr ast.Expr, info *types.Info, target processIDPredicate, pids map[types.Object]bool) bool {
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok {
		return false
	}
	return patternkit.IsPkgFunc(info, call, "os", "FindProcess") && len(call.Args) > 0 && (target(call.Args[0], info) || pidsFrom(call.Args[0], info, pids))
}

// processAliases are the variables that hold the PIDs and the handles of a
// process; Groups, of the parent aliases only, those that hold the caller's
// process group.
type processAliases struct {
	PIDs    map[types.Object]bool
	Handles map[types.Object]bool
	Groups  map[types.Object]bool
}

// aliasWrites holds every value written to a variable; nil is a write whose
// value is unknown (a second result, ++, range, its address taken), and
// declaredWithoutValue the zero value of a declaration without one.
type aliasWrites map[types.Object][]ast.Expr

// declaredWithoutValue is the write of a declaration without value: a value
// unknown to a PID, no write at all to a function variable, nil until
// written, since a call through nil panics.
var declaredWithoutValue ast.Expr = &ast.BadExpr{}

// withoutZeroValues drops the declarations without value from writes.
func withoutZeroValues(writes aliasWrites) aliasWrites {
	out := make(aliasWrites, len(writes))
	for obj, values := range writes {
		var kept []ast.Expr
		for _, value := range values {
			if value != declaredWithoutValue {
				kept = append(kept, value)
			}
		}
		if len(kept) > 0 {
			out[obj] = kept
		}
	}
	return out
}

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
			values := n.Values
			if len(values) == 0 {
				values = slices.Repeat([]ast.Expr{declaredWithoutValue}, len(names))
			}
			add(names, values)
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
	out := processAliases{PIDs: maps.Clone(base.PIDs), Handles: maps.Clone(base.Handles), Groups: maps.Clone(base.Groups)}
	if out.PIDs == nil {
		out.PIDs, out.Handles, out.Groups = make(map[types.Object]bool), make(map[types.Object]bool), make(map[types.Object]bool)
	}
	resolveAliases(writes, out.PIDs, func(e ast.Expr) bool { return target(e, info) || pidsFrom(e, info, out.PIDs) })
	resolveAliases(writes, out.Handles, func(e ast.Expr) bool {
		return findProcessFor(e, info, target, out.PIDs) || pidsFrom(e, info, out.Handles)
	})
	return out
}
