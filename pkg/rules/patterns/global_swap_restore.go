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
	rules.Register(NewGlobalSwapRestoreRule())
}

// GlobalSwapRestoreRule detects a package variable swapped for the length of
// one call and put back:
//
//	old := defaultLimits
//	defaultLimits = v.limits
//	ok := Check(amount)          // reads defaultLimits
//	defaultLimits = old
//
// It works while one goroutine runs the code. Two requests at once each save
// the other's value and restore the wrong one; in between Check of one
// request runs with the other's limits, and the default stays changed for
// every later caller. Pass the value to the call instead (CheckWith(limits,
// amount)). Test files are not checked: a test swapping a global for its own
// run is the usual way to stub one.
type GlobalSwapRestoreRule struct {
	*rules.BaseRule
}

// NewGlobalSwapRestoreRule creates the rule
func NewGlobalSwapRestoreRule() *GlobalSwapRestoreRule {
	return &GlobalSwapRestoreRule{BaseRule: rules.NewBaseRule(
		"global-swap-restore",
		"patterns",
		"Detects a package variable saved, replaced for one call and restored — concurrent callers see each other's value and the restore loses one",
		core.SeverityHigh,
	)}
}

// AnalyzeFile is a no-op: a variable of another file is resolved through
// the package's types.
func (r *GlobalSwapRestoreRule) AnalyzeFile(_ *core.FileContext) []*core.Violation { return nil }

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *GlobalSwapRestoreRule) RequiresSSA() bool { return false }

// AnalyzeGoProject reports the swaps of package variables in production code.
func (r *GlobalSwapRestoreRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	return rules.AnalyzeGoFiles(ctx, r.Name(), func(file *core.FileContext, info *types.Info) []*core.Violation {
		if file.IsTestFile() {
			return nil
		}
		var violations []*core.Violation
		ast.Inspect(file.GoAST, func(n ast.Node) bool {
			block, ok := n.(*ast.BlockStmt)
			if !ok {
				return true
			}
			for _, swap := range globalSwaps(block.List, file.GoAST, info) {
				line := file.LineFor(swap.stmt)
				if file.IsSuppressed(line, r.Name()) {
					continue
				}
				v := r.CreateViolation(file.RelPath, line, fmt.Sprintf(
					"Package variable %s swapped for one call and restored from %s — concurrent callers see each other's value, and the restore can put back the wrong one",
					swap.global, swap.saved))
				v.WithCode(strings.TrimSpace(file.GetLine(line)))
				v.WithSuggestion(fmt.Sprintf("Pass the value to the code that reads %s instead of changing the package variable", swap.global))
				violations = append(violations, v)
			}
			return true
		})
		return violations
	})
}

// globalSwap is an assignment that replaces a saved package variable.
type globalSwap struct {
	stmt   ast.Stmt
	global string // how the code spells the variable
	saved  string // the local holding its old value
}

// pendingSwap follows one saved package variable down a statement list.
type pendingSwap struct {
	globalSwap
	restored bool
}

// globalSwaps finds, in one statement list, `old := G` followed by `G = x`
// and a restore `G = old` after it or in a defer.
func globalSwaps(list []ast.Stmt, file *ast.File, info *types.Info) []globalSwap {
	saves := make(map[any]*pendingSwap)
	var order []*pendingSwap
	for _, stmt := range list {
		switch s := stmt.(type) {
		case *ast.DeferStmt:
			ast.Inspect(s, func(n ast.Node) bool {
				assign, ok := n.(*ast.AssignStmt)
				if !ok {
					return true
				}
				if target, rhs, ok := globalAssignment(assign, file, info); ok {
					if p := saves[target]; p != nil && isIdent(rhs, p.saved) {
						p.restored = true
					}
				}
				return true
			})
		case *ast.AssignStmt:
			if global, saved, ok := globalSave(s, file, info); ok {
				p := &pendingSwap{globalSwap: globalSwap{global: types.ExprString(s.Rhs[0]), saved: saved}}
				saves[global] = p
				order = append(order, p)
				continue
			}
			target, rhs, ok := globalAssignment(s, file, info)
			p := saves[target]
			if !ok || p == nil {
				continue
			}
			switch {
			case !isIdent(rhs, p.saved):
				if p.stmt == nil {
					p.stmt = s
				}
			case p.stmt != nil:
				p.restored = true
			}
		}
	}
	var swaps []globalSwap
	for _, p := range order {
		if p.stmt != nil && p.restored {
			swaps = append(swaps, p.globalSwap)
		}
	}
	return swaps
}

// globalSave matches `old := G` and returns G and the local's name.
func globalSave(assign *ast.AssignStmt, file *ast.File, info *types.Info) (any, string, bool) {
	if assign.Tok != token.DEFINE || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
		return nil, "", false
	}
	saved, ok := assign.Lhs[0].(*ast.Ident)
	if !ok || saved.Name == "_" {
		return nil, "", false
	}
	global, ok := packageVariable(assign.Rhs[0], file, info)
	return global, saved.Name, ok
}

// globalAssignment matches `G = x` and returns G and x.
func globalAssignment(assign *ast.AssignStmt, file *ast.File, info *types.Info) (any, ast.Expr, bool) {
	if assign.Tok != token.ASSIGN || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
		return nil, nil, false
	}
	target, ok := packageVariable(assign.Lhs[0], file, info)
	return target, assign.Rhs[0], ok
}

// packageVariable resolves an identifier or a qualified name to a package
// variable: its types.Object when the file is typed, its declaration in the
// file otherwise.
func packageVariable(expr ast.Expr, file *ast.File, info *types.Info) (any, bool) {
	var ident *ast.Ident
	switch e := ast.Unparen(expr).(type) {
	case *ast.Ident:
		ident = e
	case *ast.SelectorExpr:
		if info == nil {
			return nil, false // a qualified name needs the other package's types
		}
		ident = e.Sel
	default:
		return nil, false
	}
	if info != nil {
		v, ok := info.Uses[ident].(*types.Var)
		if !ok || v.IsField() || v.Pkg() == nil || v.Parent() != v.Pkg().Scope() {
			return nil, false
		}
		return v, true
	}
	if ident.Obj == nil || ident.Obj.Kind != ast.Var {
		return nil, false
	}
	spec, ok := ident.Obj.Decl.(*ast.ValueSpec)
	if !ok || !topLevelSpec(file, spec) {
		return nil, false
	}
	return ident.Obj, true
}

// topLevelSpec reports a var spec declared at the top of the file.
func topLevelSpec(file *ast.File, spec *ast.ValueSpec) bool {
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.VAR {
			continue
		}
		for _, s := range gen.Specs {
			if s == spec {
				return true
			}
		}
	}
	return false
}
