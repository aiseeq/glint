package shellrules

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"slices"
	"sort"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

const rawProcessKillSuggestion = "Use proc.StopChild from github.com/aiseeq/akit/proc; pass the request (signal, stdin close, or context cancellation) in its request function literal."
const rawCommandContextSuggestion = "Call proc.CancelByStop(cmd, grace, syscall.SIGTERM) from github.com/aiseeq/akit/proc before Start/Run and check its error; it sets cmd.Cancel. Split a chained exec.CommandContext(...).Run() into a variable first. On context cancellation, os/exec calls Process.Kill by default."

var rawHarmlessSignalNumbers = map[string]bool{
	"1": true, "10": true, "12": true, "19": true, "20": true, "21": true, "22": true,
}

type rawProcessKillRule struct{ *rules.BaseRule }

func init() { rules.Register(newRawProcessKillRule()) }

func newRawProcessKillRule() *rawProcessKillRule {
	return &rawProcessKillRule{rules.NewBaseRule("raw-process-kill", "patterns", "Detects process termination signals sent outside the approved child process helper", core.SeverityMedium)}
}

// AnalyzeFile is not called: the rule reads Go through AnalyzeGoProject.
func (r *rawProcessKillRule) AnalyzeFile(*core.FileContext) []*core.Violation { return nil }

func (r *rawProcessKillRule) RequiresSSA() bool { return false }

func (r *rawProcessKillRule) AnalyzeGoProject(project *core.GoProjectContext) ([]*core.Violation, error) {
	return analyzeSignalProject(project, r.analyzeGo)
}

func (r *rawProcessKillRule) ReportsOn(ctx *core.FileContext) bool { return ctx.IsGoFile() }

func (r *rawProcessKillRule) analyzeGo(file *core.FileContext, pkg *signalPackage) []*core.Violation {
	if pkg == nil || pkg.path == akitProcPath {
		return nil
	}
	var findings []*core.Violation
	findings = append(findings, commandContextKillFindings(r, file, pkg)...)
	for _, site := range fileSignalSites(file, pkg) {
		if site.request || site.implicitTarget() || site.toSelf() || harmlessSignal(site.signal(), site.info) || rawHarmlessSignalNumbers[iValue(site.signal(), site.info)] {
			continue
		}
		line := file.LineFor(site.node)
		if file.IsSuppressed(line, r.Name()) {
			continue
		}
		callee := site.node
		if call, ok := site.node.(*ast.CallExpr); ok {
			callee = call.Fun
		}
		message := fmt.Sprintf("Call to %s sends a process-termination signal outside the approved child stopper; use proc.StopChild from github.com/aiseeq/akit/proc and pass the request in its function literal", types.ExprString(callee))
		v := r.CreateViolation(file.RelPath, line, message)
		v.WithCode(strings.TrimSpace(file.GetLine(line)))
		v.WithSuggestion(rawProcessKillSuggestion)
		findings = append(findings, v)
	}
	sort.SliceStable(findings, func(i, j int) bool { return findings[i].Line < findings[j].Line })
	return findings
}

func commandContextKillFindings(r *rawProcessKillRule, file *core.FileContext, pkg *signalPackage) []*core.Violation {
	var findings []*core.Violation
	if pkg == nil || pkg.info == nil || file.GoAST == nil {
		return findings
	}
	for _, decl := range file.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && fn.Body != nil {
			commandContextInFunction(r, file, pkg.info, fn.Body, &findings)
		}
	}
	ast.Inspect(file.GoAST, func(node ast.Node) bool {
		lit, ok := node.(*ast.FuncLit)
		if ok {
			commandContextInFunction(r, file, pkg.info, lit.Body, &findings)
		}
		return true
	})
	return findings
}

func commandContextInFunction(r *rawProcessKillRule, file *core.FileContext, info *types.Info, body *ast.BlockStmt, findings *[]*core.Violation) {
	if body == nil || info == nil {
		return
	}
	var constructors []*ast.CallExpr
	ast.Inspect(body, func(node ast.Node) bool {
		if _, nested := node.(*ast.FuncLit); nested {
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		if isExecCommandContext(call, info) {
			constructors = append(constructors, call)
		}
		return true
	})
	for _, constructor := range constructors {
		if nonCancelingCommandContext(constructor, info) {
			continue
		}
		target := commandContextAssignedTarget(constructor, body, info)
		terminal := commandContextTerminal(constructor, target, constructors, body, info)
		if terminal == nil {
			continue
		}
		if target != nil && commandContextConfiguredOrEscapes(target, constructor.End(), commandContextTerminalPos(terminal), terminal, body, info) {
			continue
		}
		line := file.LineFor(constructor)
		if file.IsSuppressed(line, r.Name()) {
			continue
		}
		v := r.CreateViolation(file.RelPath, line, rawCommandContextSuggestion)
		v.WithCode(strings.TrimSpace(file.GetLine(line)))
		v.WithSuggestion(rawCommandContextSuggestion)
		*findings = append(*findings, v)
	}
}

func isExecCommandContext(call *ast.CallExpr, info *types.Info) bool {
	selector, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "CommandContext" {
		return false
	}
	fn, ok := info.Uses[selector.Sel].(*types.Func)
	return ok && fn.Pkg() != nil && fn.Pkg().Path() == "os/exec" && fn.Name() == "CommandContext"
}

func isCommandTerminal(name string) bool {
	switch name {
	case "Start", "Run", "Output", "CombinedOutput":
		return true
	default:
		return false
	}
}

func commandContextAssignedTarget(constructor *ast.CallExpr, body *ast.BlockStmt, info *types.Info) ast.Expr {
	var target ast.Expr
	ast.Inspect(body, func(node ast.Node) bool {
		if target != nil {
			return false
		}
		switch stmt := node.(type) {
		case *ast.AssignStmt:
			for i, rhs := range stmt.Rhs {
				if rhs == constructor && i < len(stmt.Lhs) {
					target = stmt.Lhs[i]
					return false
				}
				if i < len(stmt.Lhs) && containsNode(rhs, constructor) {
					target = compositeCommandTarget(stmt.Lhs[i], rhs, constructor, info)
					if target != nil {
						return false
					}
				}
			}
		case *ast.ValueSpec:
			for i, rhs := range stmt.Values {
				if rhs == constructor && i < len(stmt.Names) {
					target = stmt.Names[i]
					return false
				}
				if i < len(stmt.Names) && containsNode(rhs, constructor) {
					target = compositeCommandTarget(stmt.Names[i], rhs, constructor, info)
					if target != nil {
						return false
					}
				}
			}
		}
		return true
	})
	return target
}

func compositeCommandTarget(base, value ast.Expr, constructor *ast.CallExpr, info *types.Info) ast.Expr {
	var target ast.Expr
	ast.Inspect(value, func(node ast.Node) bool {
		if target != nil {
			return false
		}
		lit, ok := node.(*ast.CompositeLit)
		if !ok {
			return true
		}
		for i, elt := range lit.Elts {
			if !containsNode(elt, constructor) {
				continue
			}
			if pair, ok := elt.(*ast.KeyValueExpr); ok {
				switch key := ast.Unparen(pair.Key).(type) {
				case *ast.Ident:
					if _, ok := compositeLiteralStruct(lit, info); ok {
						target = &ast.SelectorExpr{X: base, Sel: key}
					} else {
						target = &ast.IndexExpr{X: base, Index: pair.Key}
					}
				default:
					target = &ast.IndexExpr{X: base, Index: pair.Key}
				}
			} else {
				if structure, ok := compositeLiteralStruct(lit, info); ok && i < structure.NumFields() {
					target = &ast.SelectorExpr{X: base, Sel: ast.NewIdent(structure.Field(i).Name())}
				} else {
					idx := &ast.BasicLit{Kind: token.INT, Value: fmt.Sprint(i)}
					target = &ast.IndexExpr{X: base, Index: idx}
				}
			}
			return false
		}
		return true
	})
	return target
}

func compositeLiteralStruct(lit *ast.CompositeLit, info *types.Info) (*types.Struct, bool) {
	if lit == nil || info == nil {
		return nil, false
	}
	typ := info.TypeOf(lit)
	if typ == nil {
		return nil, false
	}
	if pointer, ok := typ.(*types.Pointer); ok {
		typ = pointer.Elem()
	}
	structure, ok := typ.Underlying().(*types.Struct)
	return structure, ok
}

func containsNode(node, target ast.Node) bool {
	found := false
	ast.Inspect(node, func(n ast.Node) bool {
		if n == target {
			found = true
			return false
		}
		return !found
	})
	return found
}

func commandContextTerminal(constructor *ast.CallExpr, target ast.Expr, constructors []*ast.CallExpr, body *ast.BlockStmt, info *types.Info) *ast.CallExpr {
	var first *ast.CallExpr
	ast.Inspect(body, func(node ast.Node) bool {
		if _, nested := node.(*ast.FuncLit); nested {
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
		if !ok || !isCommandTerminal(selector.Sel.Name) || selector.Sel.Pos() <= constructor.End() {
			return true
		}
		matches := false
		receiver := ast.Unparen(selector.X)
		if direct, ok := receiver.(*ast.CallExpr); ok {
			matches = direct == constructor
		} else if target != nil {
			matches = commandContextExprMatches(receiver, commandContextAliases(target, constructor.End(), selector.Sel.Pos(), body, info), info)
		}
		if !matches {
			return true
		}
		for _, other := range constructors {
			if other == constructor || other.Pos() <= constructor.End() || other.Pos() >= selector.Sel.Pos() {
				continue
			}
			if sameCommandExpr(commandContextAssignedTarget(other, body, info), target, info) &&
				!commandContextInDifferentIfBranches(constructor, other, body) {
				return true
			}
		}
		if first == nil || selector.Sel.Pos() < commandContextTerminalPos(first) {
			first = call
		}
		return true
	})
	return first
}

func commandContextInDifferentIfBranches(first, second ast.Node, body *ast.BlockStmt) bool {
	different := false
	ast.Inspect(body, func(node ast.Node) bool {
		if different {
			return false
		}
		statement, ok := node.(*ast.IfStmt)
		if !ok || statement.Else == nil {
			return true
		}
		firstThen, secondThen := containsNode(statement.Body, first), containsNode(statement.Body, second)
		firstElse, secondElse := containsNode(statement.Else, first), containsNode(statement.Else, second)
		different = (firstThen && secondElse) || (secondThen && firstElse)
		return !different
	})
	return different
}

func commandContextTerminalPos(call *ast.CallExpr) token.Pos {
	selector, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok {
		return call.Pos()
	}
	return selector.Sel.Pos()
}

func commandContextConfiguredOrEscapes(target ast.Expr, after, before token.Pos, terminal *ast.CallExpr, body *ast.BlockStmt, info *types.Info) bool {
	aliases := commandContextAliases(target, after, before, body, info)
	configured := false
	ast.Inspect(body, func(node ast.Node) bool {
		if configured {
			return false
		}
		switch n := node.(type) {
		case *ast.FuncLit:
			if closureCalledBefore(n, body, after, before, info) && cancelAssignmentIn(n.Body, aliases, before, info) {
				configured = true
			}
			return false
		case *ast.AssignStmt:
			if n.Pos() > after && n.Pos() < before && cancelAssignment(n, aliases, info) {
				configured = true
			}
		case *ast.CallExpr:
			if n == terminal || n.Pos() <= after || n.Pos() >= before {
				return true
			}
			for _, arg := range n.Args {
				if commandContextArgumentMatches(arg, aliases, info) {
					configured = true
					break
				}
			}
			if !configured && commandContextOwnerPassed(n, target, info) {
				configured = true
			}
		}
		return true
	})
	return configured
}

func commandContextOwnerPassed(call *ast.CallExpr, target ast.Expr, info *types.Info) bool {
	field, ok := ast.Unparen(target).(*ast.SelectorExpr)
	if !ok {
		return false
	}
	owner := field.X
	if selector, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr); ok && sameCommandExpr(selector.X, owner, info) {
		return true
	}
	for _, arg := range call.Args {
		if commandContextArgumentMatches(arg, []ast.Expr{owner}, info) {
			return true
		}
	}
	return false
}

func cancelAssignmentIn(body *ast.BlockStmt, aliases []ast.Expr, before token.Pos, info *types.Info) bool {
	found := false
	ast.Inspect(body, func(node ast.Node) bool {
		if found {
			return false
		}
		if stmt, ok := node.(*ast.AssignStmt); ok && stmt.Pos() < before && cancelAssignment(stmt, aliases, info) {
			found = true
			return false
		}
		return true
	})
	return found
}

func cancelAssignment(stmt *ast.AssignStmt, aliases []ast.Expr, info *types.Info) bool {
	for _, lhs := range stmt.Lhs {
		selector, ok := ast.Unparen(lhs).(*ast.SelectorExpr)
		if ok && selector.Sel.Name == "Cancel" && commandContextExprMatches(selector.X, aliases, info) {
			return true
		}
	}
	return false
}

func commandContextArgumentMatches(arg ast.Expr, aliases []ast.Expr, info *types.Info) bool {
	arg = ast.Unparen(arg)
	if address, ok := arg.(*ast.UnaryExpr); ok && address.Op == token.AND {
		arg = ast.Unparen(address.X)
	}
	return commandContextExprMatches(arg, aliases, info)
}

func commandContextAliases(target ast.Expr, after, before token.Pos, body *ast.BlockStmt, info *types.Info) []ast.Expr {
	if target == nil {
		return nil
	}
	aliases := []ast.Expr{target}
	add := func(expr ast.Expr) bool {
		if expr == nil {
			return false
		}
		for _, current := range aliases {
			if sameCommandExpr(expr, current, info) {
				return false
			}
		}
		aliases = append(aliases, expr)
		return true
	}
	for changed := true; changed; {
		changed = false
		ast.Inspect(body, func(node ast.Node) bool {
			if _, nested := node.(*ast.FuncLit); nested {
				return false
			}
			switch stmt := node.(type) {
			case *ast.AssignStmt:
				if stmt.Pos() <= after || stmt.Pos() >= before {
					return true
				}
				for i, rhs := range stmt.Rhs {
					if i < len(stmt.Lhs) && commandContextExprMatches(rhs, aliases, info) {
						changed = add(stmt.Lhs[i]) || changed
					}
				}
			case *ast.ValueSpec:
				if stmt.Pos() <= after || stmt.Pos() >= before {
					return true
				}
				for i, rhs := range stmt.Values {
					if i < len(stmt.Names) && commandContextExprMatches(rhs, aliases, info) {
						changed = add(stmt.Names[i]) || changed
					}
				}
			case *ast.RangeStmt:
				if stmt.Pos() <= after || stmt.Pos() >= before {
					return true
				}
				for _, alias := range aliases {
					if index, ok := ast.Unparen(alias).(*ast.IndexExpr); ok && sameCommandExpr(index.X, stmt.X, info) {
						if id, ok := ast.Unparen(stmt.Value).(*ast.Ident); ok {
							changed = add(id) || changed
						}
					}
				}
			}
			return true
		})
	}
	return aliases
}

func commandContextExprMatches(expr ast.Expr, aliases []ast.Expr, info *types.Info) bool {
	for _, alias := range aliases {
		if sameCommandExpr(expr, alias, info) {
			return true
		}
	}
	return false
}

func sameCommandExpr(left, right ast.Expr, info *types.Info) bool {
	left, right = ast.Unparen(left), ast.Unparen(right)
	if left == nil || right == nil {
		return false
	}
	switch l := left.(type) {
	case *ast.Ident:
		r, ok := right.(*ast.Ident)
		return ok && objectForExpr(l, info) != nil && objectForExpr(l, info) == objectForExpr(r, info)
	case *ast.SelectorExpr:
		r, ok := right.(*ast.SelectorExpr)
		if !ok || l.Sel.Name != r.Sel.Name || !sameCommandExpr(l.X, r.X, info) {
			return false
		}
		leftObject, rightObject := selectorObject(l, info), selectorObject(r, info)
		return leftObject == nil || rightObject == nil || leftObject == rightObject
	case *ast.IndexExpr:
		r, ok := right.(*ast.IndexExpr)
		return ok && sameCommandExpr(l.X, r.X, info) && types.ExprString(l.Index) == types.ExprString(r.Index)
	case *ast.UnaryExpr:
		r, ok := right.(*ast.UnaryExpr)
		if ok && (l.Op == token.AND || l.Op == token.MUL) && l.Op == r.Op {
			return sameCommandExpr(l.X, r.X, info)
		}
		return (l.Op == token.AND || l.Op == token.MUL) && sameCommandExpr(l.X, right, info)
	default:
		return false
	}
}

func selectorObject(selector *ast.SelectorExpr, info *types.Info) types.Object {
	if selection := info.Selections[selector]; selection != nil {
		return selection.Obj()
	}
	return info.Uses[selector.Sel]
}

func objectForExpr(expr ast.Expr, info *types.Info) types.Object {
	id, ok := ast.Unparen(expr).(*ast.Ident)
	if !ok {
		return nil
	}
	if obj := info.Uses[id]; obj != nil {
		return obj
	}
	return info.Defs[id]
}

func closureCalledBefore(lit *ast.FuncLit, body *ast.BlockStmt, after, before token.Pos, info *types.Info) bool {
	var objects []types.Object
	ast.Inspect(body, func(node ast.Node) bool {
		switch stmt := node.(type) {
		case *ast.AssignStmt:
			for i, rhs := range stmt.Rhs {
				if rhs == lit && i < len(stmt.Lhs) {
					if obj := objectForExpr(stmt.Lhs[i], info); obj != nil {
						objects = append(objects, obj)
					}
				}
			}
		case *ast.ValueSpec:
			for i, rhs := range stmt.Values {
				if rhs == lit && i < len(stmt.Names) {
					if obj := objectForExpr(stmt.Names[i], info); obj != nil {
						objects = append(objects, obj)
					}
				}
			}
		}
		return true
	})
	called := false
	ast.Inspect(body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok || call.Pos() <= after || call.Pos() >= before {
			return !called
		}
		if commandContextIsDeferredCall(call, body) {
			return true
		}
		if call.Fun == lit {
			called = true
			return false
		}
		if obj := objectForExpr(call.Fun, info); obj != nil {
			if slices.Contains(objects, obj) {
				called = true
				return false
			}
		}
		return true
	})
	return called
}

func commandContextIsDeferredCall(call *ast.CallExpr, body *ast.BlockStmt) bool {
	deferred := false
	ast.Inspect(body, func(node ast.Node) bool {
		if statement, ok := node.(*ast.DeferStmt); ok && statement.Call == call {
			deferred = true
			return false
		}
		return !deferred
	})
	return deferred
}

func nonCancelingCommandContext(constructor *ast.CallExpr, info *types.Info) bool {
	if len(constructor.Args) == 0 {
		return false
	}
	call, ok := ast.Unparen(constructor.Args[0]).(*ast.CallExpr)
	if !ok {
		return false
	}
	selector, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "Background" && selector.Sel.Name != "TODO" {
		return false
	}
	fn, ok := info.Uses[selector.Sel].(*types.Func)
	return ok && fn.Pkg() != nil && fn.Pkg().Path() == "context"
}
