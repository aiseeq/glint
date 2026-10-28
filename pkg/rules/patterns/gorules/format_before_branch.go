package gorules

import (
	"go/ast"
	"go/token"
	"go/types"
	"slices"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
)

func init() {
	rules.Register(NewFormatBeforeBranchRule())
}

// costlyFormatters are the calls that build a string or bytes for output:
// worth doing only when the output happens.
var costlyFormatters = []struct {
	pkg   string
	names []string
}{
	{"fmt", []string{"Sprintf", "Sprint", "Sprintln", "Errorf"}},
	{"strings", []string{"Join"}},
	{"encoding/json", []string{"Marshal", "MarshalIndent"}},
}

// NewFormatBeforeBranchRule creates format-before-branch: a string or bytes
// built by fmt.Sprintf, fmt.Errorf, strings.Join or json.Marshal into a
// local that only one branch of the next if or switch uses - usually the
// error, the debug or the rare case. The work runs on every call and is
// thrown away whenever the branch is not taken:
//
//	msg := fmt.Sprintf("charge %d on %d", a.Tag, t.Tag)
//	if dmg < 0 { return fmt.Errorf("%s: damage %d", msg, dmg) }
//	if dmg < 0 { return fmt.Errorf("charge %d on %d: damage %d", a.Tag, t.Tag, dmg) }
//
// Not reported: a value the condition reads; arguments that are called or
// that change, are passed on or have a method called between the assignment
// and the branch (the value is a snapshot); a branch that is not the next
// statement of the same block, so moving the work in could run it more
// often. A default formatted and then refined by the next if (name :=
// fmt.Sprint(id); if x, ok := names[id]; ok { name = x }) is reported only
// in a loop or a hot function: in code that runs once it is the readable
// idiom. The finding is low in ordinary code and medium in a //glint:hot
// function.
func NewFormatBeforeBranchRule() *patternkit.TypedFuncRule {
	r := &patternkit.TypedFuncRule{
		BaseRule: rules.NewBaseRule(
			"format-before-branch",
			"patterns",
			"Detects a string built by fmt.Sprintf/Errorf, strings.Join or json.Marshal before an if or switch whose one branch is its only user — the formatting runs on every call and is thrown away when the branch is not taken; build it inside the branch",
			core.SeverityLow,
		),
		Suggestion: "Move the formatting into the branch that uses it (or inline it into the call there)",
		SeverityOf: patternkit.HotRaisesSeverity,
	}
	r.Check = func(scope patternkit.FuncScope, fn *ast.FuncDecl) []patternkit.FuncFinding {
		hot := patternkit.HasDirective(fn.Doc, patternkit.HotFunctionDirective)
		loops := patternkit.LoopBodies(fn.Body)
		var findings []patternkit.FuncFinding
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			var list []ast.Stmt
			switch block := n.(type) {
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
				if what := formatOnlyForBranch(scope.Info, fn, list, i, stmt); what != "" {
					findings = append(findings, patternkit.FuncFinding{Node: stmt, Message: what + " runs on every call, while only one branch below uses the result — build it inside that branch"})
				} else if what := formatOverwrittenByBranch(scope.Info, list, i, stmt); what != "" && (hot || patternkit.InsideNodes(loops, stmt)) {
					findings = append(findings, patternkit.FuncFinding{Node: stmt, Message: what + " runs on every call, while the branch below overwrites the result before reading it — build it in the else"})
				}
			}
			return true
		})
		return findings
	}
	return r
}

// formatOnlyForBranch names the formatting call of list[i] when its result
// is used only inside one branch of a later if or switch of the same list.
func formatOnlyForBranch(info *types.Info, fn *ast.FuncDecl, list []ast.Stmt, i int, stmt ast.Stmt) string {
	assign, ok := stmt.(*ast.AssignStmt)
	if !ok || assign.Tok != token.DEFINE || len(assign.Rhs) != 1 {
		return ""
	}
	call, ok := ast.Unparen(assign.Rhs[0]).(*ast.CallExpr)
	if !ok {
		return ""
	}
	what := costlyFormatterName(info, call)
	if what == "" || callsInArgs(info, call) {
		return ""
	}
	var defined []types.Object
	for _, lhs := range assign.Lhs {
		if ident, isIdent := lhs.(*ast.Ident); isIdent && info.Defs[ident] != nil {
			defined = append(defined, info.Defs[ident])
		}
	}
	uses := patternkit.UsesOf(info, fn.Body, defined)
	if len(uses) == 0 {
		return ""
	}
	j := slices.IndexFunc(list, func(s ast.Stmt) bool { return s.Pos() <= uses[0].Pos() && uses[0].End() <= s.End() })
	if j <= i {
		return ""
	}
	body := branchHolding(list[j], uses)
	if body == nil {
		return ""
	}
	between := append(slices.Clone(list[i+1:j]), branchHeader(list[j])...)
	if argsTouched(info, call, between) {
		return ""
	}
	return what
}

// formatOverwrittenByBranch names the formatting call of list[i] when the
// next statement is an if whose body assigns the variable anew before any
// read of it: the formatted value is used only when the branch is not
// taken.
//
//	name := fmt.Sprint(typ)
//	if x, ok := names[typ]; ok { name = x }
func formatOverwrittenByBranch(info *types.Info, list []ast.Stmt, i int, stmt ast.Stmt) string {
	assign, ok := stmt.(*ast.AssignStmt)
	if !ok || assign.Tok != token.DEFINE || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 || i+1 >= len(list) {
		return ""
	}
	call, ok := ast.Unparen(assign.Rhs[0]).(*ast.CallExpr)
	if !ok {
		return ""
	}
	what := costlyFormatterName(info, call)
	ident, isIdent := assign.Lhs[0].(*ast.Ident)
	branch, isIf := list[i+1].(*ast.IfStmt)
	if what == "" || !isIdent || !isIf || info.Defs[ident] == nil || callsInArgs(info, call) || argsTouched(info, call, branchHeader(branch)) {
		return ""
	}
	obj := []types.Object{info.Defs[ident]}
	for _, header := range branchHeader(branch) {
		if len(patternkit.UsesOf(info, header, obj)) > 0 {
			return ""
		}
	}
	for _, s := range branch.Body.List {
		if again, isAssign := s.(*ast.AssignStmt); isAssign && again.Tok == token.ASSIGN && len(again.Lhs) == 1 && len(again.Rhs) == 1 {
			if target, isTarget := again.Lhs[0].(*ast.Ident); isTarget && info.Uses[target] == obj[0] {
				if len(patternkit.UsesOf(info, again.Rhs[0], obj)) > 0 {
					return ""
				}
				return what
			}
		}
		if len(patternkit.UsesOf(info, s, obj)) > 0 {
			return ""
		}
	}
	return ""
}

// costlyFormatterName names a call of costlyFormatters, "" for any other.
func costlyFormatterName(info *types.Info, call *ast.CallExpr) string {
	for _, f := range costlyFormatters {
		if name, ok := patternkit.PackageFuncName(nil, info, call, f.pkg); ok && slices.Contains(f.names, name) {
			return types.ExprString(call.Fun)
		}
	}
	return ""
}

// callsInArgs reports an argument that calls something other than a builtin
// or a conversion: the call may have a side effect the move would reorder.
func callsInArgs(info *types.Info, call *ast.CallExpr) bool {
	found := false
	for _, arg := range call.Args {
		ast.Inspect(arg, func(n ast.Node) bool {
			inner, ok := n.(*ast.CallExpr)
			if !ok || found {
				return !found
			}
			if tv, typed := info.Types[inner.Fun]; typed && tv.IsType() {
				return true
			}
			found = patternkit.BuiltinCallName(info, inner) == ""
			return !found
		})
	}
	return found
}

// branchHolding returns the branch body of an if or switch statement that
// holds every use, nil when the uses are not all in one branch body.
func branchHolding(stmt ast.Stmt, uses []*ast.Ident) ast.Node {
	for _, body := range branchBodies(stmt) {
		if all(uses, func(u *ast.Ident) bool { return body.Pos() <= u.Pos() && u.End() <= body.End() }) {
			return body
		}
	}
	return nil
}

// all reports whether every item satisfies ok.
func all[T any](items []T, ok func(T) bool) bool {
	return !slices.ContainsFunc(items, func(item T) bool { return !ok(item) })
}

// branchBodies returns the bodies of the branches of an if chain or a
// switch.
func branchBodies(stmt ast.Stmt) []ast.Node {
	switch s := stmt.(type) {
	case *ast.IfStmt:
		bodies := []ast.Node{s.Body}
		switch e := s.Else.(type) {
		case *ast.BlockStmt:
			bodies = append(bodies, e)
		case *ast.IfStmt:
			bodies = append(bodies, branchBodies(e)...)
		}
		return bodies
	case *ast.SwitchStmt:
		return clauseBodies(s.Body)
	case *ast.TypeSwitchStmt:
		return clauseBodies(s.Body)
	}
	return nil
}

// clauseBodies returns the case clauses of a switch body.
func clauseBodies(body *ast.BlockStmt) []ast.Node {
	var bodies []ast.Node
	for _, clause := range body.List {
		if cc, ok := clause.(*ast.CaseClause); ok {
			bodies = append(bodies, &ast.BlockStmt{Lbrace: cc.Colon, List: cc.Body, Rbrace: cc.End()})
		}
	}
	return bodies
}

// branchHeader returns the parts of an if or switch that run before its
// branch: the init statement and the condition or tag.
func branchHeader(stmt ast.Stmt) []ast.Stmt {
	var header []ast.Stmt
	add := func(init ast.Stmt, cond ast.Expr) {
		if init != nil {
			header = append(header, init)
		}
		if cond != nil {
			header = append(header, &ast.ExprStmt{X: cond})
		}
	}
	switch s := stmt.(type) {
	case *ast.IfStmt:
		add(s.Init, s.Cond)
	case *ast.SwitchStmt:
		add(s.Init, s.Tag)
	case *ast.TypeSwitchStmt:
		add(s.Init, nil)
	}
	return header
}

// argsTouched reports whether a statement between the formatting and its
// branch may change what the formatting read: an argument's variable is
// assigned, incremented, has its address taken, is passed to a call or has
// a method called.
func argsTouched(info *types.Info, call *ast.CallExpr, between []ast.Stmt) bool {
	var args []types.Object
	for _, arg := range call.Args {
		ast.Inspect(arg, func(n ast.Node) bool {
			if ident, ok := n.(*ast.Ident); ok && info.Uses[ident] != nil {
				args = append(args, info.Uses[ident])
			}
			return true
		})
	}
	touched := false
	for _, stmt := range between {
		ast.Inspect(stmt, func(n ast.Node) bool {
			var targets []ast.Expr
			switch node := n.(type) {
			case *ast.AssignStmt:
				targets = node.Lhs
			case *ast.IncDecStmt:
				targets = []ast.Expr{node.X}
			case *ast.UnaryExpr:
				if node.Op == token.AND {
					targets = []ast.Expr{node.X}
				}
			case *ast.CallExpr:
				targets = append(slices.Clone(node.Args), node.Fun)
			}
			for _, target := range targets {
				if len(patternkit.UsesOf(info, target, args)) > 0 {
					touched = true
				}
			}
			return !touched
		})
	}
	return touched
}
