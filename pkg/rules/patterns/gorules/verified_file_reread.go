package gorules

import (
	"go/ast"
	"go/token"
	"go/types"
	"strconv"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
)

func init() { rules.Register(NewVerifiedFileRereadRule()) }

// NewVerifiedFileRereadRule detects evidence produced from a different file read.
func NewVerifiedFileRereadRule() *patternkit.TypedFuncRule {
	return patternkit.NewTypedFuncRule(rules.NewBaseRule("verified-file-reread", "security", "Detects file contents checked in a different read from their use", core.SeverityMedium), "Use the same file contents for verification and output", func(scope patternkit.FuncScope, fn *ast.FuncDecl) []patternkit.FuncFinding {
		if fn.Body == nil || scope.Info == nil {
			return nil
		}
		a := &rereadAnalysis{info: scope.Info, inits: map[ast.Stmt]*ast.IfStmt{}, seen: map[token.Pos]bool{}, derived: map[types.Object]bool{}}
		unsupported := false
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			switch n.(type) {
			case *ast.SwitchStmt, *ast.TypeSwitchStmt, *ast.SelectStmt:
				unsupported = true
			}
			if s, ok := n.(*ast.IfStmt); ok && s.Init != nil {
				a.inits[s.Init] = s
			}
			return true
		})
		if unsupported {
			return nil
		}
		(&patternkit.FlowWalker[[]rereadState, struct{}]{Rule: a}).Walk(fn.Body, []rereadState{{}}, struct{}{})
		return a.findings
	})
}

type rereadState struct {
	path, first, second, err1, err2 types.Object
	read                            ast.Node
	checked, secondChecked, blocked bool
}
type rereadAnalysis struct {
	info     *types.Info
	inits    map[ast.Stmt]*ast.IfStmt
	seen     map[token.Pos]bool
	derived  map[types.Object]bool
	findings []patternkit.FuncFinding
}

func rereadKey(s rereadState) string {
	pos := func(o types.Object) string {
		if o == nil {
			return "0"
		}
		return strconv.Itoa(int(o.Pos()))
	}
	p := "0"
	if s.read != nil {
		p = strconv.Itoa(int(s.read.Pos()))
	}
	return patternkit.FlowPathKey(pos(s.path), pos(s.first), pos(s.second), pos(s.err1), pos(s.err2), p, strconv.FormatBool(s.checked), strconv.FormatBool(s.secondChecked), strconv.FormatBool(s.blocked))
}
func (*rereadAnalysis) CloneState(s []rereadState) []rereadState {
	return append([]rereadState(nil), s...)
}
func (*rereadAnalysis) JoinStates(a, b []rereadState) []rereadState {
	joined := patternkit.JoinFlowPaths(a, b, rereadKey)
	if len(joined) > 1 {
		return []rereadState{{blocked: true}}
	}
	return joined
}
func (*rereadAnalysis) LiveState(s []rereadState) bool { return len(s) > 0 }
func (*rereadAnalysis) DeadState() []rereadState       { return nil }
func (*rereadAnalysis) EnterScope(k patternkit.FlowScopeKind, _ ast.Node, p struct{}, s []rereadState) (struct{}, []rereadState) {
	if k == patternkit.FlowScopeForHeader || k == patternkit.FlowScopeForBody || k == patternkit.FlowScopeRangeBody {
		for i := range s {
			s[i] = rereadState{blocked: true}
		}
	}
	return p, s
}
func (*rereadAnalysis) LeaveScope(patternkit.FlowScopeKind, struct{}, *patternkit.FlowEdges[[]rereadState]) {
}
func (*rereadAnalysis) Normalize(e *patternkit.FlowEdges[[]rereadState]) {
	e.Next = patternkit.JoinFlowPaths(nil, e.Next, rereadKey)
	e.Breaks = patternkit.JoinFlowPaths(nil, e.Breaks, rereadKey)
	e.Continues = patternkit.JoinFlowPaths(nil, e.Continues, rereadKey)
}
func (a *rereadAnalysis) object(e ast.Expr) types.Object {
	id, ok := ast.Unparen(e).(*ast.Ident)
	if !ok {
		return nil
	}
	if o := a.info.Uses[id]; o != nil {
		return o
	}
	return a.info.Defs[id]
}
func (a *rereadAnalysis) mentions(n ast.Node, obj types.Object) bool {
	if obj == nil || n == nil {
		return false
	}
	found := false
	ast.Inspect(n, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && a.info.Uses[id] == obj {
			found = true
		}
		return !found
	})
	return found
}
func (a *rereadAnalysis) mentionsDerived(n ast.Node) bool {
	found := false
	ast.Inspect(n, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && a.derived[a.info.Uses[id]] {
			found = true
		}
		return !found
	})
	return found
}
func (a *rereadAnalysis) readCall(e ast.Expr) (*ast.CallExpr, types.Object) {
	c, ok := ast.Unparen(e).(*ast.CallExpr)
	if !ok || len(c.Args) != 1 {
		return nil, nil
	}
	f := patternkit.StaticFunc(a.info, c)
	if f == nil || f.Pkg() == nil || f.Pkg().Path() != "os" || f.Name() != "ReadFile" {
		return nil, nil
	}
	path := a.object(c.Args[0])
	v, ok := path.(*types.Var)
	if !ok || v.Pkg() == nil || v.IsField() || v.Parent() == v.Pkg().Scope() || !patternkit.IsStringType(v.Type()) {
		return nil, nil
	}
	return c, path
}

func rereadPureStringFunc(name string) bool {
	switch name {
	case "Clone", "Compare", "Contains", "ContainsAny", "ContainsRune", "Count", "Cut", "Equal", "EqualFold", "HasPrefix", "HasSuffix", "Index", "IndexAny", "IndexByte", "IndexRune", "LastIndex", "LastIndexAny", "LastIndexByte", "Repeat", "Replace", "ReplaceAll", "Split", "SplitAfter", "SplitAfterN", "SplitN", "ToLower", "ToUpper", "Trim", "TrimPrefix", "TrimSpace", "TrimSuffix":
		return true
	}
	return false
}

func (a *rereadAnalysis) readAndConstants(n ast.Node, read types.Object) bool {
	valid := true
	ast.Inspect(n, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok {
			if v, ok := a.info.Uses[id].(*types.Var); ok && v != read {
				valid = false
			}
		}
		return valid
	})
	return valid
}

// safeExpression permits only conversions, harmless builtins and explicit pure functions.
func (a *rereadAnalysis) safeExpression(n ast.Node, checkObj types.Object) bool {
	safe := true
	ast.Inspect(n, func(n ast.Node) bool {
		if !safe {
			return false
		}
		switch x := n.(type) {
		case *ast.FuncLit:
			safe = false
		case *ast.UnaryExpr:
			if x.Op == token.AND || x.Op == token.ARROW {
				safe = false
			}
		case *ast.CallExpr:
			safe = a.safeCall(x, checkObj)
		}
		return safe
	})
	return safe
}

func (a *rereadAnalysis) safeCall(call *ast.CallExpr, checkObj types.Object) bool {
	if a.info.Types[call.Fun].IsType() {
		return true
	}
	if id, ok := call.Fun.(*ast.Ident); ok {
		if b, ok := a.info.Uses[id].(*types.Builtin); ok && (b.Name() == "len" || b.Name() == "cap") {
			return true
		}
	}
	f := patternkit.StaticFunc(a.info, call)
	if f == nil || f.Pkg() == nil {
		return false
	}
	p := f.Pkg().Path()
	pure := ((p == "bytes" || p == "strings") && rereadPureStringFunc(f.Name())) || (p == "encoding/hex" && (f.Name() == "EncodeToString" || f.Name() == "DecodeString")) || ((p == "crypto/sha256" || p == "crypto/sha512" || p == "crypto/sha1" || p == "crypto/md5") && strings.HasPrefix(f.Name(), "Sum"))
	if !pure && checkObj != nil {
		pure = a.safeCheckArgs(call.Args, checkObj)
	}
	if !pure {
		return false
	}
	sig, ok := f.Type().(*types.Signature)
	if !ok || sig.Recv() != nil {
		return false
	}
	for _, arg := range call.Args {
		typ := a.info.TypeOf(arg)
		if typ == nil {
			return false
		}
		if _, ok := typ.Underlying().(*types.Pointer); ok {
			return false
		}
	}
	return true
}

func (a *rereadAnalysis) safeCheckArgs(args []ast.Expr, checkObj types.Object) bool {
	pure, usesRead := true, false
	for _, arg := range args {
		usesRead = usesRead || a.mentions(arg, checkObj)
		if !a.readAndConstants(arg, checkObj) || (!a.mentions(arg, checkObj) && a.info.Types[arg].Value == nil) {
			pure = false
		}
	}
	return pure && usesRead
}
func (a *rereadAnalysis) report(s rereadState) {
	if s.read != nil && !a.seen[s.read.Pos()] {
		a.seen[s.read.Pos()] = true
		a.findings = append(a.findings, patternkit.FuncFinding{Node: s.read, Message: "file contents used for evidence came from a different read than the verified contents"})
	}
}
func (a *rereadAnalysis) consume(n ast.Node, s rereadState) bool {
	if s.second == nil {
		return false
	}
	return (s.checked && a.mentions(n, s.second) && !a.mentions(n, s.first)) || (s.secondChecked && a.mentions(n, s.first) && !a.mentions(n, s.second))
}
func (a *rereadAnalysis) safeUse(expressions []ast.Expr, s rereadState) bool {
	value := s.second
	if s.secondChecked {
		value = s.first
	}
	for _, expression := range expressions {
		if !a.safeExpression(expression, value) {
			return false
		}
	}
	return true
}
func (a *rereadAnalysis) SimpleStmt(stmt ast.Stmt, states []rereadState, _ struct{}) ([]rereadState, bool) {
	for i := range states {
		s := &states[i]
		switch x := stmt.(type) {
		case *ast.AssignStmt:
			a.assignStmt(x, s)
		case *ast.DeclStmt:
			if !a.safeExpression(x, nil) {
				*s = rereadState{blocked: true}
			}
		case *ast.ReturnStmt:
			if a.consume(x, *s) && a.safeUse(x.Results, *s) {
				a.report(*s)
			}
		case *ast.ExprStmt:
			a.exprStmt(x, s)
		default:
			*s = rereadState{blocked: true}
		}
	}
	_, done := stmt.(*ast.ReturnStmt)
	return states, done
}

func (a *rereadAnalysis) assignStmt(stmt *ast.AssignStmt, s *rereadState) {
	if len(stmt.Rhs) == 1 && len(stmt.Lhs) >= 1 {
		if call, path := a.readCall(stmt.Rhs[0]); call != nil {
			a.assignRead(stmt, s, call, path)
			return
		}
	}
	if s.second != nil && (a.mentions(stmt, s.first) || a.mentionsDerived(stmt)) {
		*s = rereadState{blocked: true}
		return
	}
	validInit := false
	if cond := a.inits[stmt]; cond != nil && s.first != nil && patternkit.EndsWithReturn(cond.Body) && a.safeExpression(stmt, s.first) && a.mentions(stmt, s.first) {
		validInit = true
	}
	if !validInit && !a.safeExpression(stmt, nil) {
		*s = rereadState{blocked: true}
		return
	}
	a.checkAssignmentTargets(stmt.Lhs, s)
	if validInit {
		s.checked = true
	}
	if !validInit && s.first != nil && s.second == nil {
		a.recordDerived(stmt, s)
	}
}

func (a *rereadAnalysis) assignRead(stmt *ast.AssignStmt, s *rereadState, call *ast.CallExpr, path types.Object) {
	target := a.object(stmt.Lhs[0])
	var er types.Object
	if len(stmt.Lhs) > 1 {
		er = a.object(stmt.Lhs[1])
	}
	if !s.blocked && s.first == nil {
		s.path = path
		s.first = target
		s.err1 = er
	} else if !s.blocked && s.path == path && s.first != nil && s.second == nil {
		s.second = target
		s.err2 = er
		s.read = call
	} else {
		*s = rereadState{blocked: true}
	}
}

func (a *rereadAnalysis) checkAssignmentTargets(lhs []ast.Expr, s *rereadState) {
	for _, target := range lhs {
		id, ok := ast.Unparen(target).(*ast.Ident)
		if !ok {
			*s = rereadState{blocked: true}
			break
		}
		obj := a.object(id)
		if id.Name != "_" {
			v, local := obj.(*types.Var)
			if !local || v.Pkg() == nil || v.Parent() == v.Pkg().Scope() {
				*s = rereadState{blocked: true}
				break
			}
		}
		if id.Name != "_" && (obj == s.path || obj == s.first || obj == s.second) {
			*s = rereadState{blocked: true}
			break
		}
	}
}

func (a *rereadAnalysis) recordDerived(stmt *ast.AssignStmt, s *rereadState) {
	for _, rhs := range stmt.Rhs {
		if a.mentions(rhs, s.first) || a.mentionsDerived(rhs) {
			for _, lhs := range stmt.Lhs {
				if obj := a.object(lhs); obj != nil {
					a.derived[obj] = true
				}
			}
		}
	}
}

func (a *rereadAnalysis) exprStmt(stmt *ast.ExprStmt, s *rereadState) {
	call, ok := stmt.X.(*ast.CallExpr)
	output := false
	if ok {
		f := patternkit.StaticFunc(a.info, call)
		output = f != nil && f.Pkg() != nil && f.Pkg().Path() == "fmt" && (f.Name() == "Print" || f.Name() == "Printf" || f.Name() == "Println")
	}
	if output && a.consume(stmt, *s) && a.safeUse(call.Args, *s) {
		a.report(*s)
		s.second = nil
		s.read = nil
		s.err2 = nil
		s.secondChecked = false
	} else if !a.safeExpression(stmt, nil) {
		*s = rereadState{blocked: true}
	}
}
func (a *rereadAnalysis) IfCondition(stmt *ast.IfStmt, states []rereadState, _ struct{}) ([]rereadState, []rereadState) {
	for i := range states {
		s := &states[i]
		if s.first == nil {
			if !a.safeExpression(stmt.Cond, nil) {
				*s = rereadState{blocked: true}
			}
			continue
		}
		first, second := a.mentions(stmt.Cond, s.first), a.mentions(stmt.Cond, s.second)
		if s.second != nil && a.mentionsDerived(stmt.Cond) {
			*s = rereadState{blocked: true}
			continue
		}
		if first && second {
			*s = rereadState{blocked: true}
			continue
		}
		check := types.Object(nil)
		if patternkit.EndsWithReturn(stmt.Body) {
			if first {
				check = s.first
			}
			if second {
				check = s.second
			}
		}
		if !a.safeExpression(stmt.Cond, check) {
			*s = rereadState{blocked: true}
			continue
		}
		if check == s.first && check != nil {
			s.checked = true
		}
		if check == s.second && check != nil {
			if s.checked {
				*s = rereadState{blocked: true}
				continue
			}
			s.secondChecked = true
		}
	}
	return a.CloneState(states), states
}
func (a *rereadAnalysis) FlowExpr(_ ast.Expr, s []rereadState, _ struct{}) []rereadState {
	for i := range s {
		s[i] = rereadState{blocked: true}
	}
	return s
}
func (a *rereadAnalysis) RangeVars(_ *ast.RangeStmt, s []rereadState, _ struct{}) []rereadState {
	return a.FlowExpr(nil, s, struct{}{})
}
func (a *rereadAnalysis) TypeSwitchGuard(_ ast.Stmt, s []rereadState, _ struct{}) []rereadState {
	return a.FlowExpr(nil, s, struct{}{})
}
func (a *rereadAnalysis) CaseClause(_ ast.Stmt, _ *ast.CaseClause, s []rereadState, p struct{}) ([]rereadState, struct{}) {
	return a.FlowExpr(nil, s, p), p
}
func (a *rereadAnalysis) CommClause(_ *ast.CommClause, s []rereadState, p struct{}) ([]rereadState, struct{}) {
	return a.FlowExpr(nil, s, p), p
}
