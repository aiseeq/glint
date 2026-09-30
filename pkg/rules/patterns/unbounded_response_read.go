package patterns

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"golang.org/x/tools/go/types/typeutil"
)

func init() {
	rules.Register(NewUnboundedResponseReadRule())
}

// UnboundedResponseReadRule detects unbounded reads of HTTP response bodies
// and of decompressed streams.
type UnboundedResponseReadRule struct {
	*rules.BaseRule
}

// NewUnboundedResponseReadRule creates the rule.
func NewUnboundedResponseReadRule() *UnboundedResponseReadRule {
	return &UnboundedResponseReadRule{
		BaseRule: rules.NewBaseRule(
			"unbounded-response-read",
			"patterns",
			"Detects unbounded io.ReadAll (or ioutil.ReadAll) calls on HTTP response bodies and on decompressing readers (gzip, zlib, flate, lzw, bzip2, zstd)",
			core.SeverityHigh,
		),
	}
}

// AnalyzeFile is a no-op: whether a call yields an *http.Response is a
// question about its type, which one file without type information cannot
// answer.
func (r *UnboundedResponseReadRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *UnboundedResponseReadRule) RequiresSSA() bool { return false }

// AnalyzeGoProject reports unbounded reads of response bodies.
func (r *UnboundedResponseReadRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	return rules.AnalyzeTypedFiles(ctx, r.Name(), r.analyzeFile)
}

// analyzeFile checks every declared function of the file; function literals
// are checked as their own scopes from inside them.
func (r *UnboundedResponseReadRule) analyzeFile(ctx *core.FileContext, info *types.Info) []*core.Violation {
	var violations []*core.Violation
	reported := make(map[token.Pos]struct{})
	for _, decl := range ctx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		analyzer := &unboundedResponseAnalyzer{
			rule:       r,
			ctx:        ctx,
			info:       info,
			violations: &violations,
			reported:   reported,
		}
		analyzer.checkFunctionBody(fn.Body)
	}
	return append(violations, r.decompressedReads(ctx, info, reported)...)
}

// decompressorConstructors are the functions, by import path, whose first
// result reads decompressed data.
var decompressorConstructors = map[string]map[string]bool{
	"compress/gzip":                       {"NewReader": true},
	"compress/zlib":                       {"NewReader": true, "NewReaderDict": true},
	"compress/flate":                      {"NewReader": true, "NewReaderDict": true},
	"compress/lzw":                        {"NewReader": true},
	"compress/bzip2":                      {"NewReader": true},
	"github.com/klauspost/compress/gzip":  {"NewReader": true},
	"github.com/klauspost/compress/zlib":  {"NewReader": true, "NewReaderDict": true},
	"github.com/klauspost/compress/flate": {"NewReader": true, "NewReaderDict": true},
	"github.com/klauspost/compress/zstd":  {"NewReader": true},
}

func isDecompressorCall(info *types.Info, expr ast.Expr) bool {
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok {
		return false
	}
	fn, ok := typeutil.Callee(info, call).(*types.Func)
	if !ok || fn.Pkg() == nil {
		return false
	}
	return decompressorConstructors[fn.Pkg().Path()][fn.Name()]
}

// decompressedReads reports io.ReadAll over a decompressing reader: a small
// compressed input, bounded or not, expands without bound. A reader is a
// variable every assignment of which is a decompressor constructor, or the
// constructor call itself.
func (r *UnboundedResponseReadRule) decompressedReads(ctx *core.FileContext, info *types.Info, reported map[token.Pos]struct{}) []*core.Violation {
	decompressors := make(map[types.Object]bool)
	record := func(lhs ast.Expr, decompressor bool) {
		ident, ok := ast.Unparen(lhs).(*ast.Ident)
		if !ok {
			return
		}
		obj := info.ObjectOf(ident)
		if obj == nil {
			return
		}
		if seen, ok := decompressors[obj]; ok && !seen {
			return
		}
		decompressors[obj] = decompressor
	}
	recordValues := func(lhs []ast.Expr, rhs []ast.Expr) {
		for i, target := range lhs {
			switch {
			case len(rhs) == len(lhs):
				record(target, isDecompressorCall(info, rhs[i]))
			case len(rhs) == 1:
				record(target, i == 0 && isDecompressorCall(info, rhs[0]))
			}
		}
	}
	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			recordValues(node.Lhs, node.Rhs)
		case *ast.ValueSpec:
			names := make([]ast.Expr, len(node.Names))
			for i, name := range node.Names {
				names[i] = name
			}
			recordValues(names, node.Values)
		}
		return true
	})

	var violations []*core.Violation
	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 1 {
			return true
		}
		if !isPackageFuncCall(ctx.GoAST, info, call, "io", "ReadAll") &&
			!isPackageFuncCall(ctx.GoAST, info, call, "io/ioutil", "ReadAll") {
			return true
		}
		arg := ast.Unparen(call.Args[0])
		decompressed := isDecompressorCall(info, arg)
		if ident, ok := arg.(*ast.Ident); ok {
			decompressed = decompressors[info.ObjectOf(ident)]
		}
		if !decompressed {
			return true
		}
		if _, exists := reported[call.Pos()]; exists {
			return true
		}
		line := ctx.PositionFor(call).Line
		if ctx.IsSuppressed(line, r.Name()) {
			return true
		}
		reported[call.Pos()] = struct{}{}
		v := r.CreateViolation(ctx.RelPath, line, "Decompressed stream read without a size limit: a small compressed input can expand without bound")
		v.WithCode(ctx.GetLine(line))
		v.WithSuggestion("Wrap the decompressing reader with io.LimitReader before calling io.ReadAll")
		v.WithContext("pattern", "unbounded_decompressed_read")
		violations = append(violations, v)
		return true
	})
	return violations
}

type responseState struct {
	scopes []map[string]bool
}

func newResponseState() *responseState {
	return &responseState{scopes: []map[string]bool{{}}}
}

func (s *responseState) clone() *responseState {
	clone := &responseState{scopes: make([]map[string]bool, len(s.scopes))}
	for i, scope := range s.scopes {
		clone.scopes[i] = make(map[string]bool, len(scope))
		for name, tracked := range scope {
			clone.scopes[i][name] = tracked
		}
	}
	return clone
}

func (s *responseState) pushScope() {
	s.scopes = append(s.scopes, make(map[string]bool))
}

func (s *responseState) popScope() {
	s.scopes = s.scopes[:len(s.scopes)-1]
}

func (s *responseState) assign(name string, tracked, define bool) {
	if name == "_" {
		return
	}
	if define {
		s.scopes[len(s.scopes)-1][name] = tracked
		return
	}
	for i := len(s.scopes) - 1; i >= 0; i-- {
		if _, exists := s.scopes[i][name]; exists {
			s.scopes[i][name] = tracked
			return
		}
	}
	s.scopes[0][name] = tracked
}

func (s *responseState) isTracked(name string) bool {
	for i := len(s.scopes) - 1; i >= 0; i-- {
		if tracked, exists := s.scopes[i][name]; exists {
			return tracked
		}
	}
	return false
}

func mergeResponseStates(states ...*responseState) *responseState {
	merged := &responseState{scopes: make([]map[string]bool, len(states[0].scopes))}
	for i := range merged.scopes {
		merged.scopes[i] = make(map[string]bool)
		for _, state := range states {
			for name, tracked := range state.scopes[i] {
				if _, exists := merged.scopes[i][name]; !exists || tracked {
					merged.scopes[i][name] = tracked
				}
			}
		}
	}
	return merged
}

type unboundedResponseAnalyzer struct {
	rule       *UnboundedResponseReadRule
	ctx        *core.FileContext
	info       *types.Info
	violations *[]*core.Violation
	reported   map[token.Pos]struct{}
}

func (a *unboundedResponseAnalyzer) checkFunctionBody(body *ast.BlockStmt) {
	walker := &flowWalker[*responseState, struct{}]{rule: a}
	walker.walk(body, newResponseState(), struct{}{})
}

func (a *unboundedResponseAnalyzer) cloneState(state *responseState) *responseState {
	return state.clone()
}

func (a *unboundedResponseAnalyzer) joinStates(left, right *responseState) *responseState {
	return mergeResponseStates(left, right)
}

func (a *unboundedResponseAnalyzer) liveState(state *responseState) bool { return state != nil }

func (a *unboundedResponseAnalyzer) deadState() *responseState { return nil }

func (a *unboundedResponseAnalyzer) enterScope(
	_ flowScopeKind,
	_ ast.Node,
	parent struct{},
	state *responseState,
) (struct{}, *responseState) {
	state.pushScope()
	return parent, state
}

func (a *unboundedResponseAnalyzer) leaveScope(_ flowScopeKind, _ struct{}, edges *flowEdges[*responseState]) {
	for _, state := range []*responseState{edges.next, edges.breaks, edges.continues} {
		if state != nil {
			state.popScope()
		}
	}
}

func (a *unboundedResponseAnalyzer) simpleStmt(stmt ast.Stmt, state *responseState, _ struct{}) (*responseState, bool) {
	switch stmt := stmt.(type) {
	case *ast.AssignStmt:
		a.checkAssignment(stmt, state)
	case *ast.DeclStmt:
		a.checkDeclaration(stmt, state)
	case *ast.ExprStmt:
		a.checkExpr(stmt.X, state)
		if stmtNoReturn(stmt, a.info, a.ctx.GoAST) != callReturns {
			return nil, true
		}
	case *ast.DeferStmt:
		a.checkExpr(stmt.Call, state)
	case *ast.GoStmt:
		a.checkExpr(stmt.Call, state)
	case *ast.ReturnStmt:
		for _, expr := range stmt.Results {
			a.checkExpr(expr, state)
		}
		return nil, true
	case *ast.SendStmt:
		a.checkExpr(stmt.Chan, state)
		a.checkExpr(stmt.Value, state)
	case *ast.IncDecStmt:
		a.checkExpr(stmt.X, state)
	}
	return state, false
}

func (a *unboundedResponseAnalyzer) ifCondition(
	stmt *ast.IfStmt,
	state *responseState,
	_ struct{},
) (*responseState, *responseState) {
	a.checkExpr(stmt.Cond, state)
	return state, state.clone()
}

func (a *unboundedResponseAnalyzer) flowExpr(expr ast.Expr, state *responseState, _ struct{}) *responseState {
	a.checkExpr(expr, state)
	return state
}

func (a *unboundedResponseAnalyzer) rangeVars(stmt *ast.RangeStmt, state *responseState, _ struct{}) *responseState {
	define := stmt.Tok == token.DEFINE
	if ident, ok := stmt.Key.(*ast.Ident); ok {
		state.assign(ident.Name, false, define)
	}
	if ident, ok := stmt.Value.(*ast.Ident); ok {
		state.assign(ident.Name, false, define)
	}
	return state
}

func (a *unboundedResponseAnalyzer) typeSwitchGuard(stmt ast.Stmt, state *responseState, scope struct{}) *responseState {
	next, _ := a.simpleStmt(stmt, state, scope)
	return next
}

func (a *unboundedResponseAnalyzer) caseClause(
	_ ast.Stmt,
	clause *ast.CaseClause,
	state *responseState,
	parent struct{},
) (*responseState, struct{}) {
	state.pushScope()
	for _, expr := range clause.List {
		a.checkExpr(expr, state)
	}
	return state, parent
}

func (a *unboundedResponseAnalyzer) commClause(
	_ *ast.CommClause,
	state *responseState,
	parent struct{},
) (*responseState, struct{}) {
	state.pushScope()
	return state, parent
}

func (a *unboundedResponseAnalyzer) normalize(*flowEdges[*responseState]) {}

func (a *unboundedResponseAnalyzer) checkAssignment(stmt *ast.AssignStmt, state *responseState) {
	for _, expr := range stmt.Lhs {
		a.checkExpr(expr, state)
	}
	for _, expr := range stmt.Rhs {
		a.checkExpr(expr, state)
	}
	responseAssignment := len(stmt.Rhs) == 1 && a.isResponseCall(stmt.Rhs[0])
	for i, lhs := range stmt.Lhs {
		if ident, ok := lhs.(*ast.Ident); ok {
			state.assign(ident.Name, i == 0 && responseAssignment, stmt.Tok == token.DEFINE)
		}
	}
}

func (a *unboundedResponseAnalyzer) checkDeclaration(stmt *ast.DeclStmt, state *responseState) {
	decl, ok := stmt.Decl.(*ast.GenDecl)
	if !ok {
		return
	}
	for _, spec := range decl.Specs {
		value, ok := spec.(*ast.ValueSpec)
		if !ok {
			continue
		}
		for _, expr := range value.Values {
			a.checkExpr(expr, state)
		}
		responseAssignment := len(value.Values) == 1 && a.isResponseCall(value.Values[0])
		for i, name := range value.Names {
			state.assign(name.Name, i == 0 && responseAssignment, true)
		}
	}
}

func (a *unboundedResponseAnalyzer) checkExpr(expr ast.Expr, state *responseState) {
	ast.Inspect(expr, func(node ast.Node) bool {
		switch node := node.(type) {
		case *ast.FuncLit:
			a.checkFunctionBody(node.Body)
			return false
		case *ast.CallExpr:
			a.checkCall(node, state)
		}
		return true
	})
}

func (a *unboundedResponseAnalyzer) checkCall(call *ast.CallExpr, state *responseState) {
	response, ok := a.unboundedResponseBodyRead(call)
	if !ok || !state.isTracked(response.Name) {
		return
	}
	if _, exists := a.reported[call.Pos()]; exists {
		return
	}
	line := a.ctx.PositionFor(call).Line
	if a.ctx.IsSuppressed(line, a.rule.Name()) {
		return
	}
	a.reported[call.Pos()] = struct{}{}
	finding := a.rule.CreateViolation(a.ctx.RelPath, line, "HTTP response body read without a size limit")
	finding.WithCode(a.ctx.GetLine(line))
	finding.WithSuggestion("Wrap " + response.Name + ".Body with io.LimitReader before calling io.ReadAll")
	finding.WithContext("pattern", "unbounded_response_read")
	finding.WithContext("variable", response.Name)
	*a.violations = append(*a.violations, finding)
}

// isResponseCall reports whether expr is a call whose (first) result is an
// *http.Response: http.Get, a client's Do reached through any expression, or
// a wrapper that returns the response.
func (a *unboundedResponseAnalyzer) isResponseCall(expr ast.Expr) bool {
	_, isCall := ast.Unparen(expr).(*ast.CallExpr)
	return isCall && isPointerToNamedType(firstResultType(a.info, expr), "net/http", "Response")
}

// unboundedResponseBodyRead returns x for io.ReadAll(x.Body) and for its
// deprecated alias ioutil.ReadAll(x.Body).
func (a *unboundedResponseAnalyzer) unboundedResponseBodyRead(call *ast.CallExpr) (*ast.Ident, bool) {
	if len(call.Args) != 1 {
		return nil, false
	}
	if !isPackageFuncCall(a.ctx.GoAST, a.info, call, "io", "ReadAll") &&
		!isPackageFuncCall(a.ctx.GoAST, a.info, call, "io/ioutil", "ReadAll") {
		return nil, false
	}
	body, ok := ast.Unparen(call.Args[0]).(*ast.SelectorExpr)
	if !ok || body.Sel.Name != "Body" {
		return nil, false
	}
	response, ok := ast.Unparen(body.X).(*ast.Ident)
	if !ok {
		return nil, false
	}
	return response, true
}
