package security

import (
	"go/ast"
	"go/token"
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewProxyHeaderTrustRule())
}

// ProxyHeaderTrustRule detects a handler that takes the client's address or
// scheme from a header a reverse proxy sets, without checking that the
// connection came from that proxy:
//
//	if xff := r.Header.Get("X-Forwarded-For"); xff != "" { return xff }
//	if r.Header.Get("X-Forwarded-Proto") == "https" { return true }
//	if remoteIP != "127.0.0.1" { return r.Header.Get("X-Real-IP") }   // trust turned around
//	return strings.TrimSpace(strings.Split(xff, ",")[0])               // leftmost hop
//
// Any client sends these headers: a rate limit, a ban, an audit record or a
// Secure cookie decision taken from them is the client's own choice. The
// value counts only where a condition around it holds when the connection
// came from a trusted proxy — a comparison with a loopback address, a call or
// a flag named for loopback, trusted, proxy, private, internal. The leftmost
// element of X-Forwarded-For is what the client sent even behind the proxy:
// the proxy appends the address it saw.
type ProxyHeaderTrustRule struct {
	*rules.BaseRule
}

// NewProxyHeaderTrustRule creates the rule
func NewProxyHeaderTrustRule() *ProxyHeaderTrustRule {
	return &ProxyHeaderTrustRule{
		BaseRule: rules.NewBaseRule(
			"proxy-header-trust",
			"security",
			"Detects proxy headers (X-Forwarded-For, X-Real-IP, X-Forwarded-Proto, CF-*) trusted without checking the connection came from the proxy",
			core.SeverityHigh,
		),
	}
}

// proxyHeaders are the headers a reverse proxy or a CDN sets, lower-cased.
var proxyHeaders = map[string]bool{
	"x-forwarded-for": true, "x-real-ip": true, "x-forwarded-proto": true, "x-forwarded-scheme": true,
	"x-forwarded-ssl": true, "x-client-ip": true, "true-client-ip": true, "cf-connecting-ip": true,
	"cf-visitor": true, "forwarded": true, "x-original-forwarded-for": true, "x-cluster-client-ip": true,
}

// forwardedForHeaders list the hops in a comma-separated chain.
var forwardedForHeaders = map[string]bool{"x-forwarded-for": true, "x-original-forwarded-for": true}

// trustWord names a check of where the connection came from.
var trustWord = regexp.MustCompile(`(?i)loopback|trust|prox(?:y|ies)|localhost|private|internal|allowlist|whitelist`)

// loopbackLiteral is an address compared with the connection's own.
var loopbackLiteral = regexp.MustCompile(`^(?:127\.|::1$|\[::1\]$|localhost$)`)

// AnalyzeFile reports the proxy headers a Go file trusts.
func (r *ProxyHeaderTrustRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.HasGoAST() || ctx.IsTestFile() {
		return nil
	}
	lr := newLineReporter(ctx, r.BaseRule)
	report := lr.report
	for _, decl := range ctx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		parents := parentMap(fn.Body)
		guards := collectTrustGuards(fn.Body)
		for _, read := range proxyHeaderReads(fn.Body, parents) {
			switch guards.weakest(read.uses) {
			case untrustedPeer:
				report(read.call, "The proxy header is trusted exactly when the connection did not come from the proxy — any client sets it",
					"Take the header only when the connection comes from the trusted proxy (loopback or its address), otherwise the connection address",
					"trust_inverted")
			case unknownPeer:
				report(read.call, "The proxy header is taken from any client — without a check that the connection came from the proxy, the client picks its own address or scheme",
					"Take the header only when RemoteAddr is the trusted proxy; otherwise use the connection address and r.TLS",
					"unchecked_peer")
			}
		}
		for _, node := range leftmostHops(fn.Body) {
			report(node, "The leftmost X-Forwarded-For element is whatever the client sent — the proxy appends the address it saw at the right",
				"Take the rightmost element the trusted proxy appended (parts[len(parts)-1]), or the one before each further proxy of yours",
				"leftmost_hop")
		}
	}
	return lr.violations
}

// headerRead is a read of a proxy header and the places its value is used.
type headerRead struct {
	call *ast.CallExpr
	uses []ast.Node
}

// proxyHeaderReads returns the proxy headers a body reads. A header assigned
// to a name is used where the name is read — a test that it is empty and a
// log line are not uses; a header read in place is used there.
func proxyHeaderReads(body *ast.BlockStmt, parents map[ast.Node]ast.Node) []headerRead {
	var reads []headerRead
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || !proxyHeaders[strings.ToLower(headerGet(call))] || insideLogCall(call, parents) {
			return true
		}
		name := assignedTo(call, parents)
		if name == nil {
			if !decidesOnlyHSTS(call, parents) {
				reads = append(reads, headerRead{call: call, uses: []ast.Node{call}})
			}
			return true
		}
		read := headerRead{call: call}
		ast.Inspect(body, func(m ast.Node) bool {
			ident, ok := m.(*ast.Ident)
			if ok && ident != name && ident.Name == name.Name && ident.Pos() > call.End() &&
				!isEmptinessTest(ident, parents) && !insideLogCall(ident, parents) {
				read.uses = append(read.uses, ident)
			}
			return true
		})
		if len(read.uses) > 0 {
			reads = append(reads, read)
		}
		return true
	})
	return reads
}

// decidesOnlyHSTS reports a header read in the condition of an if that only
// sets Strict-Transport-Security: a browser ignores it on plain HTTP, so a
// forged scheme gains nothing.
func decidesOnlyHSTS(call *ast.CallExpr, parents map[ast.Node]ast.Node) bool {
	var node ast.Node = call
	for {
		parent := parents[node]
		ifStmt, ok := parent.(*ast.IfStmt)
		if ok {
			if ifStmt.Cond != node || ifStmt.Else != nil || len(ifStmt.Body.List) == 0 {
				return false
			}
			for _, stmt := range ifStmt.Body.List {
				expr, ok := stmt.(*ast.ExprStmt)
				if !ok {
					return false
				}
				set, ok := expr.X.(*ast.CallExpr)
				if !ok || callName(set) != "Set" || len(set.Args) != 2 ||
					!strings.EqualFold(stringLiteral(set.Args[0]), "Strict-Transport-Security") {
					return false
				}
			}
			return true
		}
		if _, isExpr := parent.(ast.Expr); !isExpr {
			return false
		}
		node = parent
	}
}

// assignedTo returns the name a call's value is assigned to as a whole.
func assignedTo(call *ast.CallExpr, parents map[ast.Node]ast.Node) *ast.Ident {
	switch p := parents[call].(type) {
	case *ast.AssignStmt:
		if len(p.Lhs) == len(p.Rhs) {
			for i, rhs := range p.Rhs {
				if rhs == call {
					ident, _ := p.Lhs[i].(*ast.Ident)
					return ident
				}
			}
		}
	case *ast.ValueSpec:
		if len(p.Names) == len(p.Values) {
			for i, value := range p.Values {
				if value == call {
					return p.Names[i]
				}
			}
		}
	}
	return nil
}

// isEmptinessTest reports x == "", x != "" and len(x) used in a comparison.
func isEmptinessTest(ident *ast.Ident, parents map[ast.Node]ast.Node) bool {
	parent := parents[ident]
	if call, ok := parent.(*ast.CallExpr); ok && callName(call) == "len" {
		parent = parents[call]
	}
	bin, ok := parent.(*ast.BinaryExpr)
	if !ok {
		return false
	}
	switch bin.Op {
	case token.EQL, token.NEQ, token.GTR, token.LSS, token.GEQ, token.LEQ:
	default:
		return false
	}
	other := bin.Y
	if other == ident || parents[ident] != bin {
		other = bin.X
	}
	if lit, ok := ast.Unparen(other).(*ast.BasicLit); ok {
		return lit.Value == `""` || lit.Value == "``" || lit.Value == "0"
	}
	return false
}

// peerTrust is what a condition says of the connection a request came from.
type peerTrust int

const (
	unknownPeer peerTrust = iota
	untrustedPeer
	trustedPeer
)

// trustGuard is a region of code where the peer is known trusted or known
// untrusted.
type trustGuard struct {
	from, to token.Pos
	peer     peerTrust
}

type trustGuards []trustGuard

// at returns what the innermost guard around pos says of the peer.
func (g trustGuards) at(pos token.Pos) peerTrust {
	best := unknownPeer
	var width token.Pos = -1
	for _, guard := range g {
		if guard.from <= pos && pos < guard.to && (width < 0 || guard.to-guard.from < width) {
			best, width = guard.peer, guard.to-guard.from
		}
	}
	return best
}

// weakest returns the least trust over the places a value is used.
func (g trustGuards) weakest(uses []ast.Node) peerTrust {
	result := trustedPeer
	for _, use := range uses {
		switch g.at(use.Pos()) {
		case untrustedPeer:
			return untrustedPeer
		case unknownPeer:
			result = unknownPeer
		}
	}
	return result
}

// collectTrustGuards finds the regions of a body the conditions around them
// place behind a check of the peer: the branch of an if that holds for a
// trusted peer, the statements after an early return on an untrusted one, the
// right side of a && or || that runs only for a trusted peer.
func collectTrustGuards(body *ast.BlockStmt) trustGuards {
	var guards trustGuards
	region := func(node ast.Node, peer peerTrust) {
		if node != nil {
			guards = append(guards, trustGuard{from: node.Pos(), to: node.End(), peer: peer})
		}
	}
	afterEarlyReturn := func(list []ast.Stmt, end token.Pos) {
		for _, stmt := range list {
			ifStmt, ok := stmt.(*ast.IfStmt)
			if ok && ifStmt.Else == nil && peerFalsified(ifStmt.Cond) && terminates(ifStmt.Body) {
				guards = append(guards, trustGuard{from: ifStmt.End(), to: end, peer: trustedPeer})
			}
		}
	}
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.IfStmt:
			if peerImplied(node.Cond) {
				region(node.Body, trustedPeer)
			}
			if peerFalsified(node.Cond) {
				region(node.Else, trustedPeer)
			}
			if peerDenied(node.Cond) {
				region(node.Body, untrustedPeer)
			}
		case *ast.BlockStmt:
			afterEarlyReturn(node.List, node.Rbrace)
		case *ast.CaseClause:
			afterEarlyReturn(node.Body, node.End())
		case *ast.CommClause:
			afterEarlyReturn(node.Body, node.End())
		case *ast.BinaryExpr:
			if node.Op == token.LAND && peerImplied(node.X) || node.Op == token.LOR && peerFalsified(node.X) {
				region(node.Y, trustedPeer)
			}
			if node.Op == token.LAND && peerDenied(node.X) {
				region(node.Y, untrustedPeer)
			}
		}
		return true
	})
	return guards
}

// terminates reports a block that leaves the statement list it is in.
func terminates(block *ast.BlockStmt) bool {
	if len(block.List) == 0 {
		return false
	}
	switch last := block.List[len(block.List)-1].(type) {
	case *ast.ReturnStmt, *ast.BranchStmt:
		return true
	case *ast.ExprStmt:
		call, ok := last.X.(*ast.CallExpr)
		return ok && (callName(call) == "panic" || strings.HasPrefix(callName(call), "Fatal"))
	}
	return false
}

// peerImplied reports a condition that holds only for a trusted peer.
func peerImplied(expr ast.Expr) bool {
	switch e := ast.Unparen(expr).(type) {
	case *ast.UnaryExpr:
		return e.Op == token.NOT && peerFalsified(e.X)
	case *ast.BinaryExpr:
		switch e.Op {
		case token.LAND:
			return peerImplied(e.X) || peerImplied(e.Y)
		case token.LOR:
			return peerImplied(e.X) && peerImplied(e.Y)
		}
	}
	return peerAtom(expr) == trustedPeer
}

// peerFalsified reports a condition that fails only for a trusted peer.
func peerFalsified(expr ast.Expr) bool {
	switch e := ast.Unparen(expr).(type) {
	case *ast.UnaryExpr:
		return e.Op == token.NOT && peerImplied(e.X)
	case *ast.BinaryExpr:
		switch e.Op {
		case token.LAND:
			return peerFalsified(e.X) && peerFalsified(e.Y)
		case token.LOR:
			return peerFalsified(e.X) || peerFalsified(e.Y)
		}
	}
	return peerAtom(expr) == untrustedPeer
}

// peerDenied reports a condition that holds only for an untrusted peer.
func peerDenied(expr ast.Expr) bool {
	switch e := ast.Unparen(expr).(type) {
	case *ast.UnaryExpr:
		return e.Op == token.NOT && peerImplied(e.X)
	case *ast.BinaryExpr:
		switch e.Op {
		case token.LAND:
			return peerDenied(e.X) || peerDenied(e.Y)
		case token.LOR:
			return peerDenied(e.X) && peerDenied(e.Y)
		}
	}
	return peerAtom(expr) == untrustedPeer
}

// peerAtom reads a single test of the peer: ip == "127.0.0.1" and
// isTrustedProxy(ip) say trusted, ip != "::1" says untrusted.
func peerAtom(expr ast.Expr) peerTrust {
	switch e := ast.Unparen(expr).(type) {
	case *ast.BinaryExpr:
		if e.Op != token.EQL && e.Op != token.NEQ {
			return unknownPeer
		}
		if !loopbackLiteral.MatchString(stringLiteral(e.X)) && !loopbackLiteral.MatchString(stringLiteral(e.Y)) {
			return unknownPeer
		}
		if e.Op == token.EQL {
			return trustedPeer
		}
		return untrustedPeer
	case *ast.CallExpr:
		if trustWord.MatchString(helpers.ExprText(e.Fun)) {
			return trustedPeer
		}
		for _, arg := range e.Args {
			if trustWord.MatchString(helpers.ExprText(arg)) || loopbackLiteral.MatchString(stringLiteral(arg)) {
				return trustedPeer
			}
		}
	case *ast.Ident, *ast.SelectorExpr:
		if trustWord.MatchString(helpers.ExprText(e)) {
			return trustedPeer
		}
	}
	return unknownPeer
}

// leftmostHops returns the places a body takes the first element of an
// X-Forwarded-For chain: parts[0] of its split, strings.Cut at the first
// comma.
func leftmostHops(body *ast.BlockStmt) []ast.Node {
	chains := make(map[string]bool)
	parts := make(map[string]bool)
	isChain := func(expr ast.Expr) bool {
		expr = ast.Unparen(expr)
		if call, ok := isStringsCall(expr, "TrimSpace"); ok {
			expr = ast.Unparen(call.Args[0])
		}
		if call, ok := expr.(*ast.CallExpr); ok {
			return forwardedForHeaders[strings.ToLower(headerGet(call))]
		}
		ident, ok := expr.(*ast.Ident)
		return ok && chains[ident.Name]
	}
	isSplit := func(expr ast.Expr) bool {
		call, ok := isStringsCall(expr, "Split", "SplitN")
		return ok && len(call.Args) >= 2 && isChain(call.Args[0])
	}
	var hops []ast.Node
	assignedValues(body, func(name *ast.Ident, value ast.Expr) {
		switch {
		case isChain(value):
			chains[name.Name] = true
		case isSplit(value):
			parts[name.Name] = true
		}
	})
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.IndexExpr:
			if lit, ok := node.Index.(*ast.BasicLit); !ok || lit.Value != "0" {
				return true
			}
			if ident, ok := ast.Unparen(node.X).(*ast.Ident); ok && parts[ident.Name] || isSplit(node.X) {
				hops = append(hops, node)
			}
		case *ast.CallExpr:
			if call, ok := isStringsCall(node, "Cut"); ok && len(call.Args) == 2 && isChain(call.Args[0]) {
				hops = append(hops, node)
			}
		}
		return true
	})
	return hops
}
