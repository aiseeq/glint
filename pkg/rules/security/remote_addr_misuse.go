package security

import (
	"go/ast"
	"strings"
	"unicode"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewRemoteAddrMisuseRule())
}

// RemoteAddrMisuseRule detects http.Request.RemoteAddr taken for an IP
// address:
//
//	ip := strings.Split(r.RemoteAddr, ":")[0]        // "[::1]:52492" gives "["
//	session := Session{IP: r.RemoteAddr}             // "203.0.113.7:51234"
//	if !limiter.Allow(r.RemoteAddr) { ... }          // a new bucket per connection
//
// RemoteAddr is host:port. Split at a colon it breaks on every IPv6 address;
// kept whole it carries a port that changes with every connection, so a rate
// limit, a ban or a count keyed on it never repeats and an audit record holds
// no comparable address. net.SplitHostPort takes the host. A function that
// already splits RemoteAddr with it and keeps the whole value only when that
// fails is left alone.
type RemoteAddrMisuseRule struct {
	*rules.BaseRule
}

// NewRemoteAddrMisuseRule creates the rule
func NewRemoteAddrMisuseRule() *RemoteAddrMisuseRule {
	return &RemoteAddrMisuseRule{
		BaseRule: rules.NewBaseRule(
			"remote-addr-misuse",
			"security",
			"Detects http.Request.RemoteAddr split at a colon or used whole as an IP address, rate-limit key or audit value",
			core.SeverityMedium,
		),
	}
}

// keyedCalls take the key a limit, a ban or a record is kept under.
var keyedCalls = map[string]bool{
	"Allow": true, "AllowN": true, "Limit": true, "Wait": true, "Take": true, "Reserve": true,
	"Ban": true, "Block": true, "IsBlocked": true, "IsBanned": true, "Increment": true, "Incr": true,
}

// AnalyzeFile reports the places a Go file takes RemoteAddr for an IP.
func (r *RemoteAddrMisuseRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
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
		addrNames := make(map[string]bool)
		assignedValues(fn.Body, func(name *ast.Ident, value ast.Expr) {
			if isRemoteAddr(value, parents) {
				addrNames[name.Name] = true
			}
		})
		carriesAddr := func(expr ast.Expr) bool {
			ident, ok := ast.Unparen(expr).(*ast.Ident)
			return isRemoteAddr(expr, parents) || ok && addrNames[ident.Name]
		}
		for _, node := range colonSplits(fn.Body, carriesAddr) {
			report(node, "RemoteAddr split at a colon breaks on IPv6: \"[::1]:52492\" gives \"[\"",
				"Use net.SplitHostPort(r.RemoteAddr)", "split_by_colon")
		}
		if splitsHostPort(fn.Body, carriesAddr) {
			continue
		}
		for _, node := range addrAsIP(fn, parents) {
			report(node, "RemoteAddr is host:port — as an IP it carries a port that changes with every connection, so a key or a record on it never repeats",
				"Take the host with net.SplitHostPort(r.RemoteAddr) (behind a proxy, the client address the proxy reports)",
				"port_in_ip")
		}
	}
	return lr.violations
}

// colonSplits returns strings.Split and strings.SplitN of the address at ":".
func colonSplits(body *ast.BlockStmt, carriesAddr func(ast.Expr) bool) []ast.Node {
	var splits []ast.Node
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := isStringsCall(asExpr(n), "Split", "SplitN")
		if ok && len(call.Args) >= 2 && carriesAddr(call.Args[0]) && stringLiteral(call.Args[1]) == ":" {
			splits = append(splits, call)
		}
		return true
	})
	return splits
}

// splitsHostPort reports a body that takes the host with net.SplitHostPort.
func splitsHostPort(body *ast.BlockStmt, carriesAddr func(ast.Expr) bool) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if ok && callName(call) == "SplitHostPort" && len(call.Args) == 1 && carriesAddr(call.Args[0]) {
			found = true
		}
		return !found
	})
	return found
}

// addrAsIP returns the places a function keeps RemoteAddr itself as an IP: a
// name or a field named for an IP, a map key, the key of a limit, the result
// of a function named for an IP.
func addrAsIP(fn *ast.FuncDecl, parents map[ast.Node]ast.Node) []ast.Node {
	var places []ast.Node
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			if len(node.Lhs) != len(node.Rhs) {
				return true
			}
			for i, rhs := range node.Rhs {
				if isRemoteAddr(rhs, parents) && isIPName(targetName(node.Lhs[i])) {
					places = append(places, rhs)
				}
			}
		case *ast.KeyValueExpr:
			if key, ok := node.Key.(*ast.Ident); ok && isIPName(key.Name) && isRemoteAddr(node.Value, parents) {
				places = append(places, node.Value)
			}
		case *ast.IndexExpr:
			if isRemoteAddr(node.Index, parents) {
				places = append(places, node.Index)
			}
		case *ast.CallExpr:
			if !keyedCalls[callName(node)] {
				return true
			}
			for _, arg := range node.Args {
				if isRemoteAddr(arg, parents) {
					places = append(places, arg)
				}
			}
		case *ast.ReturnStmt:
			if len(node.Results) == 1 && isRemoteAddr(node.Results[0], parents) && isIPName(fn.Name.Name) {
				places = append(places, node.Results[0])
			}
		}
		return true
	})
	return places
}

// targetName returns the name an assignment writes: x or s.X.
func targetName(expr ast.Expr) string {
	switch e := ast.Unparen(expr).(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		return e.Sel.Name
	}
	return ""
}

// isIPName reports a name that holds an IP address: ip, clientIP, ActorIP,
// ipAddress, RemoteIPAddr. A capital run ending in IP (ZIP, SKIP) is a word.
func isIPName(name string) bool {
	lower := strings.ToLower(name)
	if lower == "ip" || lower == "ipaddr" || lower == "ipaddress" {
		return true
	}
	if strings.HasPrefix(name, "ip") && len(name) > 2 && unicode.IsUpper(rune(name[2])) {
		return true
	}
	for _, suffix := range []string{"IPAddress", "IpAddress", "IPAddr", "IpAddr", "IP", "Ip"} {
		if rest, ok := strings.CutSuffix(name, suffix); ok && rest != "" {
			last := rune(rest[len(rest)-1])
			return !unicode.IsUpper(last) || suffix == "Ip"
		}
	}
	return false
}

// asExpr returns a node as an expression, or nil.
func asExpr(n ast.Node) ast.Expr {
	expr, _ := n.(ast.Expr)
	return expr
}
