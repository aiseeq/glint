package patterns

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"net/url"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewTestnetURLAmongMainnetRule())
}

// testnetWords name a test network in a host: testnet.example.io,
// api-sepolia.example.io.
var testnetWords = map[string]bool{
	"testnet": true, "sepolia": true, "goerli": true, "holesky": true, "hoodi": true,
	"devnet": true, "amoy": true, "mumbai": true, "fuji": true, "chapel": true,
	"nile": true, "shasta": true,
}

// TestnetURLAmongMainnetRule detects a test network's URL in a table of
// production URLs:
//
//	var explorers = map[string]string{
//		ChainA: "https://explorer-a.io/tx/",
//		ChainB: "https://explorer-b.io/tx/",
//		ChainC: "https://testnet.explorer-c.io/tx/", // the chain went live since
//	}
//
// Written while the chain was in test, the entry stays when it goes live: its
// links open a test network's explorer, its requests go to a test network's
// node. An entry whose key names the test network (ChainSepolia) is meant to
// be there.
type TestnetURLAmongMainnetRule struct {
	*rules.BaseRule
}

// NewTestnetURLAmongMainnetRule creates the rule.
func NewTestnetURLAmongMainnetRule() *TestnetURLAmongMainnetRule {
	return &TestnetURLAmongMainnetRule{BaseRule: rules.NewBaseRule(
		"testnet-url-among-mainnet",
		"patterns",
		"Detects a test network's URL (testnet, sepolia, devnet…) in a table whose other URLs are production ones — the entry outlived the chain's launch",
		core.SeverityMedium,
	)}
}

// AnalyzeFile reports the test network URLs of a Go file's URL tables.
func (r *TestnetURLAmongMainnetRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || ctx.IsTestFile() || ctx.GoAST == nil || ctx.IsGenerated() {
		return nil
	}
	var violations []*core.Violation
	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		var urls, testnets []*ast.BasicLit
		var hosts []string
		for _, elt := range lit.Elts {
			key := ""
			if kv, ok := elt.(*ast.KeyValueExpr); ok {
				key = types.ExprString(kv.Key)
				elt = kv.Value
			}
			value, ok := elt.(*ast.BasicLit)
			if !ok || value.Kind != token.STRING {
				continue
			}
			parsed, ok := literalURL(value)
			if !ok {
				continue
			}
			urls = append(urls, value)
			if testnetHost(parsed.Hostname()) && !namesTestnet(key) {
				testnets = append(testnets, value)
				hosts = append(hosts, parsed.Hostname())
			}
		}
		// A table of test networks, or of half and half, is not a production one.
		if len(urls) < 3 || len(testnets) == 0 || 2*len(testnets) >= len(urls) {
			return true
		}
		for i, value := range testnets {
			line := ctx.LineFor(value)
			if ctx.IsSuppressed(line, r.Name()) {
				continue
			}
			v := r.CreateViolation(ctx.RelPath, line, "The host "+hosts[i]+" is a test network's, among production URLs — the entry outlived the chain's launch")
			v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
			v.WithSuggestion("Point the entry at the production network, or name the test network in its key")
			violations = append(violations, v)
		}
		return true
	})
	return violations
}

// literalURL returns the absolute web or websocket URL a string literal
// holds; ok is false for any other text.
func literalURL(value *ast.BasicLit) (*url.URL, bool) {
	text := constant.StringVal(constant.MakeFromLiteral(value.Value, token.STRING, 0))
	parsed, err := url.Parse(text)
	return parsed, err == nil && parsed.Host != "" && (strings.HasPrefix(parsed.Scheme, "http") || strings.HasPrefix(parsed.Scheme, "ws"))
}

// testnetHost reports a host one of whose labels (or words of a label) names
// a test network.
func testnetHost(host string) bool {
	for _, label := range strings.FieldsFunc(host, func(r rune) bool { return r == '.' || r == '-' }) {
		if testnetWords[strings.ToLower(label)] {
			return true
		}
	}
	return false
}

// namesTestnet reports a key naming a test network: ChainSepolia, "goerli".
func namesTestnet(key string) bool {
	for _, word := range helpers.IdentifierWords(strings.Trim(key, `"`)) {
		if testnetWords[word] {
			return true
		}
	}
	return false
}
