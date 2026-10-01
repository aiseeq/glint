package security

import (
	"go/ast"
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewTLSVerificationDisabledRule())
}

// TLSVerificationDisabledRule detects certificate verification switched off:
//
//	&tls.Config{InsecureSkipVerify: true}
//	process.env['NODE_TLS_REJECT_UNAUTHORIZED'] = '0'
//	new https.Agent({ rejectUnauthorized: false })
//
// Without verification anyone on the path presents their own certificate and
// reads or changes the traffic, credentials included. NODE_TLS_REJECT_UNAUTHORIZED
// turns it off for every request of the Node process, not only the one that
// needed it. A test configuration that runs against a deployed environment
// sends real credentials too, so TypeScript and JavaScript test files are
// checked; Go test files are not (httptest servers use self-signed
// certificates and their clients trust them explicitly).
type TLSVerificationDisabledRule struct {
	*rules.BaseRule
}

// NewTLSVerificationDisabledRule creates the rule
func NewTLSVerificationDisabledRule() *TLSVerificationDisabledRule {
	return &TLSVerificationDisabledRule{BaseRule: rules.NewBaseRule(
		"tls-verification-disabled",
		"security",
		"Detects TLS certificate verification turned off (InsecureSkipVerify, NODE_TLS_REJECT_UNAUTHORIZED=0, rejectUnauthorized: false)",
		core.SeverityHigh,
	)}
}

var scriptTLSOff = regexp.MustCompile(`NODE_TLS_REJECT_UNAUTHORIZED['"\]]*\s*=\s*['"]?0|rejectUnauthorized\s*:\s*false`)

const tlsSuggestion = "Trust the certificate explicitly (a CA bundle, RootCAs, NODE_EXTRA_CA_CERTS) instead of turning verification off"

// AnalyzeFile reports the places that turn certificate verification off.
func (r *TLSVerificationDisabledRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if ctx.IsTypeScriptFile() || ctx.IsJavaScriptFile() {
		return r.analyzeScript(ctx)
	}
	if !ctx.HasGoAST() || ctx.IsTestFile() {
		return nil
	}
	lr := newLineReporter(ctx, r.BaseRule)
	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		kv, ok := n.(*ast.KeyValueExpr)
		if !ok {
			return true
		}
		key, ok := kv.Key.(*ast.Ident)
		value, isIdent := kv.Value.(*ast.Ident)
		if ok && isIdent && key.Name == "InsecureSkipVerify" && value.Name == "true" {
			lr.report(kv, "TLS certificate verification is off (InsecureSkipVerify: true) — anyone on the path can read and change the traffic", tlsSuggestion, "tls_verification_disabled")
		}
		return true
	})
	return lr.violations
}

// analyzeScript reports TypeScript and JavaScript lines that turn
// verification off.
func (r *TLSVerificationDisabledRule) analyzeScript(ctx *core.FileContext) []*core.Violation {
	var violations []*core.Violation
	for i, line := range strings.Split(string(ctx.Content), "\n") {
		code := strings.TrimSpace(line)
		if strings.HasPrefix(code, "//") || strings.HasPrefix(code, "*") || !scriptTLSOff.MatchString(code) {
			continue
		}
		if ctx.IsSuppressed(i+1, r.Name()) {
			continue
		}
		v := r.CreateViolation(ctx.RelPath, i+1, "TLS certificate verification is off — anyone on the path can read and change the traffic, credentials included")
		v.WithCode(code)
		v.WithSuggestion(tlsSuggestion)
		violations = append(violations, v)
	}
	return violations
}
