package security

import (
	"go/ast"
	"go/token"
	"go/types"
	"regexp"
	"slices"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewTLSVerificationDisabledRule())
}

// TLSVerificationDisabledRule detects certificate verification switched off:
//
//	&tls.Config{InsecureSkipVerify: true}
//	process.env['NODE_TLS_REJECT_UNAUTHORIZED'] = '0'
//	new https.Agent({ rejectUnauthorized: false })
//	browser.newContext({ ignoreHTTPSErrors: true })   // Playwright
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
		"Detects TLS certificate verification turned off (InsecureSkipVerify, NODE_TLS_REJECT_UNAUTHORIZED=0, rejectUnauthorized: false, ignoreHTTPSErrors: true)",
		core.SeverityHigh,
	)}
}

// NeedsTypedGoProject asks the runner to keep this rule active for files it analyzes.
func (r *TLSVerificationDisabledRule) NeedsTypedGoProject(files []*core.FileContext) bool {
	return slices.ContainsFunc(files, func(file *core.FileContext) bool {
		return file.IsGoFile() || file.IsJavaScriptFile() || file.IsTypeScriptFile()
	})
}

// TypedGoProjectImports lists the package used by this rule's type checks.
func (r *TLSVerificationDisabledRule) TypedGoProjectImports() []string {
	return []string{"crypto/tls"}
}

var scriptTLSOff = regexp.MustCompile(`NODE_TLS_REJECT_UNAUTHORIZED['"\]]*\s*=\s*['"]?0|ignoreHTTPSErrors\s*:\s*true`)
var scriptRejectUnauthorized = regexp.MustCompile(`["']?rejectUnauthorized["']?\s*:\s*false\b`)

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
		switch node := n.(type) {
		case *ast.CompositeLit:
			if isTLSConfigLiteral(ctx, node) {
				for _, elt := range node.Elts {
					field, ok := elt.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					key, hasKey := field.Key.(*ast.Ident)
					value, isTrue := field.Value.(*ast.Ident)
					if hasKey && isTrue && key.Name == "InsecureSkipVerify" && value.Name == "true" {
						lr.report(field, "TLS certificate verification is off (InsecureSkipVerify: true) — anyone on the path can read and change the traffic", tlsSuggestion, "tls_verification_disabled")
					}
				}
			}
		case *ast.AssignStmt:
			if node.Tok != token.ASSIGN || len(node.Lhs) != len(node.Rhs) {
				return true
			}
			for i, lhs := range node.Lhs {
				selector, ok := lhs.(*ast.SelectorExpr)
				value, isTrue := node.Rhs[i].(*ast.Ident)
				if ok && selector.Sel.Name == "InsecureSkipVerify" && isTrue && value.Name == "true" && isTLSConfigSelector(ctx.GoTypesInfo, selector) {
					lr.report(node, "TLS certificate verification is off (InsecureSkipVerify = true) — anyone on the path can read and change the traffic", tlsSuggestion, "tls_verification_disabled")
				}
			}
		}
		return true
	})
	return lr.violations
}

func isTLSConfigSelector(info *types.Info, selector *ast.SelectorExpr) bool {
	return info != nil && isTLSConfigType(info, info.TypeOf(selector.X))
}

func isTLSConfigLiteral(ctx *core.FileContext, lit *ast.CompositeLit) bool {
	if ctx.GoTypesInfo != nil {
		return isTLSConfigType(ctx.GoTypesInfo, ctx.GoTypesInfo.TypeOf(lit))
	}
	selector, ok := lit.Type.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, isPkg := selector.X.(*ast.Ident)
	return isPkg && pkg.Name == "tls" && selector.Sel.Name == "Config"
}

// analyzeScript reports TypeScript and JavaScript lines that turn
// verification off.
func (r *TLSVerificationDisabledRule) analyzeScript(ctx *core.FileContext) []*core.Violation {
	var violations []*core.Violation
	text := helpers.FileJSText(ctx)
	code := helpers.FileJSCode(ctx)
	for i, line := range text {
		if !scriptTLSOff.MatchString(line) && !hasRejectUnauthorizedObjectKey(line, code[i]) {
			continue
		}
		if ctx.IsSuppressed(i+1, r.Name()) {
			continue
		}
		v := r.CreateViolation(ctx.RelPath, i+1, "TLS certificate verification is off — anyone on the path can read and change the traffic, credentials included")
		v.WithCode(strings.TrimSpace(ctx.Lines[i]))
		v.WithSuggestion(tlsSuggestion)
		violations = append(violations, v)
	}
	return violations
}

func hasRejectUnauthorizedObjectKey(text, code string) bool {
	for _, loc := range scriptRejectUnauthorized.FindAllStringIndex(text, -1) {
		colon := strings.IndexByte(text[loc[0]:loc[1]], ':') + loc[0]
		if colon < len(code) && code[colon] == ':' {
			return true
		}
	}
	return false
}

func isTLSConfigType(info *types.Info, typ types.Type) bool {
	if info == nil || typ == nil {
		return false
	}
	typ = types.Unalias(typ)
	if pointer, ok := typ.(*types.Pointer); ok {
		typ = types.Unalias(pointer.Elem())
	}
	named, ok := typ.(*types.Named)
	return ok && named.Obj().Name() == "Config" && named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == "crypto/tls"
}
