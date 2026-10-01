package security

import (
	"go/ast"
	"go/constant"
	"go/types"
	"net/http"
	"regexp"
	"slices"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewIdentityHeaderFromClientRule())
}

// IdentityHeaderFromClientRule detects an identity read from a request header
// that the project itself never sets:
//
//	func AdminID(r *http.Request) string { return r.Header.Get("X-Admin-ID") }
//
// A header nobody in the project writes onto the request arrives from the
// client, and the client writes whatever it likes: sending X-Admin-ID makes
// the caller that admin. A header the project's own middleware sets after
// verifying a token (r.Header.Set("X-User-ID", claims.UserID)) is trusted
// as far as the middleware is. A header is an identity when its last word
// names a principal (user, admin, account, tenant, customer, member, owner,
// employee, operator), optionally followed by id, or is a role. Headers a
// proxy sets by convention (X-Forwarded-*, X-Auth-Request-*) are left to
// proxy-header-trust.
type IdentityHeaderFromClientRule struct {
	*rules.BaseRule
}

// NewIdentityHeaderFromClientRule creates the rule
func NewIdentityHeaderFromClientRule() *IdentityHeaderFromClientRule {
	return &IdentityHeaderFromClientRule{BaseRule: rules.NewBaseRule(
		"identity-header-from-client",
		"security",
		"Detects a user, admin, tenant or role identity read from a request header (X-Admin-ID) that no code of the project sets — the client chooses who it is",
		core.SeverityHigh,
	)}
}

// AnalyzeFile is a no-op: the headers the project sets are known only
// across all its files.
func (r *IdentityHeaderFromClientRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *IdentityHeaderFromClientRule) RequiresSSA() bool { return false }

var (
	identityHeader      = regexp.MustCompile(`^x-(?:[a-z0-9]+-)*(?:(?:user|admin|account|tenant|customer|member|owner|employee|operator)(?:-id)?|roles?)$`)
	proxyIdentityHeader = regexp.MustCompile(`^x-(?:forwarded|auth-request|original)-`)
)

// AnalyzeGoProject reports identity headers read from requests that the
// project never sets on a request.
func (r *IdentityHeaderFromClientRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	set := make(map[string]bool)
	_, err := rules.AnalyzeTypedFiles(ctx, r.Name(), func(fileCtx *core.FileContext, info *types.Info) []*core.Violation {
		if fileCtx.IsTestFile() {
			return nil
		}
		ast.Inspect(fileCtx.GoAST, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if name, ok := requestHeaderCall(call, info, "Set", "Add"); ok {
					set[name] = true
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(fileCtx *core.FileContext, info *types.Info) []*core.Violation {
		if fileCtx.IsTestFile() {
			return nil
		}
		var violations []*core.Violation
		ast.Inspect(fileCtx.GoAST, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			name, ok := requestHeaderCall(call, info, "Get", "Values")
			if !ok || set[name] || !identityHeader.MatchString(name) || proxyIdentityHeader.MatchString(name) {
				return true
			}
			line := fileCtx.LineFor(call)
			if fileCtx.IsSuppressed(line, r.Name()) {
				return true
			}
			v := r.CreateViolation(fileCtx.RelPath, line,
				"Identity read from request header "+http.CanonicalHeaderKey(name)+", which no code of the project sets — any client sends it and becomes that principal")
			v.WithCode(strings.TrimSpace(fileCtx.GetLine(line)))
			v.WithSuggestion("Take the identity from the verified token or session, or from a header the project's own auth middleware sets after verification")
			v.WithContext("pattern", "identity_header_from_client")
			violations = append(violations, v)
			return true
		})
		return violations
	})
}

// requestHeaderCall returns the lower-cased constant header name of a call
// of one of the methods on the Header of an *http.Request.
func requestHeaderCall(call *ast.CallExpr, info *types.Info, methods ...string) (string, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || len(call.Args) == 0 || !slices.Contains(methods, sel.Sel.Name) {
		return "", false
	}
	header, ok := ast.Unparen(sel.X).(*ast.SelectorExpr)
	if !ok || header.Sel.Name != "Header" || !isNamedType(info.TypeOf(header.X), "net/http", "Request") {
		return "", false
	}
	tv := info.Types[call.Args[0]]
	if tv.Value == nil || tv.Value.Kind() != constant.String {
		return "", false
	}
	return strings.ToLower(constant.StringVal(tv.Value)), true
}
