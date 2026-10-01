package patterns

import (
	"go/ast"
	"go/token"
	"regexp"
	"slices"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewCredentialPresenceOnlyRule())
}

// CredentialPresenceOnlyRule detects a credential field of a decoded request
// that the function only tests for presence:
//
//	if err := json.NewDecoder(r.Body).Decode(&req); err != nil { ... }
//	if req.Signature == "" { http.Error(w, "signature required", 400); return }
//	user, err := auth.ConnectWallet(ctx, req.Wallet) // the signature is never checked
//
// Any non-empty signature, token or password passes: the check looks like
// authentication and verifies nothing. The request variable must not be used
// whole (passed, returned, a method called on it) — then another function may
// verify the field.
type CredentialPresenceOnlyRule struct {
	*rules.BaseRule
}

// NewCredentialPresenceOnlyRule creates the rule
func NewCredentialPresenceOnlyRule() *CredentialPresenceOnlyRule {
	return &CredentialPresenceOnlyRule{BaseRule: rules.NewBaseRule(
		"credential-presence-only",
		"patterns",
		"Detects a signature, token or password of a decoded request that is only tested for presence — any non-empty value passes",
		core.SeverityHigh,
	)}
}

var (
	requestCredentialField = regexp.MustCompile(`(?i)(signature|^sig$|proof|otp$|totp|hmac|captcha|password|passcode|^pin$|token$|^nonce$)`)
	decodeCall             = regexp.MustCompile(`(?i)(decode|unmarshal|bind|parse)`)
)

// AnalyzeFile reports the credentials of decoded requests read only for
// presence.
func (r *CredentialPresenceOnlyRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !productionGoFile(ctx) {
		return nil
	}
	var violations []*core.Violation
	for _, decl := range ctx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		for _, decoded := range decodedVariables(fn.Body) {
			name := decoded.name
			for _, check := range presenceOnlyFields(fn.Body, name, decoded.addr) {
				line := ctx.LineFor(check.node)
				if ctx.IsSuppressed(line, r.Name()) {
					continue
				}
				v := r.CreateViolation(ctx.RelPath, line, "Credential "+name+"."+check.field+
					" is only tested for presence — any non-empty value passes, nothing verifies it")
				v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
				v.WithSuggestion("Verify the value (signature recovery, token lookup, password hash compare) or pass it to the code that does")
				violations = append(violations, v)
			}
		}
	}
	return violations
}

// decodedVariable is a local variable whose address a decoding call
// receives.
type decodedVariable struct {
	name string
	addr *ast.UnaryExpr
}

// decodedVariables returns, in source order, the local variables whose
// address a decoding call receives (json.NewDecoder(r.Body).Decode(&req)).
func decodedVariables(body *ast.BlockStmt) []decodedVariable {
	var decoded []decodedVariable
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || !decodeCall.MatchString(calledFunctionName(call.Fun)) {
			return true
		}
		for _, arg := range call.Args {
			if addr, ok := arg.(*ast.UnaryExpr); ok && addr.Op == token.AND {
				if ident, ok := addr.X.(*ast.Ident); ok {
					decoded = append(decoded, decodedVariable{name: ident.Name, addr: addr})
				}
			}
		}
		return true
	})
	return decoded
}

// presenceCheck is a credential field compared with "" or by its length.
type presenceCheck struct {
	field string
	node  ast.Node
}

// presenceOnlyFields returns the credential fields of the variable that every
// read compares with "" or by length, when the variable is not used whole
// anywhere but in its decoding.
func presenceOnlyFields(body *ast.BlockStmt, name string, decoded *ast.UnaryExpr) []presenceCheck {
	presence := make(map[*ast.SelectorExpr]ast.Node)
	ast.Inspect(body, func(n ast.Node) bool {
		bin, ok := n.(*ast.BinaryExpr)
		if !ok {
			return true
		}
		for _, side := range [][2]ast.Expr{{bin.X, bin.Y}, {bin.Y, bin.X}} {
			if sel := presenceOperand(side[0], side[1], bin.Op); sel != nil {
				presence[sel] = bin
			}
		}
		return true
	})

	fields := make(map[string]bool) // field -> every read is a presence check
	first := make(map[string]ast.Node)
	whole := false
	parents := helpers.ParentMap(body)
	ast.Inspect(body, func(n ast.Node) bool {
		ident, ok := n.(*ast.Ident)
		if !ok || ident.Name != name {
			return true
		}
		switch parent := parents[ident].(type) {
		case *ast.SelectorExpr:
			if parent.X != ident {
				return true
			}
			if call, called := parents[parent].(*ast.CallExpr); called && call.Fun == parent {
				whole = true // a method of the request
				return true
			}
			field := parent.Sel.Name
			check, isPresence := presence[parent]
			if _, known := fields[field]; !known {
				fields[field] = true
			}
			if !isPresence {
				fields[field] = false
				return true
			}
			if first[field] == nil || check.Pos() < first[field].Pos() {
				first[field] = check
			}
		case *ast.UnaryExpr:
			if parent != decoded {
				whole = true
			}
		case *ast.ValueSpec, *ast.AssignStmt:
			// the declaration of the variable
			if assign, ok := parent.(*ast.AssignStmt); ok && !slices.Contains(assign.Lhs, ast.Expr(ident)) {
				whole = true
			}
		default:
			whole = true
		}
		return true
	})
	if whole {
		return nil
	}
	var checks []presenceCheck
	for field, only := range fields {
		if only && requestCredentialField.MatchString(field) {
			checks = append(checks, presenceCheck{field: field, node: first[field]})
		}
	}
	slices.SortFunc(checks, func(a, b presenceCheck) int { return int(a.node.Pos() - b.node.Pos()) })
	return checks
}

// presenceOperand returns the field selector of a presence test: sel == "",
// sel != "", len(sel) == 0, len(sel) > 0.
func presenceOperand(side, other ast.Expr, op token.Token) *ast.SelectorExpr {
	switch op {
	case token.EQL, token.NEQ, token.GTR, token.LSS, token.GEQ, token.LEQ:
	default:
		return nil
	}
	if call, ok := side.(*ast.CallExpr); ok {
		if fun, ok := call.Fun.(*ast.Ident); ok && fun.Name == "len" && len(call.Args) == 1 {
			if lit, ok := other.(*ast.BasicLit); ok && lit.Kind == token.INT {
				sel, _ := call.Args[0].(*ast.SelectorExpr)
				return sel
			}
		}
		return nil
	}
	lit, ok := other.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING || (op != token.EQL && op != token.NEQ) {
		return nil
	}
	if text, ok := goStringLiteral(lit); !ok || text != "" {
		return nil
	}
	sel, _ := side.(*ast.SelectorExpr)
	return sel
}
