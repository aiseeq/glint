package security

import (
	"go/ast"
	"go/types"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewJWTTokenTypeRule())
}

// JWTTokenTypeRule detects a refresh that reads token claims carrying their
// kind without looking at the kind:
//
//	type TokenClaims struct { jwt.RegisteredClaims; UserID, TokenType string }
//
//	func (m *Manager) RefreshTokens(token string) (*Pair, error) {
//	    result, err := m.validator.Validate(token)
//	    claims := result.Data                      // access or refresh?
//	    return m.issue(claims.UserID)
//	}
//
// Access and refresh tokens signed with the same key differ only in that
// field: a refresh that does not compare it accepts an access token and
// extends a session the access token was meant to end with. Claims are a
// struct named ...Claims or embedding RegisteredClaims or StandardClaims,
// with a TokenType, Typ or Type field.
type JWTTokenTypeRule struct {
	*rules.BaseRule
}

// NewJWTTokenTypeRule creates the rule
func NewJWTTokenTypeRule() *JWTTokenTypeRule {
	return &JWTTokenTypeRule{
		BaseRule: rules.NewBaseRule(
			"jwt-token-type-unchecked",
			"security",
			"Detects a token refresh that reads claims carrying the token kind without checking it is a refresh token",
			core.SeverityHigh,
		),
	}
}

// AnalyzeFile is a no-op: the claims type is known only with type information.
func (r *JWTTokenTypeRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *JWTTokenTypeRule) RequiresSSA() bool { return false }

// AnalyzeGoProject reports the refresh functions of the project that read
// claims without their kind.
func (r *JWTTokenTypeRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(fileCtx *core.FileContext, info *types.Info) []*core.Violation {
		var violations []*core.Violation
		for _, decl := range fileCtx.GoAST.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || !strings.Contains(strings.ToLower(fn.Name.Name), "refresh") {
				continue
			}
			read := uncheckedClaimsRead(fn.Body, info)
			if read == nil {
				continue
			}
			line := fileCtx.LineFor(read)
			if fileCtx.IsSuppressed(line, r.Name()) {
				continue
			}
			v := r.CreateViolation(fileCtx.RelPath, line,
				"The refresh reads token claims without checking their kind — an access token signed with the same key refreshes the session")
			v.WithCode(strings.TrimSpace(fileCtx.GetLine(line)))
			v.WithSuggestion("Reject the claims unless their token type is refresh (and the other way round where access tokens are checked)")
			violations = append(violations, v)
		}
		return violations
	})
}

// uncheckedClaimsRead returns the first place a body takes claims that carry
// a token kind from a call or a field, when the body never names that kind —
// reads it, sets it, or hands the claims to a call about their type.
func uncheckedClaimsRead(body *ast.BlockStmt, info *types.Info) ast.Expr {
	var first ast.Expr
	checked := false
	ast.Inspect(body, func(n ast.Node) bool {
		switch n.(type) {
		case *ast.SelectorExpr, *ast.CallExpr, *ast.TypeAssertExpr:
			if expr, ok := n.(ast.Expr); ok && first == nil && claimsKindField(info.TypeOf(expr)) != nil {
				first = expr
			}
		}
		switch node := n.(type) {
		case *ast.SelectorExpr:
			if selection, ok := info.Selections[node]; ok && isKindFieldName(selection.Obj().Name()) {
				checked = checked || claimsKindField(selection.Recv()) != nil
			}
		case *ast.KeyValueExpr:
			if key, ok := node.Key.(*ast.Ident); ok && isKindFieldName(key.Name) {
				checked = true
			}
		case *ast.CallExpr:
			name := strings.ToLower(callName(node))
			if strings.Contains(name, "type") || strings.Contains(name, "kind") {
				for _, arg := range node.Args {
					checked = checked || claimsKindField(info.TypeOf(arg)) != nil
				}
			}
		}
		return true
	})
	if checked || first == nil {
		return nil
	}
	return first
}

func isKindFieldName(name string) bool {
	return name == "TokenType" || name == "Typ" || name == "Type"
}

// claimsKindField returns the field that says which kind of token claims
// are, for a claims struct or a pointer to one.
func claimsKindField(t types.Type) *types.Var {
	if t == nil {
		return nil
	}
	if p, ok := types.Unalias(t).(*types.Pointer); ok {
		t = p.Elem()
	}
	named, ok := types.Unalias(t).(*types.Named)
	if !ok {
		return nil
	}
	st, ok := named.Underlying().(*types.Struct)
	if !ok {
		return nil
	}
	claims := strings.HasSuffix(named.Obj().Name(), "Claims")
	var kind *types.Var
	for i := range st.NumFields() {
		field := st.Field(i)
		if field.Embedded() {
			if embedded, ok := types.Unalias(derefType(field.Type())).(*types.Named); ok {
				name := embedded.Obj().Name()
				claims = claims || name == "RegisteredClaims" || name == "StandardClaims"
			}
			continue
		}
		if basic, ok := field.Type().Underlying().(*types.Basic); ok && basic.Kind() == types.String && isKindFieldName(field.Name()) {
			kind = field
		}
	}
	if !claims {
		return nil
	}
	return kind
}

func derefType(t types.Type) types.Type {
	if p, ok := types.Unalias(t).(*types.Pointer); ok {
		return p.Elem()
	}
	return t
}
