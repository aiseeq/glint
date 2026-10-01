package security

import (
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"golang.org/x/tools/go/types/typeutil"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewSecretCompareNotConstantTimeRule())
}

// SecretCompareNotConstantTimeRule detects a secret compared with == / != or
// bytes.Equal:
//
//	if headers.signature != h.expectedSignature { return errUnauthorized }
//
// The comparison stops at the first differing byte, so the time it takes
// tells a caller how much of a guessed signature, token or key was right,
// and the secret leaks byte by byte. hmac.Equal or
// subtle.ConstantTimeCompare take the same time whatever the input.
//
// A value is a secret by its name. Its last word is secret, hmac, password
// or apikey; key qualified by api, secret, private, public, access, signing,
// webhook, auth, client, shared or processing; or token qualified by
// access, refresh, auth, api, bearer, session, csrf, reset or jwt. A bare
// token, signature or sig also names a lexer token or a blockchain
// transaction, so it counts only when the other side is named for a secret
// too; a comparison with a hash, an id or an address compares identifiers.
// The comparison must decide something about the caller: the condition of
// an if that returns, or a returned expression. A comparison with a
// constant (an empty check, a token kind) reveals nothing, and tests are
// left alone.
type SecretCompareNotConstantTimeRule struct {
	*rules.BaseRule
}

// NewSecretCompareNotConstantTimeRule creates the rule
func NewSecretCompareNotConstantTimeRule() *SecretCompareNotConstantTimeRule {
	return &SecretCompareNotConstantTimeRule{BaseRule: rules.NewBaseRule(
		"secret-compare-not-constant-time",
		"security",
		"Detects a signature, token, key or password compared with ==, != or bytes.Equal instead of a constant-time comparison",
		core.SeverityMedium,
	)}
}

// AnalyzeFile is a no-op: operand types and constants need type information.
func (r *SecretCompareNotConstantTimeRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *SecretCompareNotConstantTimeRule) RequiresSSA() bool { return false }

// AnalyzeGoProject reports the secret comparisons of the project's files.
func (r *SecretCompareNotConstantTimeRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(fileCtx *core.FileContext, info *types.Info) []*core.Violation {
		if fileCtx.IsTestFile() {
			return nil
		}
		var violations []*core.Violation
		parents := helpers.ParentMap(fileCtx.GoAST)
		ast.Inspect(fileCtx.GoAST, func(n ast.Node) bool {
			x, y, ok := comparedOperands(n, info)
			if !ok || !secretCompared(x, y, info) || !decides(n, parents) {
				return true
			}
			line := fileCtx.LineFor(n)
			if fileCtx.IsSuppressed(line, r.Name()) {
				return true
			}
			v := r.CreateViolation(fileCtx.RelPath, line,
				"A secret is compared byte by byte — the time the comparison takes tells a caller how much of a guessed value was right")
			v.WithCode(strings.TrimSpace(fileCtx.GetLine(line)))
			v.WithSuggestion("Compare with hmac.Equal or subtle.ConstantTimeCompare")
			v.WithContext("pattern", "secret_compare_not_constant_time")
			violations = append(violations, v)
			return true
		})
		return violations
	})
}

// comparedOperands returns the operands of x == y, x != y and
// bytes.Equal(x, y).
func comparedOperands(n ast.Node, info *types.Info) (ast.Expr, ast.Expr, bool) {
	switch node := n.(type) {
	case *ast.BinaryExpr:
		if node.Op == token.EQL || node.Op == token.NEQ {
			return node.X, node.Y, true
		}
	case *ast.CallExpr:
		fn, ok := typeutil.Callee(info, node).(*types.Func)
		if ok && fn.Pkg() != nil && fn.Pkg().Path() == "bytes" && fn.Name() == "Equal" && len(node.Args) == 2 {
			return node.Args[0], node.Args[1], true
		}
	}
	return nil, nil, false
}

// secretCompared reports two non-constant strings or byte slices named for
// a secret: one unambiguously, or both by a bare token or signature.
func secretCompared(x, y ast.Expr, info *types.Info) bool {
	for _, operand := range []ast.Expr{x, y} {
		tv, ok := info.Types[operand]
		if !ok || tv.Value != nil || tv.IsNil() || !stringOrBytes(tv.Type) {
			return false
		}
	}
	xs, ys := secretKind(x), secretKind(y)
	if xs == notSecret || ys == notSecret {
		return false
	}
	return xs == strongSecret || ys == strongSecret || (xs == weakSecret && ys == weakSecret)
}

// decides reports a comparison that is the condition (or a part of it) of
// an if whose body returns, or part of a returned expression.
func decides(n ast.Node, parents map[ast.Node]ast.Node) bool {
	child := n
	for parent := parents[child]; parent != nil; child, parent = parent, parents[parent] {
		switch p := parent.(type) {
		case *ast.BinaryExpr, *ast.UnaryExpr, *ast.ParenExpr:
			continue
		case *ast.ReturnStmt:
			return true
		case *ast.IfStmt:
			return p.Cond == child && returns(p.Body)
		default:
			return false
		}
	}
	return false
}

func returns(body *ast.BlockStmt) bool {
	for _, stmt := range body.List {
		if _, ok := stmt.(*ast.ReturnStmt); ok {
			return true
		}
	}
	return false
}

func stringOrBytes(t types.Type) bool {
	switch u := t.Underlying().(type) {
	case *types.Basic:
		return u.Info()&types.IsString != 0
	case *types.Slice:
		elem, ok := u.Elem().Underlying().(*types.Basic)
		return ok && elem.Kind() == types.Byte
	}
	return false
}

// secretness classifies an operand of a comparison by its name.
type secretness int

const (
	plainValue   secretness = iota // a name that says nothing
	notSecret                      // an identifier: hash, id, address
	weakSecret                     // a bare token, signature or sig
	strongSecret                   // a secret, password, qualified key or token
)

var (
	strongSecretNouns = map[string]bool{"secret": true, "hmac": true, "password": true, "passwd": true, "apikey": true}
	weakSecretNouns   = map[string]bool{"token": true, "signature": true, "sig": true}
	identifierNouns   = map[string]bool{"hash": true, "id": true, "ids": true, "address": true, "addr": true, "txid": true}
	secretQualifiers  = map[string]map[string]bool{
		"key": {
			"api": true, "secret": true, "private": true, "public": true, "access": true,
			"signing": true, "webhook": true, "auth": true, "client": true, "shared": true,
			"processing": true,
		},
		"token": {
			"access": true, "refresh": true, "auth": true, "api": true, "bearer": true,
			"session": true, "csrf": true, "reset": true, "jwt": true,
		},
	}
)

// secretKind classifies a variable or field by the last words of its name.
func secretKind(expr ast.Expr) secretness {
	var name string
	switch e := ast.Unparen(expr).(type) {
	case *ast.Ident:
		name = e.Name
	case *ast.SelectorExpr:
		name = e.Sel.Name
	case *ast.StarExpr:
		return secretKind(e.X)
	default:
		return plainValue
	}
	words := helpers.IdentifierWords(name)
	if len(words) == 0 {
		return plainValue
	}
	last := words[len(words)-1]
	switch {
	case identifierNouns[last]:
		return notSecret
	case strongSecretNouns[last]:
		return strongSecret
	case len(words) > 1 && secretQualifiers[last][words[len(words)-2]]:
		return strongSecret
	case weakSecretNouns[last]:
		return weakSecret
	}
	return plainValue
}
