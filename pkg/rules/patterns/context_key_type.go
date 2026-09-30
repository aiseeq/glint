package patterns

import (
	"fmt"
	"go/ast"
	"go/types"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewContextKeyBuiltinTypeRule())
}

// ContextKeyBuiltinTypeRule detects a context value read or stored under a
// key of a built-in type:
//
//	userID, ok := r.Context().Value("userID").(string)
//	// the middleware stored it under ctxKey("userID"): ok is always false
//
//	ctx = context.WithValue(ctx, "role", role)
//
// A context compares keys by type and value, so "userID" and
// ctxKey("userID") are different keys: the reader gets nil and takes the
// request as anonymous. Keys of a built-in type also collide between
// packages. Keys belong to an unexported type of the package that owns
// them. Only context.Context's Value and context.WithValue are checked: a
// type of its own with a Value method, a web framework's context, keeps
// its own string keys.
type ContextKeyBuiltinTypeRule struct {
	*rules.BaseRule
}

// NewContextKeyBuiltinTypeRule creates the rule
func NewContextKeyBuiltinTypeRule() *ContextKeyBuiltinTypeRule {
	return &ContextKeyBuiltinTypeRule{BaseRule: rules.NewBaseRule(
		"context-key-builtin-type",
		"patterns",
		"Detects a context value read or stored under a key of a built-in type (a string, a number)",
		core.SeverityHigh,
	)}
}

// AnalyzeFile is a no-op: key types are known only with type information.
func (r *ContextKeyBuiltinTypeRule) AnalyzeFile(_ *core.FileContext) []*core.Violation { return nil }

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *ContextKeyBuiltinTypeRule) RequiresSSA() bool { return false }

// AnalyzeGoProject reports the context keys of built-in types.
func (r *ContextKeyBuiltinTypeRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(fileCtx *core.FileContext, info *types.Info) []*core.Violation {
		var violations []*core.Violation
		ast.Inspect(fileCtx.GoAST, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			key, verb, ok := contextKeyArg(call, info)
			if !ok {
				return true
			}
			basic, ok := info.TypeOf(key).(*types.Basic)
			if !ok {
				return true
			}
			line := fileCtx.LineFor(key)
			if fileCtx.IsSuppressed(line, r.Name()) {
				return true
			}
			v := r.CreateViolation(fileCtx.RelPath, line, fmt.Sprintf(
				"Context value %s under a %s key — a key of another type with the same text is a different key, and packages using the same string collide",
				verb, types.Default(basic).String()))
			v.WithCode(strings.TrimSpace(fileCtx.GetLine(line)))
			v.WithSuggestion("Use a key of an unexported type of the package that owns the value (type ctxKey string; const userIDKey ctxKey = \"userID\"), the same one the writer uses")
			violations = append(violations, v)
			return true
		})
		return violations
	})
}

// contextKeyArg returns the key of ctx.Value(key) on a context.Context or of
// context.WithValue(parent, key, value).
func contextKeyArg(call *ast.CallExpr, info *types.Info) (ast.Expr, string, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return nil, "", false
	}
	fn, ok := info.Uses[sel.Sel].(*types.Func)
	if !ok || fn.Pkg() == nil || fn.Pkg().Path() != "context" {
		return nil, "", false
	}
	switch {
	case fn.Name() == "Value" && len(call.Args) == 1:
		return call.Args[0], "read", true
	case fn.Name() == "WithValue" && len(call.Args) == 3:
		return call.Args[1], "stored", true
	}
	return nil, "", false
}
