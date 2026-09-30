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
	rules.Register(NewContextFirstRule())
}

// entryPointFuncs legitimately create the root context of the program.
var entryPointFuncs = map[string]bool{"main": true, "init": true, "TestMain": true}

// ContextFirstRule detects a function that needs a context, does not accept one,
// and therefore invents its own:
//
//	func (s *Service) SyncWallet(address string) error {
//	    ctx := context.Background()          // the caller's deadline is gone
//	    return s.repo.Save(ctx, address)
//	}
//
// The call chain silently stops being cancellable at this function: a request
// the user aborted keeps running, a shutdown waits for work nobody needs, and a
// deadline set three frames up applies to nothing below.
//
// The rule looks at what the function does, not at what it is called: a function
// that hands no context to anything needs none, whatever its name. Functions
// that already accept a context are the business of context-background, which
// reports the same misuse from the other side.
//
// Not flagged: package main and the entry points init/TestMain, where the root
// context of the program has to come from somewhere; contexts created for a
// goroutine that outlives the call; and contexts whose cancel function is stored
// rather than deferred, which belong to something started here and stopped
// elsewhere.
type ContextFirstRule struct {
	*rules.BaseRule
}

// NewContextFirstRule creates the rule
func NewContextFirstRule() *ContextFirstRule {
	return &ContextFirstRule{
		BaseRule: rules.NewBaseRule(
			"context-first",
			"patterns",
			"Detects functions that create their own context.Background instead of accepting one, breaking the caller's cancellation",
			core.SeverityMedium,
		),
	}
}

// AnalyzeFile checks one file without type information: context.Context and
// context.Background are known through the file's import of "context".
func (r *ContextFirstRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	return r.analyze(ctx, nil)
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *ContextFirstRule) RequiresSSA() bool { return false }

// AnalyzeGoProject checks every file, with type information where the package
// has it.
func (r *ContextFirstRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	return rules.AnalyzeGoFiles(ctx, r.Name(), r.analyze)
}

// analyze reports every function that manufactures the context it should have
// been given.
func (r *ContextFirstRule) analyze(ctx *core.FileContext, info *types.Info) []*core.Violation {
	if !ctx.IsGoFile() || !ctx.HasGoAST() || ctx.IsTestFile() {
		return nil
	}
	// Package main is where the root context of the program is born; there is no
	// caller above it to inherit one from.
	if ctx.GoAST.Name != nil && ctx.GoAST.Name.Name == "main" {
		return nil
	}

	var violations []*core.Violation

	for _, decl := range ctx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || fn.Name == nil {
			continue
		}
		if accepts, _ := contextParams(ctx.GoAST, info, fn.Type); entryPointFuncs[fn.Name.Name] || accepts {
			continue
		}
		for _, call := range manufacturedContexts(ctx.GoAST, info, fn.Body) {
			violations = append(violations, r.report(ctx, fn, call))
		}
	}

	return violations
}

func (r *ContextFirstRule) report(ctx *core.FileContext, fn *ast.FuncDecl, call *ast.CallExpr) *core.Violation {
	line := ctx.LineFor(call)
	v := r.CreateViolation(ctx.RelPath, line,
		fmt.Sprintf("%s takes no context but creates its own here — the caller's cancellation and deadline stop at this call",
			qualifiedFuncName(fn)))
	v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
	v.WithSuggestion(fmt.Sprintf("Accept ctx context.Context as the first parameter of %s and pass it down instead of creating a new one",
		fn.Name.Name))
	v.WithContext("pattern", "context_not_accepted")
	v.WithContext("function", fn.Name.Name)
	return v
}

// manufacturedContexts returns the context.Background/TODO calls of the body
// whose result is handed to another call — that is what makes the function the
// place where cancellation ends, rather than a place that merely mentions a
// context.
func manufacturedContexts(file *ast.File, info *types.Info, body *ast.BlockStmt) []*ast.CallExpr {
	var created []*ast.CallExpr
	names := make(map[string]*ast.CallExpr)
	deferredCancels := deferredCalls(body)

	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.GoStmt:
			// A goroutine outliving the call has no caller context to inherit.
			return false
		case *ast.AssignStmt:
			for i, rhs := range node.Rhs {
				call, ok := rootContextCall(file, info, rhs)
				if !ok || i >= len(node.Lhs) {
					continue
				}
				if outlivesCall(node.Lhs, deferredCancels) {
					continue
				}
				if ident, ok := node.Lhs[i].(*ast.Ident); ok {
					names[ident.Name] = call
				}
			}
		case *ast.CallExpr:
			if _, building := rootContextCall(file, info, node); building {
				// context.WithTimeout(context.Background(), d) still builds the
				// context; what counts is where the result is handed over.
				return true
			}
			for _, arg := range node.Args {
				if call, ok := rootContextCall(file, info, arg); ok {
					created = append(created, call)
					continue
				}
				ident, ok := arg.(*ast.Ident)
				if !ok {
					continue
				}
				if call, known := names[ident.Name]; known {
					created = append(created, call)
					delete(names, ident.Name)
				}
			}
		}
		return true
	})

	return created
}

// outlivesCall reports whether the context being assigned belongs to something
// that keeps running after the call returns: its cancel function is stored, or
// handed on, instead of being deferred here. A scheduler started in one method
// and stopped in another has no caller context to inherit.
func outlivesCall(targets []ast.Expr, deferredCancels map[string]bool) bool {
	if len(targets) < 2 {
		return false
	}
	switch cancel := targets[1].(type) {
	case *ast.Ident:
		return cancel.Name != "_" && !deferredCancels[cancel.Name]
	default:
		// Assigned to a field or an index: the owner cancels it later.
		return true
	}
}

// deferredCalls returns the names of the functions the body defers.
func deferredCalls(body *ast.BlockStmt) map[string]bool {
	deferred := make(map[string]bool)
	ast.Inspect(body, func(n ast.Node) bool {
		stmt, ok := n.(*ast.DeferStmt)
		if !ok {
			return true
		}
		if ident, ok := stmt.Call.Fun.(*ast.Ident); ok {
			deferred[ident.Name] = true
		}
		return true
	})
	return deferred
}

// rootContextCall reports whether the expression starts a fresh context chain,
// seeing through the wrappers that derive from one: context.WithTimeout(context.
// Background(), d) is still a root.
func rootContextCall(file *ast.File, info *types.Info, expr ast.Expr) (*ast.CallExpr, bool) {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return nil, false
	}
	name, ok := packageFuncName(file, info, call, "context")
	if !ok {
		return nil, false
	}
	if name == "Background" || name == "TODO" {
		return call, true
	}
	if !strings.HasPrefix(name, "With") || len(call.Args) == 0 {
		return nil, false
	}
	return rootContextCall(file, info, call.Args[0])
}

func qualifiedFuncName(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return fn.Name.Name
	}
	if typeName := receiverTypeName(fn.Recv); typeName != "" {
		return typeName + "." + fn.Name.Name
	}
	return fn.Name.Name
}
