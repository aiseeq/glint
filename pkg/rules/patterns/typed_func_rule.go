package patterns

import (
	"fmt"
	"go/ast"
	"go/types"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

// funcScope is what a typed function check sees: the types of the function's
// package and the declarations of the loaded packages, to follow a call.
type funcScope struct {
	info  *types.Info
	decls map[*types.Func]typedFuncDecl
}

// callee returns the declaration a static call reaches, ok false for a call
// whose body is not loaded (a library, an interface method, a func value).
func (s funcScope) callee(call *ast.CallExpr) (typedFuncDecl, bool) {
	fn := staticFunc(s.info, call)
	if fn == nil {
		return typedFuncDecl{}, false
	}
	decl, ok := s.decls[fn.Origin()]
	return decl, ok
}

// funcFinding is one report of a function check: where and what.
type funcFinding struct {
	node    ast.Node
	message string
}

// typedFuncRule is a rule that checks every function declaration of the
// production files of a typed Go project; check returns the findings of one
// function.
type typedFuncRule struct {
	*rules.BaseRule
	suggestion string
	check      func(scope funcScope, fn *ast.FuncDecl) []funcFinding
}

// AnalyzeFile is a no-op: the check needs types.
func (r *typedFuncRule) AnalyzeFile(_ *core.FileContext) []*core.Violation { return nil }

// RequiresSSA reports that typed syntax is enough.
func (r *typedFuncRule) RequiresSSA() bool { return false }

// AnalyzeGoProject runs the check over every function of the project.
func (r *typedFuncRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%s: nil Go project context", r.Name())
	}
	decls, err := funcDeclsByObject(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", r.Name(), err)
	}
	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(file *core.FileContext, info *types.Info) []*core.Violation {
		scope := funcScope{info: info, decls: decls}
		return analyzeGoFunctions(file, func(fn *ast.FuncDecl) []*core.Violation {
			var violations []*core.Violation
			for _, f := range r.check(scope, fn) {
				line := file.LineFor(f.node)
				if file.IsSuppressed(line, r.Name()) {
					continue
				}
				v := r.CreateViolation(file.RelPath, line, f.message)
				v.WithCode(strings.TrimSpace(file.GetLine(line)))
				v.WithSuggestion(r.suggestion)
				violations = append(violations, v)
			}
			return violations
		})
	})
}
