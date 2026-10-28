package patternkit

import (
	"fmt"
	"go/ast"
	"go/types"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

// FuncScope is what a typed function check sees: the types of the function's
// package and the declarations of the loaded packages, to follow a call.
type FuncScope struct {
	Info    *types.Info
	Decls   map[*types.Func]TypedFuncDecl
	Callers map[*types.Func][]FuncCallSite
}

// Callee returns the declaration a static call reaches, ok false for a call
// whose body is not loaded (a library, an interface method, a func value).
func (s FuncScope) Callee(call *ast.CallExpr) (TypedFuncDecl, bool) {
	fn := StaticFunc(s.Info, call)
	if fn == nil {
		return TypedFuncDecl{}, false
	}
	decl, ok := s.Decls[fn.Origin()]
	return decl, ok
}

// FuncFinding is one report of a function check: where and what.
type FuncFinding struct {
	Node    ast.Node
	Message string
}

// TypedFuncRule is a rule that checks every function declaration of the
// production files of a typed Go project; check returns the findings of one
// function.
type TypedFuncRule struct {
	*rules.BaseRule
	Suggestion string
	Check      func(scope FuncScope, fn *ast.FuncDecl) []FuncFinding
	// ForProject, when set, builds the check of one run from the declarations
	// of the whole project: what the check compares a function with is
	// collected once per run, not kept on the shared rule.
	ForProject func(decls map[*types.Func]TypedFuncDecl) func(scope FuncScope, fn *ast.FuncDecl) []FuncFinding
	// SeverityOf, when set, gives the severity of the findings of one
	// function, raising the default where the cost matters more (a hot
	// function); it never lowers it.
	SeverityOf func(fn *ast.FuncDecl) core.Severity
}

// AnalyzeFile is a no-op: the check needs types.
func (r *TypedFuncRule) AnalyzeFile(_ *core.FileContext) []*core.Violation { return nil }

// RequiresSSA reports that typed syntax is enough.
func (r *TypedFuncRule) RequiresSSA() bool { return false }

// AnalyzeGoProject runs the check over every function of the project.
func (r *TypedFuncRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%s: nil Go project context", r.Name())
	}
	decls, err := FuncDeclsByObject(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", r.Name(), err)
	}
	callers, err := FuncCallSites(ctx, decls)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", r.Name(), err)
	}
	check := r.Check
	if r.ForProject != nil {
		check = r.ForProject(decls)
	}
	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(file *core.FileContext, info *types.Info) []*core.Violation {
		scope := FuncScope{Info: info, Decls: decls, Callers: callers}
		return AnalyzeGoFunctions(file, func(fn *ast.FuncDecl) []*core.Violation {
			var violations []*core.Violation
			for _, f := range check(scope, fn) {
				line := file.LineFor(f.Node)
				if file.IsSuppressed(line, r.Name()) {
					continue
				}
				v := r.CreateViolation(file.RelPath, line, f.Message)
				if r.SeverityOf != nil {
					v.Severity = max(v.Severity, r.SeverityOf(fn))
				}
				v.WithCode(strings.TrimSpace(file.GetLine(line)))
				v.WithSuggestion(r.Suggestion)
				violations = append(violations, v)
			}
			return violations
		})
	})
}

// NewTypedFuncRule returns the rule that runs check on every function with
// type information and gives suggestion with each finding.
func NewTypedFuncRule(base *rules.BaseRule, suggestion string, check func(scope FuncScope, fn *ast.FuncDecl) []FuncFinding) *TypedFuncRule {
	return &TypedFuncRule{BaseRule: base, Suggestion: suggestion, Check: check}
}

// WithInfo returns the scope of a function type-checked in info: the
// declarations and callers of the run stay the same.
func (s FuncScope) WithInfo(info *types.Info) FuncScope {
	return FuncScope{Info: info, Decls: s.Decls, Callers: s.Callers}
}
