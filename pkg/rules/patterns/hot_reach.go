package patterns

import (
	"cmp"
	"fmt"
	"go/ast"
	"go/types"
	"slices"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

// hotFunction is a function a hot-path rule checks: one marked //glint:hot,
// or one a marked function reaches through static calls of loaded bodies.
type hotFunction struct {
	// chain is the call path from the marked function to this one; a marked
	// function's chain is its own name.
	chain []string
}

// in describes where a finding of the function is, for a rule's message.
func (h hotFunction) in() string {
	if len(h.chain) == 1 {
		return " in hot function " + h.chain[0]
	}
	return " in " + h.chain[len(h.chain)-1] + ", which hot function " + h.chain[0] + " reaches through " + strings.Join(h.chain, " → ")
}

// hotReachKey caches the hot functions of one run per rule and reach.
type hotReachKey struct {
	rule       string
	transitive bool
}

// hotFunctions returns the functions marked //glint:hot and, when transitive,
// every loaded function they reach through static calls - a call through an
// interface or a func value is not followed. A call whose line carries the
// rule's suppression (a cold branch: the first frame, an error) is not
// followed either. Each reached function keeps the shortest chain from the
// first marked function in position order.
func hotFunctions(ctx *core.GoProjectContext, rule string, transitive bool) (map[*ast.FuncDecl]hotFunction, error) {
	return core.Shared(ctx, hotReachKey{rule: rule, transitive: transitive}, func() (map[*ast.FuncDecl]hotFunction, error) {
		decls, err := funcDeclsByObject(ctx)
		if err != nil {
			return nil, err
		}
		var roots []typedFuncDecl
		for _, decl := range decls {
			if hasDirective(decl.decl.Doc, hotFunctionDirective) {
				roots = append(roots, decl)
			}
		}
		slices.SortFunc(roots, func(a, b typedFuncDecl) int { return cmp.Compare(a.decl.Pos(), b.decl.Pos()) })

		hot := make(map[*ast.FuncDecl]hotFunction, len(roots))
		queue := make([]typedFuncDecl, 0, len(roots))
		for _, root := range roots {
			hot[root.decl] = hotFunction{chain: []string{qualifiedFuncName(root.decl)}}
			queue = append(queue, root)
		}
		if !transitive {
			return hot, nil
		}
		for len(queue) > 0 {
			caller := queue[0]
			queue = queue[1:]
			chain := hot[caller.decl].chain
			for _, callee := range hotCallees(ctx, rule, caller, decls) {
				if _, seen := hot[callee.decl]; seen {
					continue
				}
				hot[callee.decl] = hotFunction{chain: append(slices.Clip(chain), qualifiedFuncName(callee.decl))}
				queue = append(queue, callee)
			}
		}
		return hot, nil
	})
}

// hotCallees returns the loaded functions a body calls statically, in call
// order, leaving out the calls on a branch that ends in failure and the
// calls whose line suppresses the rule.
func hotCallees(ctx *core.GoProjectContext, rule string, caller typedFuncDecl, decls map[*types.Func]typedFuncDecl) []typedFuncDecl {
	cold := coldBlocks(caller.info, caller.decl)
	var callees []typedFuncDecl
	ast.Inspect(caller.decl.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if insideNodes(cold, call) {
			return true
		}
		fn := staticFunc(caller.info, call)
		if fn == nil {
			return true
		}
		callee, loaded := decls[fn.Origin()]
		if !loaded {
			return true
		}
		// A caller outside the run has no file context to carry a
		// suppression, and its call is followed.
		if file, err := ctx.FileForPosition(call.Pos()); err == nil && file.IsSuppressed(file.LineFor(call), rule) {
			return true
		}
		callees = append(callees, callee)
		return true
	})
	return callees
}

// hotScope is what a hot function check sees: the function's file and
// package types, where the function is for the message, and, when the rule
// runs with escape: true, what the compiler's escape analysis says about it.
type hotScope struct {
	file    *ast.File
	info    *types.Info
	in      string
	escapes *escapeNotes
}

// hotFuncRule is a rule that checks the hot functions of a typed Go project;
// check returns the findings of one function.
//
// With transitive: true the rule also checks every function of the module a
// marked function reaches through static calls: the mark goes on the root of
// the tick, while the work is done by what it calls. A call through an
// interface or a func value is not followed, nor is a call whose line carries
// the rule's suppression (a cold branch: the first frame, a debug observer).
//
// A branch that ends in failure - returns a non-nil error or panics - is
// cold in every mode: its findings are not reported and its calls are not
// followed.
type hotFuncRule struct {
	*rules.BaseRule
	suggestion string
	check      func(scope hotScope, fn *ast.FuncDecl) []funcFinding
	transitive bool
	// takesEscape reports a rule whose check reads the compiler's escape
	// analysis; escape is the escape: true setting of such a rule.
	takesEscape bool
	escape      bool
}

// Configure reads transitive - whether functions reached from a marked one
// are hot too - and, for a rule that takes it, escape.
func (r *hotFuncRule) Configure(settings map[string]any) error {
	transitive, _, err := rules.BoolSetting(settings, r.Name(), "transitive")
	if err != nil {
		return err
	}
	escape, present, err := rules.BoolSetting(settings, r.Name(), "escape")
	if err != nil {
		return err
	}
	if present && !r.takesEscape {
		return fmt.Errorf("configure %s: the rule has no escape setting", r.Name())
	}
	if err := r.BaseRule.Configure(settings); err != nil {
		return err
	}
	r.transitive, r.escape = transitive, escape
	return nil
}

// AnalyzeFile is a no-op: the checks need types.
func (r *hotFuncRule) AnalyzeFile(_ *core.FileContext) []*core.Violation { return nil }

// RequiresSSA reports that typed syntax is enough.
func (r *hotFuncRule) RequiresSSA() bool { return false }

// AnalyzeGoProject checks every hot function.
func (r *hotFuncRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%s: nil Go project context", r.Name())
	}
	hot, err := hotFunctions(ctx, r.Name(), r.transitive)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", r.Name(), err)
	}
	var escapes *escapeNotes
	if r.escape {
		if escapes, err = compilerEscapes(ctx, hot, r.transitive); err != nil {
			return nil, fmt.Errorf("%s: %w", r.Name(), err)
		}
	}
	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(file *core.FileContext, info *types.Info) []*core.Violation {
		return analyzeGoFunctions(file, func(fn *ast.FuncDecl) []*core.Violation {
			h, isHot := hot[fn]
			if !isHot {
				return nil
			}
			var violations []*core.Violation
			scope := hotScope{file: file.GoAST, info: info, in: h.in(), escapes: escapes}
			cold := coldBlocks(info, fn)
			for _, f := range r.check(scope, fn) {
				if insideNodes(cold, f.node) {
					continue
				}
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

// coldBlocks returns the branches of a function body that end in failure: an
// if, else, case or select clause whose last statement returns a non-nil
// error or panics. Such a branch runs once per failure, not on every call, so
// what it allocates is not garbage of every tick.
func coldBlocks(info *types.Info, fn *ast.FuncDecl) []ast.Node {
	var cold []ast.Node
	consider := func(node ast.Node, list []ast.Stmt) {
		if len(list) > 0 && failsHere(info, list[len(list)-1]) {
			cold = append(cold, node)
		}
	}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.IfStmt:
			consider(node.Body, node.Body.List)
			if block, ok := node.Else.(*ast.BlockStmt); ok {
				consider(block, block.List)
			}
		case *ast.CaseClause:
			consider(node, node.Body)
		case *ast.CommClause:
			consider(node, node.Body)
		}
		return true
	})
	return cold
}

// failsHere reports a statement that leaves the function in failure: a
// return whose last result is a non-nil error, or a panic.
func failsHere(info *types.Info, stmt ast.Stmt) bool {
	switch s := stmt.(type) {
	case *ast.ReturnStmt:
		if len(s.Results) == 0 {
			return false
		}
		last := ast.Unparen(s.Results[len(s.Results)-1])
		if isNilIdent(last) {
			return false
		}
		t := info.TypeOf(last)
		return t != nil && implementsError(t)
	case *ast.ExprStmt:
		call, ok := s.X.(*ast.CallExpr)
		return ok && builtinCallName(info, call) == "panic"
	}
	return false
}

// insideNodes reports whether node lies inside one of the nodes.
func insideNodes(nodes []ast.Node, node ast.Node) bool {
	for _, n := range nodes {
		if n.Pos() <= node.Pos() && node.End() <= n.End() {
			return true
		}
	}
	return false
}
