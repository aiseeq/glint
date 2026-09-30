package patterns

import (
	"go/ast"
	"go/types"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewSleepWithoutContextRule())
}

// SleepWithoutContextRule detects time.Sleep inside a function that has a
// context.Context available (as a parameter or captured from the enclosing
// function). Cancelling the context does not interrupt the pause: a sync loop
// sleeping 250ms per item keeps running long after the caller gave up, and a
// graceful shutdown waits out every pending sleep.
//
// Typical case: a sync job sleeps between provider calls with a live ctx in
// scope; stopping the sync has to wait for the whole backlog of pauses.
type SleepWithoutContextRule struct {
	*rules.BaseRule
}

// NewSleepWithoutContextRule creates the rule.
func NewSleepWithoutContextRule() *SleepWithoutContextRule {
	return &SleepWithoutContextRule{
		BaseRule: rules.NewBaseRule(
			"sleep-without-context",
			"patterns",
			"Detects time.Sleep in functions that have a context.Context — cancellation does not interrupt the pause",
			core.SeverityLow,
		),
	}
}

// AnalyzeFile checks one file without type information: a struct carrying a
// context is seen only when this file declares it.
func (r *SleepWithoutContextRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	return r.analyze(ctx, nil)
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *SleepWithoutContextRule) RequiresSSA() bool { return false }

// AnalyzeGoProject checks every file, with type information where the package
// has it.
func (r *SleepWithoutContextRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	return rules.AnalyzeGoFiles(ctx, r.Name(), r.analyze)
}

// analyze flags time.Sleep calls that ignore an available context.
func (r *SleepWithoutContextRule) analyze(ctx *core.FileContext, info *types.Info) []*core.Violation {
	if !ctx.IsGoFile() || ctx.IsTestFile() || !ctx.HasGoAST() {
		return nil
	}

	carriers := structsCarryingContext(ctx.GoAST, info)
	check := &sleepCheck{rule: r, ctx: ctx, info: info, carriers: carriers}

	var violations []*core.Violation
	for _, decl := range ctx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		_, live := contextParams(ctx.GoAST, info, fn.Type)
		available := live || check.paramsCarryContext(fn.Type.Params) || check.paramsCarryContext(fn.Recv)
		violations = append(violations, check.body(fn.Body, available)...)
	}
	return violations
}

// sleepCheck carries what one file's check needs.
type sleepCheck struct {
	rule     *SleepWithoutContextRule
	ctx      *core.FileContext
	info     *types.Info
	carriers map[string]bool
}

// structsCarryingContext collects, for a file without type information, the
// same-file struct types with a context.Context field. A function taking such
// a struct has the caller's context in hand even though its own signature does
// not name one: the pause still ignores cancellation, and the caller still
// waits it out. With type information the parameter's type answers directly.
func structsCarryingContext(file *ast.File, info *types.Info) map[string]bool {
	carriers := make(map[string]bool)
	if info != nil {
		return carriers
	}
	ast.Inspect(file, func(n ast.Node) bool {
		spec, ok := n.(*ast.TypeSpec)
		if !ok {
			return true
		}
		structType, ok := spec.Type.(*ast.StructType)
		if !ok || structType.Fields == nil {
			return true
		}
		for _, field := range structType.Fields.List {
			if isContextTypeExpr(file, nil, field.Type) {
				carriers[spec.Name.Name] = true
				break
			}
		}
		return true
	})
	return carriers
}

// paramsCarryContext reports whether any named parameter (or the receiver) is
// a struct, or a pointer to one, with a context.Context field.
func (c *sleepCheck) paramsCarryContext(params *ast.FieldList) bool {
	if params == nil {
		return false
	}
	for _, param := range params.List {
		named := false
		for _, name := range param.Names {
			if name.Name != "_" {
				named = true
			}
		}
		if !named {
			continue
		}
		if c.info != nil {
			if structHasContextField(c.info.TypeOf(param.Type)) {
				return true
			}
			continue
		}
		if c.carriers[localTypeName(param.Type)] {
			return true
		}
	}
	return false
}

// structHasContextField reports whether t, or what it points to, is a struct
// with a context.Context field.
func structHasContextField(t types.Type) bool {
	if t == nil {
		return false
	}
	if ptr, ok := t.Underlying().(*types.Pointer); ok {
		t = ptr.Elem()
	}
	structType, ok := t.Underlying().(*types.Struct)
	if !ok {
		return false
	}
	for i := 0; i < structType.NumFields(); i++ {
		if isNamedType(structType.Field(i).Type(), "context", "Context") {
			return true
		}
	}
	return false
}

// localTypeName returns the name of a same-package type, following one pointer.
func localTypeName(expr ast.Expr) string {
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = star.X
	}
	ident, ok := expr.(*ast.Ident)
	if !ok {
		return ""
	}
	return ident.Name
}

// body walks one function body. ctxAvailable carries whether a live context
// is reachable at this nesting level; a closure inherits the enclosing
// function's context and may also introduce its own parameter.
func (c *sleepCheck) body(body *ast.BlockStmt, ctxAvailable bool) []*core.Violation {
	var violations []*core.Violation
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncLit:
			_, live := contextParams(c.ctx.GoAST, c.info, node.Type)
			violations = append(violations, c.body(node.Body, ctxAvailable || live)...)
			return false
		case *ast.CallExpr:
			if !ctxAvailable || !isPackageFuncCall(c.ctx.GoAST, c.info, node, "time", "Sleep") {
				return true
			}
			line := lineFromNode(c.ctx, node)
			if c.ctx.IsSuppressed(line, c.rule.Name()) {
				return true
			}
			v := c.rule.CreateViolation(c.ctx.RelPath, line,
				"time.Sleep in a function with context.Context — cancellation does not interrupt the pause")
			v.WithCode(c.ctx.GetLine(line))
			v.WithSuggestion("Wait in a ctx-aware way: select { case <-ctx.Done(): return ctx.Err(); case <-time.After(d): } or a shared sleepWithContext helper")
			violations = append(violations, v)
		}
		return true
	})
	return violations
}
