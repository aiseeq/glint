package patterns

import (
	"fmt"
	"go/ast"
	"go/types"
	"runtime"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewLargeValueCopiedPerElementRule())
}

// defaultLargeValueMaxBytes is the size up to which a copy of a value is
// cheap: two cache lines.
const defaultLargeValueMaxBytes = 128

// LargeValueCopiedPerElementRule detects a large value copied once per element
// of a collection: the value variable of a range over a slice, an array or a
// map of large values, and a by-value parameter of the element type in a
// function handed to a call together with the collection (a slices.SortFunc,
// BinarySearchFunc or DeleteFunc callback, a generic filter, a method of a
// named slice). Each copy is a memmove of the whole value, and in a loop over
// many elements the copies cost more than the comparison or the sum they feed.
type LargeValueCopiedPerElementRule struct {
	*rules.BaseRule
	maxBytes int64
}

// NewLargeValueCopiedPerElementRule creates the rule.
func NewLargeValueCopiedPerElementRule() *LargeValueCopiedPerElementRule {
	return &LargeValueCopiedPerElementRule{
		BaseRule: rules.NewBaseRule(
			"large-value-copied-per-element",
			"patterns",
			"Detects a value over max_bytes (128) copied for every element: the value of a range over a slice, array or map of large structs, and a by-value parameter of the element type in a callback passed with the collection (slices.SortFunc, BinarySearchFunc, DeleteFunc, a generic filter) — in a hot loop the copies cost more than the work",
			core.SeverityMedium,
		),
		maxBytes: defaultLargeValueMaxBytes,
	}
}

// Configure reads max_bytes, the largest size copied without a report.
func (r *LargeValueCopiedPerElementRule) Configure(settings map[string]any) error {
	if err := r.BaseRule.Configure(settings); err != nil {
		return err
	}
	r.maxBytes = int64(r.GetIntSetting("max_bytes", defaultLargeValueMaxBytes))
	return nil
}

// AnalyzeFile is a no-op: the size of a type needs type information.
func (r *LargeValueCopiedPerElementRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough.
func (r *LargeValueCopiedPerElementRule) RequiresSSA() bool { return false }

// AnalyzeGoProject checks every production file of the typed project.
func (r *LargeValueCopiedPerElementRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	sizes := projectSizes(ctx)
	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(file *core.FileContext, info *types.Info) []*core.Violation {
		check := largeCopyCheck{info: info, sizes: sizes, maxBytes: r.maxBytes}
		var violations []*core.Violation
		ast.Inspect(file.GoAST, func(n ast.Node) bool {
			var findings []funcFinding
			switch node := n.(type) {
			case *ast.RangeStmt:
				findings = check.rangeValue(node)
			case *ast.CallExpr:
				findings = check.callbacks(node)
			}
			for _, f := range findings {
				line := file.LineFor(f.node)
				if file.IsSuppressed(line, r.Name()) {
					continue
				}
				v := r.CreateViolation(file.RelPath, line, f.message)
				v.WithCode(strings.TrimSpace(file.GetLine(line)))
				v.WithSuggestion("Range over the index and use &xs[i], keep pointers in the collection, or use an index form (sort.Search, sort.Slice, a loop over i) instead of the by-value callback")
				violations = append(violations, v)
			}
			return true
		})
		return violations
	})
}

// projectSizes returns the sizes of the platform the project was loaded for;
// one load has one platform.
func projectSizes(ctx *core.GoProjectContext) types.Sizes {
	for _, pkg := range ctx.Packages {
		if pkg != nil && pkg.Package != nil && pkg.Package.TypesSizes != nil {
			return pkg.Package.TypesSizes
		}
	}
	return types.SizesFor("gc", runtime.GOARCH)
}

// largeCopyCheck finds the per-element copies of one file.
type largeCopyCheck struct {
	info     *types.Info
	sizes    types.Sizes
	maxBytes int64
}

// large reports the size of t when it is over the limit.
func (c largeCopyCheck) large(t types.Type) (int64, bool) {
	if t == nil {
		return 0, false
	}
	switch t.Underlying().(type) {
	case *types.Struct, *types.Array:
	default:
		return 0, false
	}
	size := c.sizes.Sizeof(t)
	return size, size > c.maxBytes
}

// qualifiedTypeName spells t with package names, as the code that uses it does.
func qualifiedTypeName(t types.Type) string {
	return types.TypeString(t, func(p *types.Package) string { return p.Name() })
}

// rangeValue reports the value variable of a range over large elements.
func (c largeCopyCheck) rangeValue(stmt *ast.RangeStmt) []funcFinding {
	if stmt.Value == nil {
		return nil
	}
	if ident, ok := stmt.Value.(*ast.Ident); ok && ident.Name == "_" {
		return nil
	}
	elem := elementType(c.info.TypeOf(stmt.X))
	size, ok := c.large(elem)
	if !ok {
		return nil
	}
	return []funcFinding{{
		node: stmt.Value,
		message: fmt.Sprintf("range value %s copies %s (%d bytes) on every iteration",
			types.ExprString(stmt.Value), qualifiedTypeName(elem), size),
	}}
}

// callbacks reports a function argument of the call that takes, by value, a
// large element of a collection passed in the same call (an argument or the
// receiver): the callee calls it once per element.
func (c largeCopyCheck) callbacks(call *ast.CallExpr) []funcFinding {
	elems := c.collectionElements(call)
	if len(elems) == 0 {
		return nil
	}
	var findings []funcFinding
	for _, arg := range call.Args {
		sig, what := c.funcArgument(arg)
		if sig == nil {
			continue
		}
		for i := 0; i < sig.Params().Len(); i++ {
			param := sig.Params().At(i).Type()
			size, ok := c.large(param)
			if !ok || !containsIdentical(elems, param) {
				continue
			}
			findings = append(findings, funcFinding{
				node: arg,
				message: fmt.Sprintf("%s passed to %s takes %s (%d bytes) by value — the element is copied on every call",
					what, core.ExtractFullFunctionName(call), qualifiedTypeName(param), size),
			})
			break
		}
	}
	return findings
}

// collectionElements returns the element types of the call's collection
// arguments and of the receiver of a method call.
func (c largeCopyCheck) collectionElements(call *ast.CallExpr) []types.Type {
	var elems []types.Type
	add := func(expr ast.Expr) {
		if elem := elementType(c.info.TypeOf(expr)); elem != nil {
			elems = append(elems, elem)
		}
	}
	if sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr); ok {
		if selection, isMethod := c.info.Selections[sel]; isMethod && selection.Kind() == types.MethodVal {
			add(sel.X)
		}
	}
	for _, arg := range call.Args {
		add(arg)
	}
	return elems
}

// funcArgument returns the signature of an argument that is a function
// literal or names a declared function, with a description for the message.
func (c largeCopyCheck) funcArgument(arg ast.Expr) (*types.Signature, string) {
	switch a := ast.Unparen(arg).(type) {
	case *ast.FuncLit:
		sig, _ := c.info.TypeOf(a).(*types.Signature)
		return sig, "the function literal"
	case *ast.Ident:
		return c.declaredFunc(a)
	case *ast.SelectorExpr:
		return c.declaredFunc(a.Sel)
	}
	return nil, ""
}

// declaredFunc returns the signature of the function or method ident names.
func (c largeCopyCheck) declaredFunc(ident *ast.Ident) (*types.Signature, string) {
	fn, ok := c.info.Uses[ident].(*types.Func)
	if !ok {
		return nil, ""
	}
	sig, _ := fn.Type().(*types.Signature)
	return sig, "function " + fn.Name()
}

// containsIdentical reports whether t is one of types.
func containsIdentical(list []types.Type, t types.Type) bool {
	for _, item := range list {
		if types.Identical(item, t) {
			return true
		}
	}
	return false
}
