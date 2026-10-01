package patterns

import (
	"go/ast"
	"go/types"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewInterfaceParamIgnoredRule())
}

// InterfaceParamIgnoredRule detects a method implementing an interface of
// the project that blanks a parameter the interface names:
//
//	type Calculator interface {
//		PlatformProfit(ctx context.Context, strategy string, periodStart, periodEnd time.Time) (Result, error)
//	}
//	func (s *Service) PlatformProfit(ctx context.Context, strategy string, periodStart, _ time.Time) (Result, error)
//
// Callers pass the argument through the interface and trust it counts; the
// implementation drops it without a word - here a custom range always ends
// at the latest snapshot. Reported when the method uses another parameter of
// the same type (it handles the start and drops the end); a stub ignoring
// what it gets, a context, and a parameter the interface does not name are
// left out.
type InterfaceParamIgnoredRule struct {
	*rules.BaseRule
}

// NewInterfaceParamIgnoredRule creates the rule
func NewInterfaceParamIgnoredRule() *InterfaceParamIgnoredRule {
	return &InterfaceParamIgnoredRule{BaseRule: rules.NewBaseRule(
		"interface-param-ignored",
		"patterns",
		"Detects a method that blanks a parameter the interface it implements names — the argument callers pass is dropped",
		core.SeverityMedium,
	)}
}

// AnalyzeFile is a no-op: the interfaces a method implements need types.
func (r *InterfaceParamIgnoredRule) AnalyzeFile(_ *core.FileContext) []*core.Violation { return nil }

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *InterfaceParamIgnoredRule) RequiresSSA() bool { return false }

// AnalyzeGoProject reports the blanked parameters of the methods that
// implement an interface of the project.
func (r *InterfaceParamIgnoredRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	interfaces := projectInterfaces(ctx)
	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(file *core.FileContext, info *types.Info) []*core.Violation {
		var violations []*core.Violation
		for _, decl := range file.GoAST.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || fn.Body == nil {
				continue
			}
			obj, ok := info.Defs[fn.Name].(*types.Func)
			if !ok {
				continue
			}
			for _, blank := range droppedParams(fn, info) {
				iface, named := namingInterface(obj, blank.index, interfaces)
				line := file.LineFor(blank.name)
				if named == "" || file.IsSuppressed(line, r.Name()) {
					continue
				}
				v := r.CreateViolation(file.RelPath, line, "Parameter "+named+" of "+iface+"."+obj.Name()+" is blanked here — the implementation drops the argument callers pass through the interface")
				v.WithCode(strings.TrimSpace(file.GetLine(line)))
				v.WithSuggestion("Use the argument, or change the interface if no implementation needs it")
				violations = append(violations, v)
			}
		}
		return violations
	})
}

// droppedParam is a parameter named _, by its position in the signature.
type droppedParam struct {
	name  *ast.Ident
	index int
}

// droppedParams returns the parameters of a method named _ that are not a
// context and have a used sibling of the same type.
func droppedParams(fn *ast.FuncDecl, info *types.Info) []droppedParam {
	var dropped []droppedParam
	index := 0
	for _, field := range fn.Type.Params.List {
		if len(field.Names) == 0 {
			index++
			continue
		}
		typ := info.TypeOf(field.Type)
		for _, name := range field.Names {
			if name.Name == "_" && !isNamedType(typ, "context", "Context") && usedSibling(fn, info, typ) {
				dropped = append(dropped, droppedParam{name: name, index: index})
			}
			index++
		}
	}
	return dropped
}

// usedSibling reports a named parameter of the same type the method uses:
// it handles part of what the interface passes (a period's start) and drops
// the rest (its end). A stub ignoring all it gets is not this.
func usedSibling(fn *ast.FuncDecl, info *types.Info, typ types.Type) bool {
	used := make(map[types.Object]bool)
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok {
			if obj := info.Uses[id]; obj != nil {
				used[obj] = true
			}
		}
		return true
	})
	for _, field := range fn.Type.Params.List {
		for _, name := range field.Names {
			if obj := info.Defs[name]; obj != nil && name.Name != "_" && used[obj] && types.Identical(obj.Type(), typ) {
				return true
			}
		}
	}
	return false
}

// projectInterfaces returns the named interfaces declared in the project's
// packages.
func projectInterfaces(ctx *core.GoProjectContext) []*types.TypeName {
	var found []*types.TypeName
	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil || pkg.Package.Types == nil {
			continue
		}
		scope := pkg.Package.Types.Scope()
		for _, name := range scope.Names() {
			typeName, ok := scope.Lookup(name).(*types.TypeName)
			if ok && types.IsInterface(typeName.Type()) {
				found = append(found, typeName)
			}
		}
	}
	return found
}

// namingInterface returns an interface the method's receiver implements
// whose method names the index-th parameter, and that name.
func namingInterface(method *types.Func, index int, interfaces []*types.TypeName) (string, string) {
	sig, ok := method.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return "", ""
	}
	recv := sig.Recv().Type()
	for _, typeName := range interfaces {
		iface, ok := typeName.Type().Underlying().(*types.Interface)
		if !ok || (!types.Implements(recv, iface) && !types.Implements(types.NewPointer(recv), iface)) {
			continue
		}
		for i := range iface.NumMethods() {
			m := iface.Method(i)
			if m.Name() != method.Name() {
				continue
			}
			msig, ok := m.Type().(*types.Signature)
			if !ok {
				continue
			}
			if params := msig.Params(); index < params.Len() {
				if name := params.At(index).Name(); name != "" && name != "_" {
					return typeName.Name(), name
				}
			}
		}
	}
	return "", ""
}
