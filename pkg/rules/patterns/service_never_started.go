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
	rules.Register(NewServiceNeverStartedRule())
}

// ServiceNeverStartedRule detects a background service the program builds
// and never starts:
//
//	func (s *SyncService) Start(ctx context.Context) error { go s.loop(ctx); return nil }
//	...
//	syncService := sync.NewSyncService(cfg)   // handed to a handler, Start never called
//
// The type is in use, so nothing looks dead, yet the loop it exists for never
// runs: queued work piles up and nobody notices until the data is missed. A
// Start or Run method that starts a goroutine or loops is the service's
// entry point; the rule reports it when the type is constructed in the
// project and no code calls the method or takes it as a value. A type that
// satisfies an interface with that method is left out — the call may come
// through the interface, from a library the project hands it to.
type ServiceNeverStartedRule struct {
	*rules.BaseRule
}

// NewServiceNeverStartedRule creates the rule
func NewServiceNeverStartedRule() *ServiceNeverStartedRule {
	return &ServiceNeverStartedRule{BaseRule: rules.NewBaseRule(
		"service-never-started",
		"patterns",
		"Detects a background service whose Start/Run method nothing calls although the type is constructed — its loop never runs",
		core.SeverityMedium,
	)}
}

// AnalyzeFile is a no-op: the caller of Start may live in any package.
func (r *ServiceNeverStartedRule) AnalyzeFile(_ *core.FileContext) []*core.Violation { return nil }

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *ServiceNeverStartedRule) RequiresSSA() bool { return false }

var serviceEntryPoints = map[string]bool{"Start": true, "Run": true}

// serviceUsage is what the loaded packages do with types and methods.
type serviceUsage struct {
	// called holds the methods some code calls or takes as a value.
	called map[*types.Func]bool
	// constructed maps a named type to the first composite literal building it.
	constructed map[*types.TypeName]string
	// entryInterfaces are the interfaces with a Start or Run method.
	entryInterfaces []*types.Interface
}

type serviceUsageKey struct{}

// AnalyzeGoProject reports the Start and Run methods of constructed types
// that nothing calls.
func (r *ServiceNeverStartedRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%s: nil Go project context", r.Name())
	}
	usage, err := core.SharedLoad(ctx, serviceUsageKey{}, func() (*serviceUsage, error) {
		return collectServiceUsage(ctx)
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", r.Name(), err)
	}
	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(file *core.FileContext, info *types.Info) []*core.Violation {
		var violations []*core.Violation
		for _, decl := range file.GoAST.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || fn.Body == nil || !serviceEntryPoints[fn.Name.Name] || !runsInBackground(fn.Body) {
				continue
			}
			method, ok := info.Defs[fn.Name].(*types.Func)
			if !ok || usage.called[method] {
				continue
			}
			named := receiverNamed(method)
			if named == nil {
				continue
			}
			built, ok := usage.constructed[named.Obj()]
			if !ok || usage.reachableThroughInterface(named, fn.Name.Name) {
				continue
			}
			line := file.LineFor(fn.Name)
			if file.IsSuppressed(line, r.Name()) {
				continue
			}
			typeName := named.Obj().Name()
			v := r.CreateViolation(file.RelPath, line, fmt.Sprintf(
				"%s.%s starts the background work of %s, and nothing calls it — the type is built (%s) but its loop never runs",
				typeName, fn.Name.Name, typeName, built))
			v.WithCode(strings.TrimSpace(file.GetLine(line)))
			v.WithSuggestion(fmt.Sprintf("Call %s where the program starts its services (and stop it on shutdown), or delete the method if the work is not needed", fn.Name.Name))
			violations = append(violations, v)
		}
		return violations
	})
}

// runsInBackground reports a body that starts a goroutine or loops.
func runsInBackground(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		switch n.(type) {
		case *ast.GoStmt, *ast.ForStmt:
			found = true
		}
		return !found
	})
	return found
}

// receiverNamed returns the named type a method is declared on.
func receiverNamed(method *types.Func) *types.Named {
	sig, ok := method.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return nil
	}
	t := sig.Recv().Type()
	if ptr, ok := t.(*types.Pointer); ok {
		t = ptr.Elem()
	}
	named, _ := types.Unalias(t).(*types.Named)
	if named == nil {
		return nil
	}
	return named.Origin()
}

func collectServiceUsage(ctx *core.GoProjectContext) (*serviceUsage, error) {
	usage := &serviceUsage{
		called:      make(map[*types.Func]bool),
		constructed: make(map[*types.TypeName]string),
	}
	seen := make(map[*types.Interface]bool)
	addInterface := func(t types.Type) {
		if t == nil {
			return
		}
		iface, ok := t.Underlying().(*types.Interface)
		if !ok || seen[iface] {
			return
		}
		seen[iface] = true
		for i := range iface.NumMethods() {
			if serviceEntryPoints[iface.Method(i).Name()] {
				usage.entryInterfaces = append(usage.entryInterfaces, iface)
				return
			}
		}
	}
	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil || pkg.Package.TypesInfo == nil {
			return nil, fmt.Errorf("package has no typed syntax")
		}
		info := pkg.Package.TypesInfo
		for _, obj := range info.Uses {
			switch o := obj.(type) {
			case *types.Func:
				usage.called[o.Origin()] = true
				if sig, ok := o.Type().(*types.Signature); ok {
					for i := range sig.Params().Len() {
						addInterface(variadicElem(sig.Params().At(i).Type()))
					}
				}
			case *types.TypeName:
				addInterface(o.Type())
			}
		}
		for _, obj := range info.Defs {
			if tn, ok := obj.(*types.TypeName); ok {
				addInterface(tn.Type())
			}
		}
		for _, tv := range info.Types {
			addInterface(tv.Type)
		}
		for _, file := range pkg.Package.Syntax {
			ast.Inspect(file, func(n ast.Node) bool {
				lit, ok := n.(*ast.CompositeLit)
				if !ok {
					return true
				}
				t := info.TypeOf(lit)
				if t == nil {
					return true
				}
				named, ok := types.Unalias(t).(*types.Named)
				if !ok {
					return true
				}
				obj := named.Origin().Obj()
				if _, ok := usage.constructed[obj]; !ok {
					position := ctx.FileSet.Position(lit.Pos())
					usage.constructed[obj] = fmt.Sprintf("%s:%d", projectRelPath(ctx.ProjectRoot, position.Filename), position.Line)
				}
				return true
			})
		}
	}
	return usage, nil
}

// variadicElem returns the element type of a variadic parameter's slice, the
// type itself otherwise: an interface passed as ...Runner is still a Runner.
func variadicElem(t types.Type) types.Type {
	if slice, ok := t.Underlying().(*types.Slice); ok {
		return slice.Elem()
	}
	return t
}

// reachableThroughInterface reports a type whose value or pointer satisfies an
// interface carrying the entry point.
func (u *serviceUsage) reachableThroughInterface(named *types.Named, method string) bool {
	for _, iface := range u.entryInterfaces {
		if !interfaceHasMethod(iface, method) {
			continue
		}
		if types.Implements(named, iface) || types.Implements(types.NewPointer(named), iface) {
			return true
		}
	}
	return false
}

func interfaceHasMethod(iface *types.Interface, name string) bool {
	for i := range iface.NumMethods() {
		if iface.Method(i).Name() == name {
			return true
		}
	}
	return false
}
