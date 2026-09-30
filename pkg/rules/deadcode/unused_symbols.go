package deadcode

import (
	"errors"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewUnusedSymbolsRule())
}

// UnusedSymbolsRule detects unexported package-level functions, types,
// variables and constants that nothing in their package uses. References are
// resolved by the type checker over every compiled file of the package; the
// files the typed load leaves out — tests, files the build excludes on this
// platform — are scanned by name, so a symbol only they use is not reported.
// They are read from the package directory even when the project excluded
// them from analysis.
// A reference from inside the symbol's own declaration (a recursive call, a
// type named only by its own methods) does not keep it alive.
//
// An unexported method counts as used when an interface of its package
// declares a method of that name: it may be how the type satisfies it. An
// exported method may satisfy an interface anywhere and is not checked.
type UnusedSymbolsRule struct {
	*rules.BaseRule
}

// NewUnusedSymbolsRule creates the rule
func NewUnusedSymbolsRule() *UnusedSymbolsRule {
	return &UnusedSymbolsRule{
		BaseRule: rules.NewBaseRule(
			"unused-symbol",
			"deadcode",
			"Detects unexported package-level functions, types, variables and constants that nothing in their package uses",
			core.SeverityLow,
		),
	}
}

// AnalyzeFile does nothing: whether a symbol is used is a question about its
// whole package, answered by AnalyzeGoProject.
func (r *UnusedSymbolsRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *UnusedSymbolsRule) RequiresSSA() bool { return false }

// declaredSymbol is an unexported package-level declaration of an analyzed file.
type declaredSymbol struct {
	obj  types.Object
	kind string
	line int
}

// AnalyzeGoProject reports the unexported symbols of the analyzed files that
// no other part of their package references.
func (r *UnusedSymbolsRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, errors.New("unused symbol: nil Go project context")
	}

	byFile := make(map[*core.FileContext][]declaredSymbol)
	uses := make(map[types.Object]int)
	mentions, err := projectMentions(ctx)
	if err != nil {
		return nil, fmt.Errorf("unused symbol: %w", err)
	}
	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil || pkg.Package.TypesInfo == nil {
			return nil, errors.New("unused symbol: package has no typed syntax")
		}
		info := pkg.Package.TypesInfo
		found := false
		interfaceMethods := interfaceMethodNames(pkg.Package.Syntax)
		for _, fileCtx := range pkg.Files {
			if fileCtx.GoAST == nil || fileCtx.IsTestFile() {
				continue
			}
			for _, sym := range unexportedDeclarations(fileCtx, info, interfaceMethods) {
				uses[sym.obj] = 0
				byFile[fileCtx] = append(byFile[fileCtx], sym)
				found = true
			}
		}
		if !found {
			continue
		}
		// Unexported symbols are visible only inside their package, so its
		// own syntax holds every typed reference.
		own := make(ownDeclarations)
		own.addPackage(pkg.Package.Syntax, info)
		countOutsideUses(info, own, uses)
	}

	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(fileCtx *core.FileContext, _ *types.Info) []*core.Violation {
		var violations []*core.Violation
		for _, sym := range byFile[fileCtx] {
			name := sym.obj.Name()
			if uses[sym.obj] > 0 || mentions.mentioned(fileCtx, name) || ofUnusedType(sym.obj, uses) {
				continue
			}
			v := r.CreateViolation(fileCtx.RelPath, sym.line,
				"Unexported "+sym.kind+" '"+name+"' appears to be unused")
			v.WithCode(fileCtx.GetLine(sym.line))
			v.WithSuggestion("Remove unused " + sym.kind + " or export it if intended for external use")
			v.WithContext("symbol", name)
			v.WithContext("kind", sym.kind)
			violations = append(violations, v)
		}
		return violations
	})
}

// unexportedDeclarations returns the unexported package-level functions,
// methods, types, variables and constants of a file in source order. main,
// init, the blank identifier and a method an interface of the package names
// are left out.
func unexportedDeclarations(fileCtx *core.FileContext, info *types.Info, interfaceMethods map[string]bool) []declaredSymbol {
	var symbols []declaredSymbol
	add := func(name *ast.Ident, kind string) {
		if name.Name == "_" || ast.IsExported(name.Name) {
			return
		}
		obj := info.Defs[name]
		if obj == nil {
			return
		}
		symbols = append(symbols, declaredSymbol{obj: obj, kind: kind, line: fileCtx.LineFor(name)})
	}

	for _, decl := range fileCtx.GoAST.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			switch {
			case d.Recv != nil && !interfaceMethods[d.Name.Name]:
				add(d.Name, "method")
			case d.Recv == nil && d.Name.Name != "main" && d.Name.Name != "init":
				add(d.Name, "function")
			}
		case *ast.GenDecl:
			for _, spec := range d.Specs {
				switch s := spec.(type) {
				case *ast.TypeSpec:
					add(s.Name, "type")
				case *ast.ValueSpec:
					kind := "variable"
					if d.Tok == token.CONST {
						kind = "constant"
					}
					for _, name := range s.Names {
						add(name, kind)
					}
				}
			}
		}
	}
	return symbols
}

// interfaceMethodNames returns the unexported method names the interfaces of
// a package declare.
func interfaceMethodNames(files []*ast.File) map[string]bool {
	names := make(map[string]bool)
	for _, file := range files {
		ast.Inspect(file, func(n ast.Node) bool {
			iface, ok := n.(*ast.InterfaceType)
			if !ok || iface.Methods == nil {
				return true
			}
			for _, method := range iface.Methods.List {
				for _, name := range method.Names {
					if !ast.IsExported(name.Name) {
						names[name.Name] = true
					}
				}
			}
			return true
		})
	}
	return names
}

// ofUnusedType reports a method of a type that is itself reported unused:
// the type's finding covers it.
func ofUnusedType(obj types.Object, uses map[types.Object]int) bool {
	method, ok := obj.(*types.Func)
	if !ok {
		return false
	}
	owner := receiverTypeObject(method)
	count, tracked := uses[owner]
	return owner != nil && tracked && count == 0
}
