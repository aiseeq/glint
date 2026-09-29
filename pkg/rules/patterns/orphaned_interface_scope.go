package patterns

import (
	"fmt"
	"go/ast"
	"go/types"
	"path/filepath"
	"sort"

	"github.com/aiseeq/glint/pkg/core"
)

// typedInterface is an interface declaration of a type-checked package.
type typedInterface struct {
	info *interfaceInfo
	file *core.FileContext
	obj  *types.TypeName
}

// analyzeTyped checks the interfaces of type-checked packages against every
// loaded package: a reference from any production file of the project is a
// usage, a named type of any package whose method set satisfies the interface
// is an implementation.
func (r *OrphanedInterfaceRule) analyzeTyped(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	var candidates []*typedInterface
	byObj := make(map[types.Object]*typedInterface)
	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil || pkg.Package.TypesInfo == nil {
			return nil, fmt.Errorf("%s: package has no typed syntax", r.Name())
		}
		for _, fileCtx := range pkg.Files {
			if fileCtx.GoAST == nil || r.shouldSkipFile(fileCtx) {
				continue
			}
			for _, iface := range r.collectInterfaces(fileCtx) {
				obj, ok := pkg.Package.TypesInfo.Defs[iface.spec.Name].(*types.TypeName)
				if !ok {
					return nil, fmt.Errorf("%s: interface %q in %s has no type object", r.Name(), iface.name, fileCtx.RelPath)
				}
				candidate := &typedInterface{info: iface, file: fileCtx, obj: obj}
				candidates = append(candidates, candidate)
				byObj[obj] = candidate
			}
		}
	}
	return r.typedOrphans(ctx, candidates, byObj), nil
}

// typedOrphans reports the candidates nothing in the project references or implements.
func (r *OrphanedInterfaceRule) typedOrphans(ctx *core.GoProjectContext, candidates []*typedInterface, byObj map[types.Object]*typedInterface) []*core.Violation {
	if len(candidates) == 0 {
		return nil
	}

	used := make(map[*typedInterface]bool)
	var named []*types.TypeName
	for _, pkg := range ctx.Packages {
		info := pkg.Package.TypesInfo
		for ident, obj := range info.Uses {
			candidate, ok := byObj[obj]
			if !ok {
				continue
			}
			spec := candidate.info.spec
			if ident.Pos() >= spec.Pos() && ident.Pos() < spec.End() {
				continue // the interface mentioning itself in its own methods
			}
			used[candidate] = true
		}
		for _, obj := range info.Defs {
			if typeName, ok := obj.(*types.TypeName); ok && isImplementationCandidate(typeName) {
				named = append(named, typeName)
			}
		}
	}

	var violations []*core.Violation
	for _, candidate := range candidates {
		if used[candidate] || implementedByAny(candidate.obj, named) {
			continue
		}
		if v := r.report(candidate.file, candidate.info, "the project"); v != nil {
			violations = append(violations, v)
		}
	}
	return violations
}

// isImplementationCandidate keeps the declared types that can implement an
// interface: not aliases and not interfaces (embedding counts as a usage).
// Type parameters have an interface as their underlying type and drop out too.
func isImplementationCandidate(typeName *types.TypeName) bool {
	if typeName.IsAlias() {
		return false
	}
	_, isInterface := typeName.Type().Underlying().(*types.Interface)
	return !isInterface
}

// implementedByAny reports whether some type T or *T among named satisfies
// the interface. Uninstantiated generic types (on either side) cannot be
// checked with types.Implements and are matched by method names instead.
func implementedByAny(obj *types.TypeName, named []*types.TypeName) bool {
	iface, ok := obj.Type().Underlying().(*types.Interface)
	if !ok || iface.NumMethods() == 0 || !iface.IsMethodSet() {
		// Empty or constraint-only interface: not a contract a type implements.
		return false
	}
	genericIface := isUninstantiatedGeneric(obj.Type())
	for _, typeName := range named {
		typ := typeName.Type()
		if genericIface || isUninstantiatedGeneric(typ) {
			if hasMethodNames(typ, iface) {
				return true
			}
			continue
		}
		if types.Implements(typ, iface) || types.Implements(types.NewPointer(typ), iface) {
			return true
		}
	}
	return false
}

func isUninstantiatedGeneric(typ types.Type) bool {
	named, ok := typ.(*types.Named)
	return ok && named.TypeParams().Len() > 0 && named.TypeArgs().Len() == 0
}

// hasMethodNames reports whether *typ has a method named like every method of iface.
func hasMethodNames(typ types.Type, iface *types.Interface) bool {
	methodSet := types.NewMethodSet(types.NewPointer(typ))
	have := make(map[string]bool, methodSet.Len())
	for i := range methodSet.Len() {
		have[methodSet.At(i).Obj().Name()] = true
	}
	for i := range iface.NumMethods() {
		if !have[iface.Method(i).Name()] {
			return false
		}
	}
	return true
}

// analyzeUntyped checks interfaces of files no type-checked package claimed
// (broken packages under --tolerant, files excluded by build constraints)
// against the syntax of every production file of their package directory.
func (r *OrphanedInterfaceRule) analyzeUntyped(ctx *core.GoProjectContext) []*core.Violation {
	typedFiles := make(map[*core.FileContext]bool)
	for _, pkg := range ctx.Packages {
		for _, fileCtx := range pkg.Files {
			typedFiles[fileCtx] = true
		}
	}

	groups := make(map[string][]*core.FileContext)
	for _, fileCtx := range ctx.Files {
		if fileCtx == nil || fileCtx.GoAST == nil || fileCtx.IsTestFile() {
			continue
		}
		key := filepath.Dir(fileCtx.Path) + "\x00" + fileCtx.GoPackage
		groups[key] = append(groups[key], fileCtx)
	}
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var violations []*core.Violation
	for _, key := range keys {
		files := groups[key]
		syntax := make([]*ast.File, 0, len(files))
		for _, fileCtx := range files {
			syntax = append(syntax, fileCtx.GoAST)
		}
		for _, fileCtx := range files {
			if typedFiles[fileCtx] || r.shouldSkipFile(fileCtx) {
				continue
			}
			violations = append(violations, r.analyzeSyntax(fileCtx, syntax)...)
		}
	}
	return violations
}

// analyzeSyntax reports interfaces of fileCtx that no file of syntax
// implements by method names or references as a type.
func (r *OrphanedInterfaceRule) analyzeSyntax(fileCtx *core.FileContext, syntax []*ast.File) []*core.Violation {
	interfaces := r.collectInterfaces(fileCtx)
	if len(interfaces) == 0 {
		return nil
	}
	implementedBy := r.findImplementations(syntax, interfaces)
	usedIn := r.findUsages(syntax, interfaces)

	var violations []*core.Violation
	for _, iface := range interfaces {
		if len(implementedBy[iface.name]) > 0 || usedIn[iface.name] {
			continue
		}
		if v := r.report(fileCtx, iface, "its package"); v != nil {
			violations = append(violations, v)
		}
	}
	return violations
}
