package deadcode

import (
	"go/ast"
	"go/token"
	"go/types"
)

// posRange is a half-open source range [start, end) in the project file set.
type posRange struct {
	start, end token.Pos
}

// ownDeclarations maps a package-level object to the source ranges that make
// up its own declaration: the function itself, the type spec together with
// every method declared on the type, the value spec. A reference from inside
// those ranges does not keep the object alive — a function that only calls
// itself, or a type that only its own methods mention, is still dead.
type ownDeclarations map[types.Object][]posRange

// addPackage records the declarations of one package's syntax.
func (own ownDeclarations) addPackage(files []*ast.File, info *types.Info) {
	for _, file := range files {
		for _, decl := range file.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				own.addFunc(d, info)
			case *ast.GenDecl:
				own.addGenDecl(d, info)
			}
		}
	}
}

func (own ownDeclarations) addFunc(fn *ast.FuncDecl, info *types.Info) {
	span := posRange{start: fn.Pos(), end: fn.End()}
	obj, ok := info.Defs[fn.Name].(*types.Func)
	if !ok {
		return
	}
	own[obj] = append(own[obj], span)
	if fn.Recv == nil {
		return
	}
	if owner := receiverTypeObject(obj); owner != nil {
		own[owner] = append(own[owner], span)
	}
}

func (own ownDeclarations) addGenDecl(decl *ast.GenDecl, info *types.Info) {
	for _, spec := range decl.Specs {
		switch s := spec.(type) {
		case *ast.TypeSpec:
			if obj := info.Defs[s.Name]; obj != nil {
				own[obj] = append(own[obj], posRange{start: s.Pos(), end: s.End()})
			}
		case *ast.ValueSpec:
			for _, name := range s.Names {
				if obj := info.Defs[name]; obj != nil {
					own[obj] = append(own[obj], posRange{start: s.Pos(), end: s.End()})
				}
			}
		}
	}
}

// contains reports whether pos lies inside the declaration of obj.
func (own ownDeclarations) contains(obj types.Object, pos token.Pos) bool {
	for _, span := range own[obj] {
		if pos >= span.start && pos < span.end {
			return true
		}
	}
	return false
}

// receiverTypeObject returns the type name a method is declared on, seeing
// through pointer and generic receivers.
func receiverTypeObject(method *types.Func) types.Object {
	sig, ok := method.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return nil
	}
	recv := types.Unalias(sig.Recv().Type())
	if ptr, ok := recv.(*types.Pointer); ok {
		recv = types.Unalias(ptr.Elem())
	}
	named, ok := recv.(*types.Named)
	if !ok {
		return nil
	}
	return named.Origin().Obj()
}

// countOutsideUses adds to counts, for every object already present in it,
// the references info records outside the object's own declaration.
func countOutsideUses(info *types.Info, own ownDeclarations, counts map[types.Object]int) {
	for ident, obj := range info.Uses {
		if obj == nil {
			continue
		}
		obj = originObject(obj)
		if _, tracked := counts[obj]; !tracked {
			continue
		}
		if own.contains(obj, ident.Pos()) {
			continue
		}
		counts[obj]++
	}
}

// originObject maps an instantiated generic function to its declaration.
func originObject(obj types.Object) types.Object {
	if fn, ok := obj.(*types.Func); ok {
		return fn.Origin()
	}
	return obj
}
