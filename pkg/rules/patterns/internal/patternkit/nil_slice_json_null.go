package patternkit

import (
	"go/ast"
	"go/types"
	"sync"

	"github.com/aiseeq/glint/pkg/core"
)

// TypedFunc is a function declaration with the types of its package.
type TypedFunc struct {
	File *core.FileContext
	Info *types.Info
	Decl *ast.FuncDecl
}

// ProjectFuncDecls returns the function declarations of the analyzed
// production files.
func ProjectFuncDecls(ctx *core.GoProjectContext) []TypedFunc {
	var funcs []TypedFunc
	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil || pkg.Package.TypesInfo == nil {
			continue
		}
		for _, file := range pkg.Files {
			if file.GoAST == nil || file.IsTestFile() {
				continue
			}
			for _, decl := range file.GoAST.Decls {
				if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil {
					funcs = append(funcs, TypedFunc{File: file, Info: pkg.Package.TypesInfo, Decl: fn})
				}
			}
		}
	}
	return funcs
}

type implementedMethodsKey struct{}

type receiverMethods struct {
	once    sync.Once
	methods map[string][]*types.Func
}

type implementedMethodIndex struct {
	mu         sync.Mutex
	interfaces []*types.TypeName
	byReceiver map[types.Type]*receiverMethods
}

// ImplementedMethods returns the methods of project interfaces a method
// implements. Interface checks are shared by receiver type across rules.
func ImplementedMethods(ctx *core.GoProjectContext, method *types.Func) []*types.Func {
	sig, ok := method.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return nil
	}
	recv := sig.Recv().Type()
	index, err := core.SharedLoad(ctx, implementedMethodsKey{}, func() (*implementedMethodIndex, error) {
		return &implementedMethodIndex{
			interfaces: ProjectInterfaces(ctx),
			byReceiver: make(map[types.Type]*receiverMethods),
		}, nil
	})
	if err != nil {
		panic(err)
	}
	index.mu.Lock()
	entry, ok := index.byReceiver[recv]
	if !ok {
		entry = &receiverMethods{}
		index.byReceiver[recv] = entry
	}
	index.mu.Unlock()

	entry.once.Do(func() {
		methods := make(map[string][]*types.Func)
		for _, typeName := range index.interfaces {
			iface, ok := typeName.Type().Underlying().(*types.Interface)
			if !ok || !types.Implements(recv, iface) {
				continue
			}
			for m := range iface.Methods() {
				methods[m.Name()] = append(methods[m.Name()], m)
			}
		}
		entry.methods = methods
	})
	return entry.methods[method.Name()]
}
