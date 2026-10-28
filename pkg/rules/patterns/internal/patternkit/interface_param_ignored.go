package patternkit

import (
	"go/types"

	"github.com/aiseeq/glint/pkg/core"
)

// ProjectInterfaces returns the named interfaces declared in the project's
// packages.
func ProjectInterfaces(ctx *core.GoProjectContext) []*types.TypeName {
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
