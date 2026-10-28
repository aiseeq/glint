package helpers

import "go/types"

// InterfaceDeclaresMethod reports whether the interface has a method of that
// name, embedded interfaces included.
func InterfaceDeclaresMethod(iface *types.Interface, name string) bool {
	for method := range iface.Methods() {
		if method.Name() == name {
			return true
		}
	}
	return false
}
