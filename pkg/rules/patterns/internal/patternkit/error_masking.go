package patternkit

import (
	"go/ast"
)

// FieldListsContainName ищет имя среди объявлений полей (параметры, receiver).
func FieldListsContainName(name string, lists ...*ast.FieldList) bool {
	for _, list := range lists {
		if list == nil {
			continue
		}
		for _, field := range list.List {
			for _, ident := range field.Names {
				if ident.Name == name {
					return true
				}
			}
		}
	}
	return false
}
