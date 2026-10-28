package patternkit

import (
	"go/types"
)

// ReceiverNamed returns the named type a method is declared on.
func ReceiverNamed(method *types.Func) *types.Named {
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
