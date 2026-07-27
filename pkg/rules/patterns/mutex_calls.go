package patterns

import "go/ast"

// lockMethods and unlockMethods are the calls that open and close a critical
// section on sync.Mutex and sync.RWMutex.
var (
	lockMethods   = map[string]string{"Lock": "Unlock", "RLock": "RUnlock"}
	unlockMethods = map[string]bool{"Unlock": true, "RUnlock": true}
)

// mutexCall describes a Lock/Unlock call: which mutex expression it acts on
// ("s.mu", "c") and which method was called.
type mutexCall struct {
	receiver string
	method   string
}

// lockCall returns the call as a lock acquisition, if that is what it is.
func lockCall(call *ast.CallExpr) (mutexCall, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return mutexCall{}, false
	}
	if _, isLock := lockMethods[sel.Sel.Name]; !isLock {
		return mutexCall{}, false
	}
	receiver := receiverChain(sel.X)
	if receiver == "" {
		return mutexCall{}, false
	}
	return mutexCall{receiver: receiver, method: sel.Sel.Name}, true
}

// unlockCall returns the call as a lock release, if that is what it is.
func unlockCall(call *ast.CallExpr) (mutexCall, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return mutexCall{}, false
	}
	if !unlockMethods[sel.Sel.Name] {
		return mutexCall{}, false
	}
	receiver := receiverChain(sel.X)
	if receiver == "" {
		return mutexCall{}, false
	}
	return mutexCall{receiver: receiver, method: sel.Sel.Name}, true
}

// receiverChain renders the expression a method is called on as source-like
// text: "s.mu" for s.mu.Lock(), "c" for c.Lock().
func receiverChain(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		base := receiverChain(e.X)
		if base == "" {
			return e.Sel.Name
		}
		return base + "." + e.Sel.Name
	case *ast.UnaryExpr:
		return receiverChain(e.X)
	}
	return ""
}
