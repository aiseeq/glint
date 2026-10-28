package concurrencyrules

import (
	"go/ast"
	"go/types"

	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
)

// mutexCall describes a Lock/Unlock call: which mutex expression it acts on
// ("s.mu", "c") and which method was called.
type mutexCall struct {
	receiver string
	method   string
}

// lockCall returns the call as a lock acquisition, if that is what it is.
// info is nil for a file without type information: then the method name
// decides; with it the method must belong to a sync mutex.
func lockCall(call *ast.CallExpr, info *types.Info) (mutexCall, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || !patternkit.LockMethodNames[sel.Sel.Name] {
		return mutexCall{}, false
	}
	return mutexMethodRef(sel, info)
}

// unlockRef returns a selector naming a release method - called, or taken as
// a method value (`return s.mu.Unlock`) that someone else will call.
func unlockRef(sel *ast.SelectorExpr, info *types.Info) (mutexCall, bool) {
	if !patternkit.UnlockMethods[sel.Sel.Name] {
		return mutexCall{}, false
	}
	return mutexMethodRef(sel, info)
}

// mutexMethodRef renders the receiver of a Lock/Unlock selector; with type
// information only a method of sync.Mutex or sync.RWMutex qualifies.
func mutexMethodRef(sel *ast.SelectorExpr, info *types.Info) (mutexCall, bool) {
	if info != nil {
		selection, found := info.Selections[sel]
		if !found || !isMutexMethod(selection) {
			return mutexCall{}, false
		}
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
