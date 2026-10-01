package patterns

import (
	"go/ast"
	"go/token"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewConstructorGoroutineNeverStopsRule())
}

// ConstructorGoroutineNeverStopsRule detects a constructor that starts a
// goroutine whose loop has no way out:
//
//	func NewTracker() *Tracker {
//		t := &Tracker{}
//		go t.cleanupLoop()     // for range ticker.C { ... } - forever
//		return t
//	}
//
// Each value built leaks a goroutine that holds the value and its maps for
// the rest of the process: tests constructing it per case, a router
// re-created on reload, a per-tenant instance. The loop is endless when it is
// a bare for or ranges over a ticker channel (time.Tick, ticker.C - never
// closed) and nothing in it returns or breaks out: no select case on a
// context or a stop channel. A goroutine started outside a New* constructor
// (main, a Start method called once) is left alone.
type ConstructorGoroutineNeverStopsRule struct {
	*rules.BaseRule
	// funcs maps a directory to its functions by name, methods as Type.Name.
	funcs map[string]map[string]*ast.FuncDecl
}

// NewConstructorGoroutineNeverStopsRule creates the rule
func NewConstructorGoroutineNeverStopsRule() *ConstructorGoroutineNeverStopsRule {
	return &ConstructorGoroutineNeverStopsRule{BaseRule: rules.NewBaseRule(
		"constructor-goroutine-never-stops",
		"patterns",
		"Detects a New* constructor starting a goroutine whose loop never ends (for range ticker.C, a bare for) with no stop channel or context — every value built leaks it",
		core.SeverityMedium,
	)}
}

// UseProjectFiles collects the functions and methods of each directory.
func (r *ConstructorGoroutineNeverStopsRule) UseProjectFiles(files []*core.FileContext) {
	r.funcs = make(map[string]map[string]*ast.FuncDecl)
	for _, ctx := range files {
		if !ctx.IsGoFile() || !ctx.HasGoAST() {
			continue
		}
		dir := filepath.Dir(ctx.Path)
		if r.funcs[dir] == nil {
			r.funcs[dir] = make(map[string]*ast.FuncDecl)
		}
		for _, decl := range ctx.GoAST.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil {
				key := fn.Name.Name
				if fn.Recv != nil {
					key = receiverTypeName(fn.Recv) + "." + key
				}
				r.funcs[dir][key] = fn
			}
		}
	}
}

// ResetState drops the functions of the previous root.
func (r *ConstructorGoroutineNeverStopsRule) ResetState() { r.funcs = nil }

// AnalyzeFile reports the endless goroutines the file's constructors start.
func (r *ConstructorGoroutineNeverStopsRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || !ctx.HasGoAST() || ctx.IsTestFile() {
		return nil
	}
	funcs := r.funcs[filepath.Dir(ctx.Path)]
	var violations []*core.Violation
	for _, decl := range ctx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv != nil || fn.Body == nil || !isConstructorName(fn.Name.Name) || fn.Type.Results == nil {
			continue
		}
		built := constructedTypeName(fn)
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			stmt, ok := n.(*ast.GoStmt)
			if !ok {
				return true
			}
			body := goroutineBody(stmt.Call, built, funcs)
			if body == nil || !hasEndlessLoop(body) {
				return true
			}
			line := ctx.LineFor(stmt)
			if ctx.IsSuppressed(line, r.Name()) {
				return true
			}
			v := r.CreateViolation(ctx.RelPath, line,
				fn.Name.Name+" starts a goroutine whose loop never ends — every value built leaks it, with everything it holds")
			v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
			v.WithSuggestion("Give the loop a way out (a select case on a done channel or a context) and a Close that triggers it")
			violations = append(violations, v)
			return true
		})
	}
	return violations
}

// isConstructorName reports New… or new… followed by an upper-case letter.
func isConstructorName(name string) bool {
	for _, prefix := range []string{"New", "new"} {
		rest, ok := strings.CutPrefix(name, prefix)
		if ok && (rest == "" || unicode.IsUpper([]rune(rest)[0])) {
			return true
		}
	}
	return false
}

// constructedTypeName returns the name of the constructor's first result
// type, pointer or not.
func constructedTypeName(fn *ast.FuncDecl) string {
	result := fn.Type.Results.List[0].Type
	if star, ok := result.(*ast.StarExpr); ok {
		result = star.X
	}
	if id, ok := result.(*ast.Ident); ok {
		return id.Name
	}
	return ""
}

// goroutineBody returns the body the go statement runs: a literal, a function
// of the directory, or a method of the constructed type.
func goroutineBody(call *ast.CallExpr, built string, funcs map[string]*ast.FuncDecl) *ast.BlockStmt {
	switch fun := ast.Unparen(call.Fun).(type) {
	case *ast.FuncLit:
		return fun.Body
	case *ast.Ident:
		if decl := funcs[fun.Name]; decl != nil && decl.Recv == nil {
			return decl.Body
		}
	case *ast.SelectorExpr:
		if _, ok := fun.X.(*ast.Ident); ok && built != "" {
			if decl := funcs[built+"."+fun.Sel.Name]; decl != nil {
				return decl.Body
			}
		}
	}
	return nil
}

// hasEndlessLoop reports a loop of the body that never ends: a bare for or a
// range over a ticker channel, with no return, break out of it or goto in it.
func hasEndlessLoop(body *ast.BlockStmt) bool {
	endless := false
	ast.Inspect(body, func(n ast.Node) bool {
		if endless {
			return false
		}
		if _, nested := n.(*ast.FuncLit); nested {
			return false
		}
		var loopBody *ast.BlockStmt
		switch loop := n.(type) {
		case *ast.ForStmt:
			if loop.Cond != nil {
				return true
			}
			loopBody = loop.Body
		case *ast.RangeStmt:
			if !tickerChannel(loop.X) {
				return true
			}
			loopBody = loop.Body
		default:
			return true
		}
		if !leavesLoop(loopBody) {
			endless = true
		}
		return true
	})
	return endless
}

// tickerChannel reports ticker.C and time.Tick(...): channels nobody closes.
func tickerChannel(expr ast.Expr) bool {
	switch e := ast.Unparen(expr).(type) {
	case *ast.SelectorExpr:
		return e.Sel.Name == "C"
	case *ast.CallExpr:
		if sel, ok := e.Fun.(*ast.SelectorExpr); ok {
			if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "time" && sel.Sel.Name == "Tick" {
				return true
			}
		}
	}
	return false
}

// leavesLoop reports a return, a goto, a labelled break, or a break that
// belongs to the loop itself (not to a select, switch or inner loop).
func leavesLoop(loopBody *ast.BlockStmt) bool {
	leaves := false
	var walk func(n ast.Node, own bool) bool
	walk = func(n ast.Node, own bool) bool {
		ast.Inspect(n, func(m ast.Node) bool {
			if leaves {
				return false
			}
			switch node := m.(type) {
			case *ast.FuncLit:
				return false
			case *ast.ReturnStmt:
				leaves = true
			case *ast.BranchStmt:
				if node.Tok == token.GOTO || node.Label != nil || (node.Tok == token.BREAK && own) {
					leaves = true
				}
			case *ast.SelectStmt, *ast.SwitchStmt, *ast.TypeSwitchStmt, *ast.ForStmt, *ast.RangeStmt:
				if m != n {
					// An unlabelled break inside belongs to this statement.
					walk(m, false)
					return false
				}
			}
			return true
		})
		return leaves
	}
	return walk(loopBody, true)
}
