package deadcode

import (
	"errors"
	"go/ast"
	"go/token"
	"go/types"
	"path"
	"path/filepath"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewNeverAssignedFuncVarRule())
}

// NeverAssignedFuncVarRule detects a package-level function variable that
// code calls but nothing ever assigns:
//
//	// contracts
//	var VerifySignature func(message, signature, address string) error
//
//	// auth
//	if err := contracts.VerifySignature(msg, sig, addr); err != nil { ... }
//
// The variable was declared for a wiring that never came, and the call is a
// call of a nil function: it panics the first time the path runs. The
// package-level counterpart of never-assigned-field.
//
// The rule reads syntax, so it also works on packages that do not
// type-check: a variable is its declaring directory and name, a call names
// it as pkg.Name through an import of that directory, or as Name in the
// directory itself. Not reported: a variable declared with a value or with a
// named function type, one assigned or whose address is taken anywhere in
// the production code, one compared with nil anywhere (an optional hook the
// caller checks). An assignment in a test does not count: production calls
// still meet nil.
type NeverAssignedFuncVarRule struct {
	*rules.BaseRule
}

// NewNeverAssignedFuncVarRule creates the rule
func NewNeverAssignedFuncVarRule() *NeverAssignedFuncVarRule {
	return &NeverAssignedFuncVarRule{BaseRule: rules.NewBaseRule(
		"never-assigned-func-var",
		"deadcode",
		"Detects a package-level function variable that is called but never assigned — a guaranteed nil function call",
		core.SeverityHigh,
	)}
}

// AnalyzeFile is a no-op: the assignment may live in any package.
func (r *NeverAssignedFuncVarRule) AnalyzeFile(_ *core.FileContext) []*core.Violation { return nil }

// RequiresSSA reports that syntax is enough for this rule.
func (r *NeverAssignedFuncVarRule) RequiresSSA() bool { return false }

// funcVar is a package-level variable: the directory of its package,
// relative to the project and slash-separated, and its name.
type funcVar struct {
	dir, name string
}

// funcVarIndex is what the production files declare and do with
// package-level function variables.
type funcVarIndex struct {
	unset    map[funcVar]bool // declared as func(...) without a value
	assigned map[funcVar]bool // written, address taken, or checked for nil
	dirs     map[string]bool  // the directories declaring such variables
}

// AnalyzeGoProject reports the calls of function variables nothing assigns.
func (r *NeverAssignedFuncVarRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, errors.New("never assigned func var: nil Go project context")
	}
	index := funcVarIndex{unset: make(map[funcVar]bool), assigned: make(map[funcVar]bool), dirs: make(map[string]bool)}
	var files []*core.FileContext
	for _, file := range ctx.Files {
		if file.GoAST != nil && !file.IsTestFile() {
			files = append(files, file)
			index.declare(file)
		}
	}
	if len(index.unset) == 0 {
		return nil, nil
	}
	for _, file := range files {
		index.markWrites(file)
	}
	return rules.AnalyzeGoFiles(ctx, r.Name(), func(file *core.FileContext, _ *types.Info) []*core.Violation {
		if file.IsTestFile() {
			return nil
		}
		var violations []*core.Violation
		resolve := index.resolver(file)
		ast.Inspect(file.GoAST, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			v, ok := resolve(call.Fun)
			if !ok || !index.unset[v] || index.assigned[v] {
				return true
			}
			line := file.LineFor(call)
			if file.IsSuppressed(line, r.Name()) {
				return true
			}
			violation := r.CreateViolation(file.RelPath, line,
				"Function variable "+v.name+" is called but nothing ever assigns it — the call is a nil function call and panics")
			violation.WithCode(strings.TrimSpace(file.GetLine(line)))
			violation.WithSuggestion("Call the function that implements it directly, or assign " + v.name + " where the package is wired")
			violations = append(violations, violation)
			return true
		})
		return violations
	})
}

// fileDir is the directory of a file relative to the project, slash-separated.
func fileDir(file *core.FileContext) string {
	return path.Dir(filepath.ToSlash(file.RelPath))
}

// declare records the package-level variables of a file declared with a
// function type and no value.
func (x *funcVarIndex) declare(file *core.FileContext) {
	for _, decl := range file.GoAST.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.VAR {
			continue
		}
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok || len(vs.Values) > 0 {
				continue
			}
			if _, isFunc := vs.Type.(*ast.FuncType); !isFunc {
				continue
			}
			for _, name := range vs.Names {
				if name.Name != "_" {
					x.unset[funcVar{dir: fileDir(file), name: name.Name}] = true
					x.dirs[fileDir(file)] = true
				}
			}
		}
	}
}

// markWrites records the variables a file assigns, takes the address of or
// compares with nil.
func (x *funcVarIndex) markWrites(file *core.FileContext) {
	resolve := x.resolver(file)
	mark := func(expr ast.Expr) {
		if v, ok := resolve(expr); ok {
			x.assigned[v] = true
		}
	}
	ast.Inspect(file.GoAST, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			for _, lhs := range node.Lhs {
				mark(lhs)
			}
		case *ast.UnaryExpr:
			if node.Op == token.AND {
				mark(node.X)
			}
		case *ast.BinaryExpr:
			if node.Op == token.EQL || node.Op == token.NEQ {
				if isNilName(node.Y) {
					mark(node.X)
				}
				if isNilName(node.X) {
					mark(node.Y)
				}
			}
		}
		return true
	})
}

// resolver names the package-level variable an expression of a file refers
// to: pkg.Name through an import of a directory that declares function
// variables (the import path ends with the directory), or a bare Name of
// the file's own directory that no local declaration of the file shadows.
func (x *funcVarIndex) resolver(file *core.FileContext) func(ast.Expr) (funcVar, bool) {
	imports := make(map[string]string) // local name -> import path
	for _, spec := range file.GoAST.Imports {
		importPath := strings.Trim(spec.Path.Value, "\"`")
		name := path.Base(importPath)
		if spec.Name != nil {
			name = spec.Name.Name
		}
		imports[name] = importPath
	}
	dir := fileDir(file)
	return func(expr ast.Expr) (funcVar, bool) {
		switch e := ast.Unparen(expr).(type) {
		case *ast.Ident:
			if e.Obj != nil && e.Obj.Kind != ast.Var {
				return funcVar{}, false
			}
			if e.Obj != nil && !packageLevel(file.GoAST, e.Obj.Decl) {
				return funcVar{}, false
			}
			return funcVar{dir: dir, name: e.Name}, true
		case *ast.SelectorExpr:
			pkg, ok := e.X.(*ast.Ident)
			if !ok || pkg.Obj != nil {
				return funcVar{}, false
			}
			importPath, ok := imports[pkg.Name]
			if !ok {
				return funcVar{}, false
			}
			dir, ok := x.dirOf(importPath)
			return funcVar{dir: dir, name: e.Sel.Name}, ok
		}
		return funcVar{}, false
	}
}

// dirOf returns the declaring directory an import path names: the longest
// one the path ends with (example.com/app/shared/contracts names
// shared/contracts).
func (x *funcVarIndex) dirOf(importPath string) (string, bool) {
	best := ""
	for dir := range x.dirs {
		if dir != "." && strings.HasSuffix("/"+importPath, "/"+dir) && len(dir) > len(best) {
			best = dir
		}
	}
	return best, best != ""
}

// packageLevel reports a declaration (an identifier's Obj.Decl) that is a
// top-level declaration of the file.
func packageLevel(file *ast.File, decl any) bool {
	spec, ok := decl.(*ast.ValueSpec)
	if !ok {
		return false
	}
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, s := range gen.Specs {
			if s == spec {
				return true
			}
		}
	}
	return false
}

func isNilName(expr ast.Expr) bool {
	id, ok := ast.Unparen(expr).(*ast.Ident)
	return ok && id.Name == "nil"
}
