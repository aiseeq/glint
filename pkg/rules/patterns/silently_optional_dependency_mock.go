package patterns

import (
	"go/ast"
	"go/token"
	"sort"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

// nilFlagSite is a struct field set from a dependency being non-nil.
type nilFlagSite struct {
	file *core.FileContext
	node ast.Node
	dep  string
}

// nilSwitchedStandInModes reports a mode flag a constructor derives from a
// dependency being non-nil, which the package branches on into a mock:
//
//	return &Admin{client: client, live: client != nil}
//	...
//	if a.live { return a.client.Quote(ctx) }
//	return a.createMockQuote(ctx)
//
// A deployment that lost the client's configuration serves made-up results,
// and nothing says the mode changed: the choice belongs to an explicit flag.
func (r *SilentlyOptionalDependencyRule) nilSwitchedStandInModes(ctx *core.GoProjectContext) []*core.Violation {
	var violations []*core.Violation
	for _, pkg := range ctx.Packages {
		if pkg == nil {
			continue
		}
		flags := make(map[string][]nilFlagSite)
		var files []*core.FileContext
		for _, file := range pkg.Files {
			if file == nil || file.GoAST == nil || file.IsTestFile() {
				continue
			}
			files = append(files, file)
			collectNilFlags(file, flags)
		}
		if len(flags) == 0 {
			continue
		}
		mocked := standInSwitchedFields(files, flags)
		fields := make([]string, 0, len(flags))
		for field := range flags {
			fields = append(fields, field)
		}
		sort.Strings(fields)
		for _, field := range fields {
			if !mocked[field] {
				continue
			}
			for _, site := range flags[field] {
				line := site.file.LineFor(site.node)
				v := r.CreateViolation(site.file.RelPath, line,
					"Mode flag "+field+" is derived from "+site.dep+" being set, and the code branches on it into a mock - a missing dependency silently serves made-up results")
				v.WithCode(strings.TrimSpace(site.file.GetLine(line)))
				v.WithSuggestion("Fail the constructor when the dependency is missing, or gate the mock behind an explicit configuration flag")
				violations = append(violations, v)
			}
		}
	}
	return violations
}

// collectNilFlags finds `field: dep != nil` in composite literals and
// `x.field = dep != nil` in constructors (New*).
func collectNilFlags(file *core.FileContext, flags map[string][]nilFlagSite) {
	for _, decl := range file.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || !strings.HasPrefix(fn.Name.Name, "New") {
			continue
		}
		refused := refusedWhenNil(fn.Body)
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.KeyValueExpr:
				key, ok := node.Key.(*ast.Ident)
				if dep := nonNilTest(node.Value); ok && dep != "" && !refused[dep] {
					flags[key.Name] = append(flags[key.Name], nilFlagSite{file: file, node: node, dep: dep})
				}
			case *ast.AssignStmt:
				if len(node.Lhs) != 1 || len(node.Rhs) != 1 {
					return true
				}
				sel, ok := node.Lhs[0].(*ast.SelectorExpr)
				if dep := nonNilTest(node.Rhs[0]); ok && dep != "" && !refused[dep] {
					flags[sel.Sel.Name] = append(flags[sel.Sel.Name], nilFlagSite{file: file, node: node, dep: dep})
				}
			}
			return true
		})
	}
}

// refusedWhenNil returns the dependencies the constructor refuses to go on
// without, unless configuration allows it: if dep == nil && !cfg.AllowMock
// { return nil, err } leaves the mock to an explicit flag.
func refusedWhenNil(body *ast.BlockStmt) map[string]bool {
	refused := make(map[string]bool)
	for _, stmt := range body.List {
		ifStmt, ok := stmt.(*ast.IfStmt)
		if !ok || !blockLeaves(ifStmt.Body) {
			continue
		}
		ast.Inspect(ifStmt.Cond, func(n ast.Node) bool {
			bin, ok := n.(*ast.BinaryExpr)
			if ok && bin.Op == token.EQL && isNilIdent(bin.Y) {
				if id, ok := bin.X.(*ast.Ident); ok {
					refused[id.Name] = true
				}
			}
			return true
		})
	}
	return refused
}

// nonNilTest returns the name tested in `dep != nil`, or "".
func nonNilTest(expr ast.Expr) string {
	bin, ok := ast.Unparen(expr).(*ast.BinaryExpr)
	if !ok || bin.Op != token.NEQ || !isNilIdent(bin.Y) {
		return ""
	}
	switch x := bin.X.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		return x.Sel.Name
	}
	return ""
}

// standInSwitchedFields returns the flags some function branches on and then,
// in the branch or after it, calls a mock, fake or stub.
func standInSwitchedFields(files []*core.FileContext, flags map[string][]nilFlagSite) map[string]bool {
	mocked := make(map[string]bool)
	for _, file := range files {
		for _, decl := range file.GoAST.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || !callsStandIn(fn.Body) {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				ifStmt, ok := n.(*ast.IfStmt)
				if !ok {
					return true
				}
				ast.Inspect(ifStmt.Cond, func(c ast.Node) bool {
					if sel, ok := c.(*ast.SelectorExpr); ok && flags[sel.Sel.Name] != nil {
						mocked[sel.Sel.Name] = true
					}
					return true
				})
				return true
			})
		}
	}
	return mocked
}

// callsStandIn reports a call of a function named for a mock, a fake or a stub.
func callsStandIn(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || found {
			return !found
		}
		for _, word := range helpers.IdentifierWords(callName(call)) {
			switch strings.ToLower(word) {
			case "mock", "fake", "stub":
				found = true
			}
		}
		return !found
	})
	return found
}
