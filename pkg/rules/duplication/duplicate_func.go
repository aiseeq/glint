package duplication

import (
	"errors"
	"fmt"
	"go/ast"
	"go/types"
	"sort"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewDuplicateFuncAcrossPackagesRule())
}

// DuplicateFuncAcrossPackagesRule detects one helper kept as two copies: an
// unexported function of the same name and signature declared in two
// packages of the module:
//
//	// poller/poller.go
//	func withContextCause(ctx context.Context, err error) error { ... }
//
//	// sender/sender.go
//	func withContextCause(ctx context.Context, err error) error { ... }
//
// The copies are short and differ in details, so cross-file-duplicate does
// not see them; a fix lands in one and the other goes on without it. The
// signature prints types with full package paths, so a function over the
// package's own type (newStore returning its own *store) never matches its
// namesake. A one-word name (run, handle, parse) is a role every package
// fills its own way, a function without parameters is a constant in
// disguise, and a wrapper whose body only calls a function of another
// package already shares the implementation; test files and mock packages
// are left out.
type DuplicateFuncAcrossPackagesRule struct {
	*rules.BaseRule
}

// NewDuplicateFuncAcrossPackagesRule creates the rule
func NewDuplicateFuncAcrossPackagesRule() *DuplicateFuncAcrossPackagesRule {
	return &DuplicateFuncAcrossPackagesRule{BaseRule: rules.NewBaseRule(
		"duplicate-func-across-packages",
		"duplication",
		"Detects an unexported function declared in two packages under one name and signature — two copies of one helper that drift apart",
		core.SeverityMedium,
	)}
}

// AnalyzeFile is a no-op: the copies live in different packages.
func (r *DuplicateFuncAcrossPackagesRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *DuplicateFuncAcrossPackagesRule) RequiresSSA() bool { return false }

// AnalyzeGoProject reports each copy of a helper duplicated across packages.
func (r *DuplicateFuncAcrossPackagesRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, errors.New("duplicate func across packages: nil Go project context")
	}
	byKey := make(map[string][]*types.Func)
	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil || pkg.Package.TypesInfo == nil {
			return nil, errors.New("duplicate func across packages: package has no typed syntax")
		}
		if testDoublePackage(pkg.Package.PkgPath) {
			continue
		}
		for _, file := range pkg.Files {
			if file.GoAST == nil || file.IsTestFile() || file.IsGenerated() {
				continue
			}
			for _, fn := range helperFuncs(file.GoAST, pkg.Package.TypesInfo) {
				key := helperKey(fn)
				byKey[key] = append(byKey[key], fn)
			}
		}
	}
	twins := make(map[*types.Func]string)
	keys := make([]string, 0, len(byKey))
	for key := range byKey {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		// The first copy is the twin of every copy from another package, and
		// the first copy from another package is the twin of the first one.
		copies := byKey[key]
		first := copies[0].Pkg()
		var other *types.Package
		for _, c := range copies {
			if c.Pkg() != first {
				other = c.Pkg()
				break
			}
		}
		if other == nil {
			continue
		}
		for _, c := range copies {
			twin := first
			if c.Pkg() == first {
				twin = other
			}
			twins[c] = twin.Path()
		}
	}
	if len(twins) == 0 {
		return nil, nil
	}
	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(file *core.FileContext, info *types.Info) []*core.Violation {
		var violations []*core.Violation
		for _, decl := range file.GoAST.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			fn, ok := info.Defs[fd.Name].(*types.Func)
			if !ok || twins[fn] == "" {
				continue
			}
			line := file.LineFor(fd)
			if file.IsSuppressed(line, r.Name()) {
				continue
			}
			v := r.CreateViolation(file.RelPath, line, fmt.Sprintf(
				"Function %s has a copy with the same signature in %s — two copies of one helper: a fix lands in one and the other drifts",
				fd.Name.Name, twins[fn]))
			v.WithCode(strings.TrimSpace(file.GetLine(line)))
			v.WithSuggestion("Keep one implementation in a package both import and call it from both places")
			violations = append(violations, v)
		}
		return violations
	})
}

// helperFuncs returns the file's unexported package-level functions with
// parameters and a name of more than one word that do more than call a
// function of another package.
func helperFuncs(file *ast.File, info *types.Info) []*types.Func {
	var out []*types.Func
	for _, decl := range file.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Recv != nil || fd.Body == nil || ast.IsExported(fd.Name.Name) {
			continue
		}
		if len(helpers.IdentifierWords(fd.Name.Name)) < 2 {
			continue
		}
		fn, ok := info.Defs[fd.Name].(*types.Func)
		if !ok || fn.Signature().Params().Len() == 0 || delegates(fd.Body, info, fn.Pkg()) {
			continue
		}
		out = append(out, fn)
	}
	return out
}

// helperKey is name|signature with types printed by full package path, so
// the same parameter imported under two names gives one key.
func helperKey(fn *types.Func) string {
	return fn.Name() + "|" + types.TypeString(fn.Signature(), nil)
}

// delegates reports a body of one statement that only calls a function or
// method of another package: the implementation is already shared.
func delegates(body *ast.BlockStmt, info *types.Info, own *types.Package) bool {
	if len(body.List) != 1 {
		return false
	}
	var call *ast.CallExpr
	switch s := body.List[0].(type) {
	case *ast.ReturnStmt:
		if len(s.Results) == 1 {
			call, _ = s.Results[0].(*ast.CallExpr)
		}
	case *ast.ExprStmt:
		call, _ = s.X.(*ast.CallExpr)
	}
	if call == nil {
		return false
	}
	var name *ast.Ident
	switch fun := ast.Unparen(call.Fun).(type) {
	case *ast.Ident:
		name = fun
	case *ast.SelectorExpr:
		name = fun.Sel
	}
	if name == nil {
		return false
	}
	callee, ok := info.Uses[name].(*types.Func)
	return ok && callee.Pkg() != nil && callee.Pkg() != own
}
