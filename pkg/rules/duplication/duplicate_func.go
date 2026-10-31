package duplication

import (
	"errors"
	"fmt"
	"go/ast"
	"go/types"
	"maps"
	"slices"
	"sort"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewDuplicateFuncAcrossPackagesRule())
}

// DuplicateFuncAcrossPackagesRule detects helpers copied between packages,
// either under the same name and signature or with an identical normalized
// body under another name:
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
		"Detects helper functions copied between packages — two copies of one implementation that can drift apart",
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
	byKey, byBody, err := indexDuplicateFuncs(ctx)
	if err != nil {
		return nil, err
	}
	twins := keyedTwins(byKey)
	maps.Copy(twins, bodyTwins(byBody))
	if len(twins) == 0 {
		return nil, nil
	}
	return r.findings(ctx, twins)
}

func indexDuplicateFuncs(ctx *core.GoProjectContext) (map[string][]*types.Func, map[string][]*types.Func, error) {
	byKey := make(map[string][]*types.Func)
	byBody := make(map[string][]*types.Func)
	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil || pkg.Package.TypesInfo == nil {
			return nil, nil, errors.New("duplicate func across packages: package has no typed syntax")
		}
		if testDoublePackage(pkg.Package.PkgPath) {
			continue
		}
		for _, file := range pkg.Files {
			if file.GoAST == nil || file.IsTestFile() || file.IsGenerated() {
				continue
			}
			decls := make(map[*types.Func]*ast.FuncDecl)
			for _, decl := range file.GoAST.Decls {
				fd, ok := decl.(*ast.FuncDecl)
				if !ok || fd.Name == nil {
					continue
				}
				if fn, ok := pkg.Package.TypesInfo.Defs[fd.Name].(*types.Func); ok {
					decls[fn] = fd
				}
			}
			// Another module of the repository cannot call the original
			// without a new module dependency: copies match within a module.
			module := moduleOf(pkg.Package) + "\x00"
			for _, fn := range helperFuncs(file.GoAST, pkg.Package.TypesInfo) {
				key := module + helperKey(fn)
				byKey[key] = append(byKey[key], fn)
			}
			for _, fn := range bodyFuncs(file.GoAST, pkg.Package.TypesInfo) {
				fd := decls[fn]
				if fd == nil {
					continue
				}
				normalizer := newFunctionBlockNormalizer(pkg.Package.TypesInfo, fd)
				normalizer.walk(fd.Body)
				if normalizer.nodes < minimumDuplicateBodyNodes {
					continue
				}
				key := module + normalizer.b.String()
				byBody[key] = append(byBody[key], fn)
			}
		}
	}
	return byKey, byBody, nil
}

type duplicateFuncTwin struct {
	original string
	canCall  bool
	// unexported marks an original the copy can call only once exported.
	unexported bool
}

func keyedTwins(byKey map[string][]*types.Func) map[*types.Func]duplicateFuncTwin {
	twins := make(map[*types.Func]duplicateFuncTwin)
	keys := make([]string, 0, len(byKey))
	for key := range byKey {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		// One copy per package: the twin is always another package.
		copies := uniquePackageFuncs(byKey[key])
		if len(copies) < 2 {
			continue
		}
		sort.Slice(copies, func(i, j int) bool { return originalFuncLess(copies[i], copies[j]) })
		// Named helpers are unexported by selection, so calling across needs
		// an export, and only a package every copy can import may keep it:
		// that package is the twin of every other copy and is not reported.
		kept := slices.IndexFunc(copies, func(c *types.Func) bool { return packageImportedByAll(c.Pkg(), copies) })
		if kept >= 0 {
			for i, c := range copies {
				if i != kept {
					twins[c] = duplicateFuncTwin{original: copies[kept].Pkg().Path(), canCall: true, unexported: true}
				}
			}
			continue
		}
		// No package can keep it: the first copy is the twin of every other
		// copy, and the second is the twin of the first.
		for i, c := range copies {
			twin := copies[0].Pkg()
			if i == 0 {
				twin = copies[1].Pkg()
			}
			twins[c] = duplicateFuncTwin{original: twin.Path(), unexported: true}
		}
	}
	return twins
}

func bodyTwins(byBody map[string][]*types.Func) map[*types.Func]duplicateFuncTwin {
	twins := make(map[*types.Func]duplicateFuncTwin)
	bodyKeys := make([]string, 0, len(byBody))
	for key := range byBody {
		bodyKeys = append(bodyKeys, key)
	}
	sort.Strings(bodyKeys)
	for _, key := range bodyKeys {
		copies := uniquePackageFuncs(byBody[key])
		if len(copies) < 2 {
			continue
		}
		sort.Slice(copies, func(i, j int) bool { return originalFuncLess(copies[i], copies[j]) })
		original, canCall := copies[0], false
		for _, candidate := range copies {
			if packageImportedByAll(candidate.Pkg(), copies) {
				original, canCall = candidate, true
				break
			}
		}
		for _, copyFn := range copies {
			if copyFn == original {
				continue
			}
			twins[copyFn] = duplicateFuncTwin{
				original:   fmt.Sprintf("%s.%s", original.Pkg().Path(), original.Name()),
				canCall:    canCall,
				unexported: !original.Exported(),
			}
		}
	}
	return twins
}

func packageImportedByAll(candidate *types.Package, copies []*types.Func) bool {
	if candidate == nil || candidate.Name() == "main" {
		return false
	}
	for _, copyFn := range copies {
		if copyFn.Pkg() != candidate && !packageImportableFrom(copyFn.Pkg().Path(), candidate.Path()) {
			return false
		}
	}
	return true
}

func packageImportableFrom(importerPath, importedPath string) bool {
	internalAt := strings.LastIndex(importedPath+"/", "/internal/")
	if internalAt < 0 {
		return true
	}
	parent := importedPath[:internalAt]
	return importerPath == parent || strings.HasPrefix(importerPath, parent+"/")
}

func (r *DuplicateFuncAcrossPackagesRule) findings(ctx *core.GoProjectContext, twins map[*types.Func]duplicateFuncTwin) ([]*core.Violation, error) {
	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(file *core.FileContext, info *types.Info) []*core.Violation {
		var violations []*core.Violation
		for _, decl := range file.GoAST.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			fn, ok := info.Defs[fd.Name].(*types.Func)
			twin, hasTwin := twins[fn]
			if !ok || !hasTwin {
				continue
			}
			line := file.LineFor(fd)
			if file.IsSuppressed(line, r.Name()) {
				continue
			}
			advice := "keep one implementation and call it from both packages"
			suggestion := "Keep one implementation and call it from both places; when neither package should import the other, move it to a shared package, and when the standard library already does it, call that instead"
			switch {
			case !twin.canCall:
				advice = "move one implementation into a package both can import"
				suggestion = "Move the shared implementation into a package both packages can import"
			case twin.unexported:
				advice = "keep one implementation, export it and call it from both packages"
			}
			message := fmt.Sprintf("Function %s duplicates %s — %s", fd.Name.Name, twin.original, advice)
			v := r.CreateViolation(file.RelPath, line, message)
			v.WithCode(strings.TrimSpace(file.GetLine(line)))
			v.WithSuggestion(suggestion)
			violations = append(violations, v)
		}
		return violations
	})
}

// minimumDuplicateBodyNodes excludes accessors and one-call wrappers, whose
// matching is common by design; 20 normalized AST nodes retains the request
// predicate probe while excluding those idioms.
const minimumDuplicateBodyNodes = 20

func bodyFuncs(file *ast.File, info *types.Info) []*types.Func {
	var out []*types.Func
	for _, decl := range file.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Recv != nil || fd.Body == nil || fd.Name == nil {
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

func uniquePackageFuncs(funcs []*types.Func) []*types.Func {
	sort.Slice(funcs, func(i, j int) bool {
		if funcs[i].Pkg().Path() != funcs[j].Pkg().Path() {
			return funcs[i].Pkg().Path() < funcs[j].Pkg().Path()
		}
		return funcs[i].Name() < funcs[j].Name()
	})
	seen := make(map[*types.Package]bool)
	out := funcs[:0]
	for _, fn := range funcs {
		if fn == nil || fn.Pkg() == nil || seen[fn.Pkg()] {
			continue
		}
		seen[fn.Pkg()] = true
		out = append(out, fn)
	}
	return out
}

func originalFuncLess(a, b *types.Func) bool {
	if ast.IsExported(a.Name()) != ast.IsExported(b.Name()) {
		return ast.IsExported(a.Name())
	}
	if a.Pkg().Path() != b.Pkg().Path() {
		return a.Pkg().Path() < b.Pkg().Path()
	}
	return a.Name() < b.Name()
}

// helperFuncs returns named unexported package-level helpers used by the
// signature-based index.
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
