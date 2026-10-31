package duplication

import (
	"errors"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewForwardingWrapperFuncRule())
}

// ForwardingWrapperFuncRule detects unexported functions that only forward
// their parameters to a function in another package of the same module.
type ForwardingWrapperFuncRule struct {
	*rules.BaseRule
}

// NewForwardingWrapperFuncRule creates the rule.
func NewForwardingWrapperFuncRule() *ForwardingWrapperFuncRule {
	return &ForwardingWrapperFuncRule{BaseRule: rules.NewBaseRule(
		"forwarding-wrapper-func",
		"duplication",
		"Detects unexported functions that only forward their parameters to another package",
		core.SeverityLow,
	)}
}

// AnalyzeFile is a no-op because forwarding wrappers need project type information.
func (r *ForwardingWrapperFuncRule) AnalyzeFile(_ *core.FileContext) []*core.Violation { return nil }

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *ForwardingWrapperFuncRule) RequiresSSA() bool { return false }

// AnalyzeGoProject reports forwarding wrappers in the loaded module.
func (r *ForwardingWrapperFuncRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, errors.New("forwarding wrapper func: nil Go project context")
	}
	index, err := core.SharedLoad(ctx, forwardingWrappersKey{}, func() (*forwardingWrapperIndex, error) {
		return indexForwardingWrappers(ctx)
	})
	if err != nil {
		return nil, err
	}
	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(file *core.FileContext, info *types.Info) []*core.Violation {
		var violations []*core.Violation
		for _, decl := range file.GoAST.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Name == nil {
				continue
			}
			fn, ok := info.Defs[fd.Name].(*types.Func)
			target, found := index.forwarders[fn]
			if !ok || !found || index.values[fn] {
				continue
			}
			line := file.LineFor(fd)
			if file.IsSuppressed(line, r.Name()) {
				continue
			}
			v := r.CreateViolation(file.RelPath, line, fmt.Sprintf("%s only forwards to %s — call %s directly", fd.Name.Name, target, target))
			v.WithCode(strings.TrimSpace(file.GetLine(line)))
			v.WithSuggestion("Call the target function directly and remove this wrapper")
			violations = append(violations, v)
		}
		return violations
	})
}

type forwardingWrappersKey struct{}

type forwardingWrapperIndex struct {
	forwarders map[*types.Func]string
	values     map[*types.Func]bool
}

func indexForwardingWrappers(ctx *core.GoProjectContext) (*forwardingWrapperIndex, error) {
	index := &forwardingWrapperIndex{
		forwarders: make(map[*types.Func]string),
		values:     make(map[*types.Func]bool),
	}
	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil || pkg.Package.TypesInfo == nil {
			return nil, errors.New("forwarding wrapper func: package has no typed syntax")
		}
		if pkg.Package.Module == nil || pkg.Package.Module.Path == "" {
			continue
		}
		for _, file := range pkg.Package.Syntax {
			if file == nil {
				continue
			}
			for fn := range helpers.FuncValues(file, pkg.Package.TypesInfo) {
				index.values[fn] = true
			}
			if syntaxIsTestFile(pkg.Files, file) {
				continue
			}
			for _, decl := range file.Decls {
				fd, ok := decl.(*ast.FuncDecl)
				if !ok || fd.Recv != nil || fd.Body == nil || fd.Name == nil || ast.IsExported(fd.Name.Name) {
					continue
				}
				fn, ok := pkg.Package.TypesInfo.Defs[fd.Name].(*types.Func)
				if !ok {
					continue
				}
				target, ok := forwardedTarget(fd, pkg.Package.TypesInfo, fn, pkg.Package.Module.Path)
				if ok {
					index.forwarders[fn] = target
				}
			}
		}
	}
	return index, nil
}

func syntaxIsTestFile(files []*core.FileContext, syntax *ast.File) bool {
	for _, file := range files {
		if file.GoAST == syntax {
			return file.IsTestFile()
		}
	}
	return false
}

func forwardedTarget(fd *ast.FuncDecl, info *types.Info, wrapper *types.Func, modulePath string) (string, bool) {
	if !delegates(fd.Body, info, wrapper.Pkg()) || len(fd.Body.List) != 1 {
		return "", false
	}
	var call *ast.CallExpr
	switch stmt := fd.Body.List[0].(type) {
	case *ast.ReturnStmt:
		if len(stmt.Results) != 1 {
			return "", false
		}
		call, _ = stmt.Results[0].(*ast.CallExpr)
	case *ast.ExprStmt:
		call, _ = stmt.X.(*ast.CallExpr)
	}
	if call == nil || len(call.Args) != wrapper.Signature().Params().Len() {
		return "", false
	}
	fun := ast.Unparen(call.Fun)
	for {
		if indexed, ok := fun.(*ast.IndexExpr); ok {
			fun = ast.Unparen(indexed.X)
		} else if indexed, ok := fun.(*ast.IndexListExpr); ok {
			fun = ast.Unparen(indexed.X)
		} else {
			break
		}
	}
	selector, ok := fun.(*ast.SelectorExpr)
	if !ok || selector.Sel == nil {
		return "", false
	}
	alias, ok := ast.Unparen(selector.X).(*ast.Ident)
	if !ok {
		return "", false
	}
	if _, ok := info.Uses[alias].(*types.PkgName); !ok {
		return "", false
	}
	callee, ok := info.Uses[selector.Sel].(*types.Func)
	if !ok || callee.Pkg() == nil || callee.Pkg() == wrapper.Pkg() {
		return "", false
	}
	signature, ok := callee.Type().(*types.Signature)
	if !ok || signature.Recv() != nil {
		return "", false
	}
	calleePath := callee.Pkg().Path()
	if calleePath != modulePath && !strings.HasPrefix(calleePath, modulePath+"/") {
		return "", false
	}
	params := wrapper.Signature().Params()
	for i, arg := range call.Args {
		ident, ok := ast.Unparen(arg).(*ast.Ident)
		if !ok || info.Uses[ident] != params.At(i) {
			return "", false
		}
	}
	if wrapper.Signature().Variadic() != (call.Ellipsis != token.NoPos) {
		return "", false
	}
	return callee.Pkg().Name() + "." + callee.Name(), true
}
