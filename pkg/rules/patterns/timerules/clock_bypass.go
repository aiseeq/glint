package timerules

import (
	"go/ast"
	"go/types"
	"sort"
	"strconv"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() { rules.Register(NewClockBypassRule()) }

// ClockBypassRule reports direct reads of the standard clock in a package
// that already uses a project clock from multiple production files:
//
//	func (s *Service) Now() time.Time { return s.clock.Now() }
//	func (s *Service) Expired() bool { return time.Now().After(s.deadline) }
//
// Not flagged: the clock implementation, tests, main packages, packages with
// fewer than two project-clock calls, or a time.Now() used to measure elapsed
// time with time.Since(start) in the same function.
type ClockBypassRule struct{ *rules.BaseRule }

// NewClockBypassRule creates the clock-bypass rule.
func NewClockBypassRule() *ClockBypassRule {
	return &ClockBypassRule{BaseRule: rules.NewBaseRule(
		"clock-bypass", "patterns",
		"Detects standard clock reads in a package that already takes time from a project clock",
		core.SeverityMedium,
	)}
}

// RequiresSSA reports whether this rule requires SSA information.
func (r *ClockBypassRule) RequiresSSA() bool { return false }

// AnalyzeFile is unused because clock-bypass needs package-wide type information.
func (r *ClockBypassRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation { return nil }

type clockPackageUse struct {
	count int
	files map[string]int
}

// AnalyzeGoProject reports standard clock reads in packages that use a project clock.
func (r *ClockBypassRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	projectPaths := projectModulePaths(ctx)
	var violations []*core.Violation
	for _, pkg := range ctx.Packages {
		violations = append(violations, r.analyzeClockPackage(pkg, projectPaths)...)
	}
	return violations, nil
}

func projectModulePaths(ctx *core.GoProjectContext) map[string]bool {
	projectPaths := make(map[string]bool)
	for _, pkg := range ctx.Packages {
		if pkg != nil && pkg.Package != nil && pkg.Package.Module != nil && pkg.Package.Module.Path != "" {
			projectPaths[pkg.Package.Module.Path] = true
		}
	}
	return projectPaths
}

func (r *ClockBypassRule) analyzeClockPackage(pkg *core.GoPackageContext, projectPaths map[string]bool) []*core.Violation {
	if pkg == nil || pkg.Package == nil || pkg.Package.TypesInfo == nil || pkg.Package.Types == nil || pkg.Package.Name == "main" {
		return nil
	}
	files := productionClockFiles(pkg)
	if len(files) == 0 || implementsClockHere(pkg.Package.Types) {
		return nil
	}
	usage := countProjectClockUsage(pkg.Package.TypesInfo, files, projectPaths)
	if usage.count < 2 || len(usage.files) == 0 {
		return nil
	}
	return r.reportClockBypasses(pkg, files, usage)
}

func productionClockFiles(pkg *core.GoPackageContext) []*core.FileContext {
	files := make([]*core.FileContext, 0, len(pkg.Files))
	for _, file := range pkg.Files {
		if file != nil && file.HasGoAST() && !file.IsTestFile() && file.GoAST.Name.Name != "main" {
			files = append(files, file)
		}
	}
	return files
}

func countProjectClockUsage(info *types.Info, files []*core.FileContext, projectPaths map[string]bool) clockPackageUse {
	usage := clockPackageUse{files: make(map[string]int)}
	for _, file := range files {
		for _, decl := range file.GoAST.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if ok && isProjectClockCall(info, call, projectPaths) {
					usage.count++
					usage.files[file.RelPath]++
				}
				return true
			})
		}
	}
	return usage
}

func (r *ClockBypassRule) reportClockBypasses(pkg *core.GoPackageContext, files []*core.FileContext, usage clockPackageUse) []*core.Violation {
	places := make([]string, 0, len(usage.files))
	for name, count := range usage.files {
		places = append(places, name+" ("+itoa(count)+")")
	}
	sort.Strings(places)
	if len(places) > 3 {
		places = append(places[:3], "and "+itoa(len(usage.files)-3)+" more files")
	}
	where := strings.Join(places, ", ")
	var violations []*core.Violation
	for _, file := range files {
		violations = append(violations, r.reportFileClockBypasses(pkg.Package.TypesInfo, file, usage, where)...)
	}
	return violations
}

func (r *ClockBypassRule) reportFileClockBypasses(info *types.Info, file *core.FileContext, usage clockPackageUse, where string) []*core.Violation {
	var violations []*core.Violation
	for _, decl := range file.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		measured := elapsedStartVariables(fn, info)
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok || !isStandardClockCall(info, call) || measured[call] {
				return true
			}
			line := file.LineFor(call)
			violation := r.CreateViolation(file.RelPath, line,
				"This package takes its project clock "+itoa(usage.count)+" times in "+where+"; this standard clock read can disagree with it")
			violation.WithCode(file.GetLine(line))
			violation.WithSuggestion("Use the project's clock for the current time")
			violations = append(violations, violation)
			return true
		})
	}
	return violations
}

func modulePathFor(importPath string, modules map[string]bool) bool {
	for module := range modules {
		if importPath == module || strings.HasPrefix(importPath, module+"/") {
			return true
		}
	}
	return false
}

func isProjectClockCall(info *types.Info, call *ast.CallExpr, modules map[string]bool) bool {
	obj := calledObject(info, call)
	if obj == nil || obj.Name() != "Now" || !returnsTime(obj.Type()) {
		return false
	}
	if fn, ok := obj.(*types.Func); ok {
		if fn.Pkg() != nil && modulePathFor(fn.Pkg().Path(), modules) {
			return true
		}
	}
	if sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr); ok {
		if selection := info.Selections[sel]; selection != nil {
			return projectNamedType(selection.Recv(), modules)
		}
	}
	return false
}

func calledObject(info *types.Info, call *ast.CallExpr) types.Object {
	switch fun := ast.Unparen(call.Fun).(type) {
	case *ast.Ident:
		return info.Uses[fun]
	case *ast.SelectorExpr:
		if selection := info.Selections[fun]; selection != nil {
			return selection.Obj()
		}
		return info.Uses[fun.Sel]
	}
	return nil
}

func returnsTime(typ types.Type) bool {
	sig, ok := typ.(*types.Signature)
	if !ok || sig.Results().Len() != 1 {
		return false
	}
	named, ok := sig.Results().At(0).Type().(*types.Named)
	return ok && named.Obj().Name() == "Time" && named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == "time"
}

func projectNamedType(typ types.Type, modules map[string]bool) bool {
	if pointer, ok := typ.(*types.Pointer); ok {
		typ = pointer.Elem()
	}
	switch value := typ.(type) {
	case *types.Named:
		return value.Obj().Pkg() != nil && modulePathFor(value.Obj().Pkg().Path(), modules) && hasNowMethod(types.NewMethodSet(value))
	case *types.Interface:
		return hasProjectNowMethod(types.NewMethodSet(value.Complete()), modules)
	}
	return false
}

func hasProjectNowMethod(methods *types.MethodSet, modules map[string]bool) bool {
	for selection := range methods.Methods() {
		method := selection.Obj()
		if method.Name() == "Now" && returnsTime(method.Type()) && method.Pkg() != nil && modulePathFor(method.Pkg().Path(), modules) {
			return true
		}
	}
	return false
}

func hasNowMethod(methods *types.MethodSet) bool {
	for selection := range methods.Methods() {
		if selection.Obj().Name() == "Now" && returnsTime(selection.Obj().Type()) {
			return true
		}
	}
	return false
}

func implementsClockHere(pkg *types.Package) bool {
	for _, name := range pkg.Scope().Names() {
		obj := pkg.Scope().Lookup(name)
		fn, ok := obj.(*types.Func)
		if ok && fn.Name() == "Now" && returnsTime(fn.Type()) {
			return true
		}
		if typeName, ok := obj.(*types.TypeName); ok {
			named, ok := typeName.Type().(*types.Named)
			if !ok {
				continue
			}
			for method := range named.Methods() {
				if method.Name() == "Now" && returnsTime(method.Type()) {
					return true
				}
			}
		}
	}
	return false
}

func isStandardClockCall(info *types.Info, call *ast.CallExpr) bool {
	obj := calledObject(info, call)
	if obj == nil || obj.Pkg() == nil || obj.Pkg().Path() != "time" {
		return false
	}
	switch obj.Name() {
	case "Now":
		return true
	case "Since", "Until":
		return true
	default:
		return false
	}
}

func elapsedStartVariables(fn *ast.FuncDecl, info *types.Info) map[*ast.CallExpr]bool {
	starts := make(map[types.Object]*ast.CallExpr)
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		assign, ok := node.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 || !isNamedStandardCall(info, assign.Rhs[0], "Now") {
			return true
		}
		id, ok := assign.Lhs[0].(*ast.Ident)
		if ok {
			call, _ := ast.Unparen(assign.Rhs[0]).(*ast.CallExpr)
			starts[info.Defs[id]] = call
		}
		return true
	})
	measured := make(map[*ast.CallExpr]bool)
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok || !isNamedStandardCall(info, call, "Since") || len(call.Args) != 1 {
			return true
		}
		id, ok := ast.Unparen(call.Args[0]).(*ast.Ident)
		if !ok {
			return true
		}
		if start := starts[info.Uses[id]]; start != nil {
			measured[start] = true
			measured[call] = true
		}
		return true
	})
	return measured
}

func isNamedStandardCall(info *types.Info, expr ast.Expr, name string) bool {
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok {
		return false
	}
	obj := calledObject(info, call)
	return obj != nil && obj.Pkg() != nil && obj.Pkg().Path() == "time" && obj.Name() == name
}

func itoa(value int) string {
	return strconv.Itoa(value)
}
