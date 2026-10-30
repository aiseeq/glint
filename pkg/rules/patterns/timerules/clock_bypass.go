package timerules

import (
	"go/ast"
	"go/token"
	"go/types"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
)

func init() { rules.Register(NewClockBypassRule()) }

// ClockBypassRule reports direct reads of the standard clock in a package
// that already uses a project clock from multiple production files:
//
//	func (s *Service) Now() time.Time { return s.clock.Now() }
//	func (s *Service) Expired() bool { return time.Now().After(s.deadline) }
//
// The clock_package setting enables module-wide checks, including SQL literals.
// Not flagged: the clock implementation, tests, main packages, or a time.Now()
// used to measure elapsed time with time.Since(start) in the same function.
type ClockBypassRule struct{ *rules.BaseRule }

// NewClockBypassRule creates the clock-bypass rule.
func NewClockBypassRule() *ClockBypassRule {
	return &ClockBypassRule{BaseRule: rules.NewBaseRule(
		"clock-bypass", "patterns",
		"Detects standard clock reads alongside the project clock; clock_package enables module-wide Go and SQL checks",
		core.SeverityMedium,
	).DeclareSettings(rules.NewSettingSpec("clock_package", "string", "", "Project clock package import path used for module-wide checks.", "example/clock"))}
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
	clockPackage := r.GetStringSetting("clock_package", "")
	if clockPackage != "" && pkg.Package.PkgPath == clockPackage {
		return nil
	}
	usage := countProjectClockUsage(pkg.Package.TypesInfo, files, projectPaths)
	if clockPackage == "" && (usage.count < 2 || len(usage.files) == 0) {
		return nil
	}
	places := make([]string, 0, len(usage.files))
	for name, count := range usage.files {
		places = append(places, name+" ("+itoa(count)+")")
	}
	sort.Strings(places)
	if len(places) > 3 {
		places = append(places[:3], "and "+itoa(len(usage.files)-3)+" more files")
	}
	message := "This package takes its project clock " + itoa(usage.count) + " times in " + strings.Join(places, ", ") + "; this standard clock read can disagree with it"
	if clockPackage != "" {
		message = "This module takes time from " + clockPackage + "; this standard clock read can disagree with it"
	}
	var violations []*core.Violation
	for _, file := range files {
		violations = append(violations, r.reportStandardClockReads(pkg.Package.TypesInfo, file, message)...)
	}
	if clockPackage != "" {
		for _, file := range files {
			violations = append(violations, r.reportSQLClockReads(pkg.Package.TypesInfo, file)...)
		}
	}
	return violations
}

var databaseClockRead = regexp.MustCompile(`(?i)\bNOW\s*\(\s*\)|\b(?:CURRENT_TIMESTAMP|LOCALTIMESTAMP|CURRENT_DATE)\b`)

func (r *ClockBypassRule) reportStandardClockReads(info *types.Info, file *core.FileContext, message string) []*core.Violation {
	measured := make(map[*ast.CallExpr]bool)
	for _, decl := range file.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		for call := range elapsedStartVariables(fn, info) {
			measured[call] = true
		}
	}
	var violations []*core.Violation
	ast.Inspect(file.GoAST, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok || !isStandardClockCall(info, call) || measured[call] {
			return true
		}
		line := file.LineFor(call)
		violation := r.CreateViolation(file.RelPath, line, message)
		violation.WithCode(file.GetLine(line))
		violation.WithSuggestion("Use the project's clock for the current time")
		violations = append(violations, violation)
		return true
	})
	return violations
}

func (r *ClockBypassRule) reportSQLClockReads(info *types.Info, file *core.FileContext) []*core.Violation {
	sqlLiterals := patternkit.SqlLiterals(file.GoAST)
	covered := make(map[token.Pos]bool)
	for _, literal := range sqlLiterals {
		ast.Inspect(literal.Expr, func(node ast.Node) bool {
			if text, ok := node.(*ast.BasicLit); ok && text.Kind == token.STRING {
				covered[text.Pos()] = true
			}
			return true
		})
	}
	parents := make(map[ast.Node]ast.Node)
	var stack []ast.Node
	ast.Inspect(file.GoAST, func(node ast.Node) bool {
		if node == nil {
			stack = stack[:len(stack)-1]
			return false
		}
		if len(stack) > 0 {
			parents[node] = stack[len(stack)-1]
		}
		stack = append(stack, node)
		return true
	})
	flowingParams := returnedStringParams(info, file.GoAST)
	var violations []*core.Violation
	ast.Inspect(file.GoAST, func(node ast.Node) bool {
		text, ok := node.(*ast.BasicLit)
		if !ok || text.Kind != token.STRING || covered[text.Pos()] {
			return true
		}
		value, ok := patternkit.GoStringLiteral(text)
		if !ok || !databaseClockRead.MatchString(value) || !isSQLFragment(text, parents, info, flowingParams) {
			return true
		}
		line := file.LineForPos(text.Pos())
		for range databaseClockRead.FindAllStringIndex(value, -1) {
			violation := r.CreateViolation(file.RelPath, line, "This query takes its time from the database clock instead of the project clock; pass the moment as a parameter")
			violation.WithCode(file.GetLine(line))
			violation.WithSuggestion("Pass the current moment from the project clock as a query parameter; cast it in INTERVAL arithmetic as $N::timestamptz")
			violations = append(violations, violation)
		}
		return true
	})
	for _, literal := range sqlLiterals {
		for _, match := range databaseClockRead.FindAllStringIndex(literal.Text, -1) {
			line := literal.LineAt(file, match[0])
			violation := r.CreateViolation(file.RelPath, line, "This query takes its time from the database clock instead of the project clock; pass the moment as a parameter")
			violation.WithCode(file.GetLine(line))
			violation.WithSuggestion("Pass the current moment from the project clock as a query parameter; cast it in INTERVAL arithmetic as $N::timestamptz")
			violations = append(violations, violation)
		}
	}
	return violations
}

func returnedStringParams(info *types.Info, file *ast.File) map[*types.Func]map[int]bool {
	flows := make(map[*types.Func]map[int]bool)
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || fn.Name == nil {
			continue
		}
		object, _ := info.Defs[fn.Name].(*types.Func)
		if object == nil {
			continue
		}
		signature, _ := object.Type().(*types.Signature)
		if signature == nil || signature.Results().Len() != 1 || !patternkit.IsStringType(signature.Results().At(0).Type()) {
			continue
		}
		params := make(map[*types.Var]int)
		for i := 0; i < signature.Params().Len(); i++ {
			if patternkit.IsStringType(signature.Params().At(i).Type()) {
				params[signature.Params().At(i)] = i
			}
		}
		used := make(map[int]bool)
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			ret, ok := node.(*ast.ReturnStmt)
			if !ok {
				return true
			}
			for _, result := range ret.Results {
				ast.Inspect(result, func(part ast.Node) bool {
					if id, ok := part.(*ast.Ident); ok {
						if param, ok := info.Uses[id].(*types.Var); ok {
							if index, found := params[param]; found {
								used[index] = true
							}
						}
					}
					return true
				})
			}
			return true
		})
		if object != nil && len(used) > 0 {
			flows[object] = used
		}
	}
	return flows
}

func isSQLFragment(literal *ast.BasicLit, parents map[ast.Node]ast.Node, info *types.Info, flowingParams map[*types.Func]map[int]bool) bool {
	for node := ast.Node(literal); node != nil; node = parents[node] {
		if call, ok := node.(*ast.CallExpr); ok && isDiagnosticCall(calledObject(info, call)) {
			return false
		}
	}
	for node := ast.Node(literal); node != nil; node = parents[node] {
		if call, ok := node.(*ast.CallExpr); ok {
			obj := calledObject(info, call)
			if obj != nil && obj.Pkg() != nil && obj.Pkg().Path() == "fmt" && obj.Name() == "Sprintf" {
				return true
			}
			if ident, ok := ast.Unparen(call.Fun).(*ast.Ident); ok && ident.Name == "append" {
				for _, arg := range call.Args[1:] {
					if patternkit.ContainsNode(arg, literal) {
						return true
					}
				}
			}
			function, _ := obj.(*types.Func)
			if indexes := flowingParams[function]; function != nil && len(indexes) > 0 {
				for index := range indexes {
					if index < len(call.Args) && patternkit.ContainsNode(call.Args[index], literal) {
						return true
					}
				}
			}
		}
		if composite, ok := node.(*ast.CompositeLit); ok && isClockBypassStringSlice(info.TypeOf(composite)) && patternkit.ContainsNode(composite, literal) {
			return true
		}
		if binary, ok := node.(*ast.BinaryExpr); ok && binary.Op == token.ADD {
			return true
		}
	}
	return false
}

func isClockBypassStringSlice(typ types.Type) bool {
	if typ == nil {
		return false
	}
	slice, ok := typ.Underlying().(*types.Slice)
	return ok && patternkit.IsStringType(slice.Elem())
}

func isDiagnosticCall(obj types.Object) bool {
	if obj == nil || obj.Pkg() == nil {
		return false
	}
	name, path := obj.Name(), obj.Pkg().Path()
	switch path {
	case "errors":
		return name == "New" || name == "Join"
	case "fmt":
		return name == "Errorf"
	case "log", "log/slog", "testing":
		return strings.HasPrefix(name, "Print") || strings.HasPrefix(name, "Fatal") || strings.HasPrefix(name, "Panic") || strings.HasPrefix(name, "Log") || name == "Error" || name == "Warn" || name == "Info" || name == "Debug"
	}
	return false
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
