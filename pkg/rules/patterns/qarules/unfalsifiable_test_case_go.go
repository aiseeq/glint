package qarules

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/helpers"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
)

// UseProjectFiles collects the text every page of the project carries: the
// layout templates and the stylesheets, read from disk - the analysis does
// not list them.
func (r *UnfalsifiableTestCaseRule) UseProjectFiles(files []*core.FileContext) {
	r.sharedPageText = make(map[string]string)
	r.packageNamesByDir = make(map[string]map[string]bool)
	r.unknownPackageDirs = make(map[string]error)
	r.sharedPageErr = nil
	texts := make(map[string][]string)
	roots := make(map[string]bool)
	for _, file := range files {
		if file.ProjectRoot != "" && file.IsGoFile() && file.IsTestFile() {
			roots[file.ProjectRoot] = true
		}
	}
	for root := range roots {
		paths, err := patternkit.FilesWithExt(root, ".css", ".html", ".tmpl", ".gohtml")
		if err != nil {
			r.sharedPageErr = fmt.Errorf("list layouts under %s: %w", root, err)
			return
		}
		for _, path := range paths {
			if !sharedPageFile(path) {
				continue
			}
			data, err := os.ReadFile(path)
			if err != nil {
				r.sharedPageErr = fmt.Errorf("read layout: %w", err)
				return
			}
			dir := filepath.Dir(filepath.Dir(path))
			texts[dir] = append(texts[dir], string(data))
		}
	}
	for dir, parts := range texts {
		r.sharedPageText[dir] = strings.Join(parts, "\n")
	}
	r.collectPackageNames(files)
}

// collectPackageNames reads the package-level names of every Go file on disk
// next to a file under a shared layout or stylesheet, the files the walk
// leaves out included. A directory whose files do not parse leaves its
// package names unknown.
func (r *UnfalsifiableTestCaseRule) collectPackageNames(files []*core.FileContext) {
	diskNamesByDir := make(map[string]map[string]map[string]bool)
	for _, file := range files {
		if !file.IsGoFile() || file.GoAST == nil || r.sharedTextAbove(file.Path) == "" {
			continue
		}
		dir := filepath.Clean(filepath.Dir(file.Path))
		diskNames, seen := diskNamesByDir[dir]
		if !seen {
			var err error
			diskNames, err = packageLevelNamesOnDisk(dir)
			if err != nil {
				r.unknownPackageDirs[dir] = err
			}
			diskNamesByDir[dir] = diskNames
		}
		for packageName, names := range diskNames {
			key := bodyPackageKey(file.Path, packageName)
			packageNames := r.packageNamesByDir[key]
			if packageNames == nil {
				packageNames = make(map[string]bool)
				r.packageNamesByDir[key] = packageNames
			}
			for name := range names {
				packageNames[name] = true
			}
		}
	}
}

// ResetState drops the shared text of the previous root.
func (r *UnfalsifiableTestCaseRule) ResetState() {
	r.sharedPageText, r.packageNamesByDir, r.unknownPackageDirs, r.sharedPageErr = nil, nil, nil, nil
}

// sharedPageFile reports a layout template or a stylesheet.
func sharedPageFile(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	switch filepath.Ext(base) {
	case ".css":
		return true
	case ".html", ".tmpl", ".gohtml":
		return strings.Contains(base, "layout") || strings.HasPrefix(base, "base.")
	}
	return false
}

// pageMarker is a lone CSS class or word a body check looks for.
var pageMarker = regexp.MustCompile(`^[A-Za-z][\w-]*$`)

// analyzeGoBodyMarkers reports a Go test check that a response body holds a
// marker the shared layout or stylesheet carries on every page:
//
//	if !strings.Contains(body, "callout-error") { t.Fatal(...) } // in the CSS of every page
//
// The check holds whether the code under test rendered anything.
func (r *UnfalsifiableTestCaseRule) analyzeGoBodyMarkers(ctx *core.FileContext) []*core.Violation {
	if r.sharedPageErr != nil {
		v := r.CreateViolation(ctx.RelPath, 1, "Project files could not be read, so body checks were not compared with them: "+r.sharedPageErr.Error())
		v.Severity = core.SeverityCritical
		return []*core.Violation{v}
	}
	shared := r.sharedTextAbove(ctx.Path)
	if shared == "" {
		return nil
	}
	return analyzeGoBodyMarkerCalls(r, ctx, shared)
}

type bodyMarkerCandidate struct {
	call   *ast.CallExpr
	marker string
}

func analyzeGoBodyMarkerCalls(rule *UnfalsifiableTestCaseRule, ctx *core.FileContext, shared string) []*core.Violation {
	sharedMarkers := make(map[string]bool)
	packages := bodyPackages(ctx.GoAST)
	packageNames := rule.packageNamesByDir[bodyPackageKey(ctx.Path, ctx.GoAST.Name.Name)]
	var violations []*core.Violation
	for _, declaration := range ctx.GoAST.Decls {
		if fn, ok := declaration.(*ast.FuncDecl); ok {
			if fn.Body == nil {
				continue
			}
			candidates := collectBodyMarkerCandidates(fn.Body, packages.strings, shared, sharedMarkers)
			if len(candidates) == 0 {
				continue
			}
			index := buildBodyOriginIndex(ctx.GoAST, fn.Type, fn.Body, packages, fn.Recv, packageNames)
			index.outerNamesUnknown = index.outerNamesUnknown || rule.unknownPackageDirs[filepath.Clean(filepath.Dir(ctx.Path))] != nil
			for _, candidate := range candidates {
				subject, _, _ := bodyMarkerArgs(candidate.call, packages.strings)

				if !index.shadowsStringsContains(candidate.call) && index.isNonBody(subject) {
					continue
				}
				violations = append(violations, bodyMarkerViolation(rule, ctx, candidate))
			}
			continue
		}
		ast.Inspect(declaration, func(node ast.Node) bool {
			literal, ok := node.(*ast.FuncLit)
			if !ok {
				return true
			}
			candidates := collectBodyMarkerCandidates(literal.Body, packages.strings, shared, sharedMarkers)
			for _, candidate := range candidates {
				violations = append(violations, bodyMarkerViolation(rule, ctx, candidate))
			}
			return false
		})
	}
	return violations
}

func collectBodyMarkerCandidates(body ast.Node, stringsPackages map[string]bool, shared string, sharedMarkers map[string]bool) []bodyMarkerCandidate {
	var candidates []bodyMarkerCandidate
	ast.Inspect(body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		_, markerExpr, ok := bodyMarkerArgs(call, stringsPackages)
		if !ok {
			return true
		}
		literal, ok := markerExpr.(*ast.BasicLit)
		if !ok || literal.Kind != token.STRING {
			return true
		}
		marker, err := strconv.Unquote(literal.Value)
		if err != nil || !pageMarker.MatchString(marker) {
			return true
		}
		present, cached := sharedMarkers[marker]
		if !cached {
			present = sharedHasMarker(shared, marker)
			sharedMarkers[marker] = present
		}
		if present {
			candidates = append(candidates, bodyMarkerCandidate{call: call, marker: marker})
		}
		return true
	})
	return candidates
}

func bodyMarkerViolation(rule *UnfalsifiableTestCaseRule, ctx *core.FileContext, candidate bodyMarkerCandidate) *core.Violation {
	line := ctx.LineFor(candidate.call)
	v := rule.CreateViolation(ctx.RelPath, line, "The test looks for \""+candidate.marker+"\" in the body, and the shared layout or stylesheet carries it on every page — the check passes whether the page rendered it or not")
	v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
	v.WithSuggestion("Assert the markup only this response renders (the element with its text), not a class name or a word of the layout")
	return v
}

func bodyPackageKey(path, packageName string) string {
	return filepath.Clean(filepath.Dir(path)) + "\x00" + packageName
}

type bodyOriginPackages struct {
	strings map[string]bool
	os      map[string]bool
	ioutil  map[string]bool
	fmt     map[string]bool
}

type bodyBinding struct {
	declarations          int
	parameter             bool
	builder               bool
	readFileSource        bool
	readFileUsedElsewhere bool
	writes                []ast.Expr
	scanned               bool
	escaped               bool
	builderWrites         []ast.Expr
	state                 uint8
	known                 bool
}

type bodyOriginIndex struct {
	packages      bodyOriginPackages
	bindings      map[string]*bodyBinding
	packageNames  map[string]bool
	dotRootLocals map[string]token.Pos
	// outerNamesUnknown: a dot-import or an unreadable file of the package
	// may declare any name outside the function.
	outerNamesUnknown bool
	scanAddr          map[*ast.UnaryExpr]bool
}

func bodyPackages(file *ast.File) bodyOriginPackages {
	return bodyOriginPackages{
		strings: helpers.PackageAliases(file, `"strings"`, "strings"),
		os:      helpers.PackageAliases(file, `"os"`, "os"),
		ioutil:  helpers.PackageAliases(file, `"io/ioutil"`, "ioutil"),
		fmt:     helpers.PackageAliases(file, `"fmt"`, "fmt"),
	}
}

func bodyMarkerArgs(call *ast.CallExpr, stringsPackages map[string]bool) (ast.Expr, ast.Expr, bool) {
	if len(call.Args) == 2 {
		if sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr); ok && sel.Sel.Name == "Contains" {
			if pkg, ok := ast.Unparen(sel.X).(*ast.Ident); ok && (pkg.Name == "strings" || stringsPackages[pkg.Name]) {
				return call.Args[0], call.Args[1], true
			}
		}
	}
	if strings.HasSuffix(core.ExtractFullFunctionName(call), ".Contains") && len(call.Args) >= 3 {
		return call.Args[1], call.Args[2], true
	}
	return nil, nil, false
}

func buildBodyOriginIndex(file *ast.File, fn *ast.FuncType, body *ast.BlockStmt, packages bodyOriginPackages, receiver *ast.FieldList, projectPackageNames ...map[string]bool) *bodyOriginIndex {
	packageNames := packageLevelNames(file)
	for _, names := range projectPackageNames {
		for name := range names {
			packageNames[name] = true
		}
	}
	idx := &bodyOriginIndex{
		packages:          packages,
		bindings:          make(map[string]*bodyBinding),
		packageNames:      packageNames,
		outerNamesUnknown: hasDotImport(file),
		scanAddr:          make(map[*ast.UnaryExpr]bool),
	}
	idx.declareFields(fn, receiver)
	idx.indexDotImportRootLocals(body)
	ast.Inspect(body, func(node ast.Node) bool {
		switch current := node.(type) {
		case *ast.FuncLit:
			idx.declareFields(current.Type, nil)
		case *ast.ValueSpec:
			for _, name := range current.Names {
				idx.declare(name.Name, false)
			}
		case *ast.TypeSpec:
			idx.declare(current.Name.Name, false)
		case *ast.AssignStmt:
			if current.Tok == token.DEFINE {
				for _, lhs := range current.Lhs {
					if id, ok := ast.Unparen(lhs).(*ast.Ident); ok {
						idx.declare(id.Name, false)
					}
				}
			}
		case *ast.RangeStmt:
			if current.Tok == token.DEFINE {
				idx.declareTarget(current.Key, false)
				idx.declareTarget(current.Value, false)
			}
		}
		return true
	})
	idx.markBuilderDeclarations(body)
	idx.indexScanTargets(body)
	idx.indexWritesAndEscapes(body)
	idx.indexReadFileUses(body)
	return idx
}

func (idx *bodyOriginIndex) indexDotImportRootLocals(body *ast.BlockStmt) {
	idx.dotRootLocals = make(map[string]token.Pos)
	if body == nil {
		return
	}

	for _, statement := range body.List {
		switch current := statement.(type) {
		case *ast.AssignStmt:
			if current.Tok == token.DEFINE {
				for _, lhs := range current.Lhs {
					idx.addDotImportRootLocal(lhs)
				}
			}
		case *ast.DeclStmt:
			idx.addDotImportDeclLocals(current.Decl)
		}
	}
}

func (idx *bodyOriginIndex) addDotImportDeclLocals(decl ast.Decl) {
	declaration, ok := decl.(*ast.GenDecl)
	if !ok {
		return
	}
	for _, spec := range declaration.Specs {
		values, ok := spec.(*ast.ValueSpec)
		if !ok {
			continue
		}
		for _, name := range values.Names {
			idx.addDotImportRootLocal(name)
		}
	}
}

func (idx *bodyOriginIndex) addDotImportRootLocal(expr ast.Expr) {
	id, ok := ast.Unparen(expr).(*ast.Ident)
	if !ok {
		return
	}
	if previous := idx.dotRootLocals[id.Name]; previous == token.NoPos || id.Pos() < previous {
		idx.dotRootLocals[id.Name] = id.Pos()
	}
}

func hasDotImport(file *ast.File) bool {
	for _, imported := range file.Imports {
		if imported.Name != nil && imported.Name.Name == "." {
			return true
		}
	}
	return false
}

func packageLevelNamesOnDisk(dir string) (map[string]map[string]bool, error) {
	packages := make(map[string]map[string]bool)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read directory %s: %w", dir, err)
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".go" {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		file, parseErr := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
		if parseErr != nil {
			return nil, fmt.Errorf("parse %s: %w", path, parseErr)
		}
		if file == nil {
			continue
		}
		names := packages[file.Name.Name]
		if names == nil {
			names = make(map[string]bool)
			packages[file.Name.Name] = names
		}
		for name := range packageLevelNames(file) {
			names[name] = true
		}
	}
	return packages, nil
}

func packageLevelNames(file *ast.File) map[string]bool {
	names := make(map[string]bool)
	if file == nil {
		return names
	}
	for _, declaration := range file.Decls {
		switch current := declaration.(type) {
		case *ast.FuncDecl:
			names[current.Name.Name] = true
		case *ast.GenDecl:
			for _, spec := range current.Specs {
				switch value := spec.(type) {
				case *ast.ValueSpec:
					for _, name := range value.Names {
						names[name.Name] = true
					}
				case *ast.TypeSpec:
					names[value.Name.Name] = true
				}
			}
		}
	}
	return names
}

func (idx *bodyOriginIndex) declareFields(fn *ast.FuncType, receiver *ast.FieldList) {
	if fn != nil {
		idx.declareFieldList(fn.Params)
		idx.declareFieldList(fn.Results)
	}
	idx.declareFieldList(receiver)
}

func (idx *bodyOriginIndex) declareFieldList(fields *ast.FieldList) {
	if fields == nil {
		return
	}
	for _, field := range fields.List {
		for _, name := range field.Names {
			idx.declare(name.Name, true)
		}
	}
}

func (idx *bodyOriginIndex) declareTarget(expr ast.Expr, parameter bool) {
	if id, ok := ast.Unparen(expr).(*ast.Ident); ok {
		idx.declare(id.Name, parameter)
	}
}

func (idx *bodyOriginIndex) declare(name string, parameter bool) {
	if name == "_" {
		return
	}
	binding := idx.bindings[name]
	if binding == nil {
		binding = &bodyBinding{}
		idx.bindings[name] = binding
	}
	binding.declarations++
	binding.parameter = binding.parameter || parameter
}

func (idx *bodyOriginIndex) dotImportLocalAt(name string, pos token.Pos) bool {
	declaration := idx.dotRootLocals[name]
	return declaration != token.NoPos && declaration < pos
}

func (idx *bodyOriginIndex) nameIsDeclared(name string) bool {
	binding := idx.bindings[name]
	return idx.outerNamesUnknown || binding != nil && binding.declarations > 0 || idx.packageNames[name]
}

func (idx *bodyOriginIndex) uniqueBinding(name string) *bodyBinding {
	binding := idx.bindings[name]
	if binding == nil || binding.declarations != 1 || binding.parameter || idx.packageNames[name] {
		return nil
	}
	return binding
}

func (idx *bodyOriginIndex) markBuilderDeclarations(body *ast.BlockStmt) {
	ast.Inspect(body, func(node ast.Node) bool {
		switch current := node.(type) {
		case *ast.ValueSpec:
			for _, name := range current.Names {
				if binding := idx.bindings[name.Name]; binding != nil && idx.isBuilderType(current.Type) {
					binding.builder = true
				}
			}
			for i, name := range current.Names {
				if i < len(current.Values) {
					if binding := idx.bindings[name.Name]; binding != nil && idx.isBuilderLiteral(current.Values[i]) {
						binding.builder = true
					}
				}
			}
		case *ast.AssignStmt:
			for i, lhs := range current.Lhs {
				if i < len(current.Rhs) {
					if id, ok := ast.Unparen(lhs).(*ast.Ident); ok {
						if binding := idx.bindings[id.Name]; binding != nil && idx.isBuilderLiteral(current.Rhs[i]) {
							binding.builder = true
						}
					}
				}
			}
		}
		return true
	})
}

func (idx *bodyOriginIndex) indexScanTargets(body *ast.BlockStmt) {
	ast.Inspect(body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok || !isBodyScanCall(call) {
			return true
		}
		for _, argument := range call.Args {
			address, ok := ast.Unparen(argument).(*ast.UnaryExpr)
			if !ok || address.Op != token.AND {
				continue
			}
			idx.scanAddr[address] = true
			if id, ok := ast.Unparen(address.X).(*ast.Ident); ok {
				if binding := idx.bindings[id.Name]; binding != nil {
					binding.scanned = true
				}
			}
		}
		return true
	})
}

func (idx *bodyOriginIndex) indexWritesAndEscapes(body *ast.BlockStmt) {
	var stack []ast.Node
	ast.Inspect(body, func(node ast.Node) bool {
		if node == nil {
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			return false
		}
		var parent ast.Node
		if len(stack) > 0 {
			parent = stack[len(stack)-1]
		}
		switch current := node.(type) {
		case *ast.ValueSpec:
			idx.indexValueWrites(current)
		case *ast.AssignStmt:
			idx.indexAssignWrites(current)
		case *ast.RangeStmt:
			idx.addTargetWrite(current.Key, nil)
			idx.addTargetWrite(current.Value, nil)
		case *ast.IncDecStmt:
			idx.addTargetWrite(current.X, nil)
		case *ast.CallExpr:
			idx.recordBuilderCall(current)
		case *ast.UnaryExpr:
			if current.Op == token.AND && !idx.scanAddr[current] {
				if id, ok := ast.Unparen(current.X).(*ast.Ident); ok {
					if binding := idx.bindings[id.Name]; binding != nil {
						binding.escaped = true
					}
				}
			}
		case *ast.SelectorExpr:
			if id, ok := ast.Unparen(current.X).(*ast.Ident); ok {
				if binding := idx.bindings[id.Name]; binding != nil && binding.builder {
					if call, ok := parent.(*ast.CallExpr); !ok || call.Fun != current {
						binding.escaped = true
					}
				}
			}
		}
		stack = append(stack, node)
		return true
	})
}

func (idx *bodyOriginIndex) indexValueWrites(spec *ast.ValueSpec) {
	if len(spec.Values) == 0 {
		return
	}
	for i, name := range spec.Names {
		value, readFileSource := idx.writeValue(spec.Values, len(spec.Names), i)
		if readFileSource {
			if binding := idx.bindings[name.Name]; binding != nil {
				binding.readFileSource = true
			}
		}
		idx.addWrite(name.Name, value)
	}
}

func (idx *bodyOriginIndex) writeValue(values []ast.Expr, lhsCount, index int) (ast.Expr, bool) {
	if len(values) == lhsCount && index < len(values) {
		return values[index], false
	}
	if len(values) == 1 && lhsCount == 1 {
		return values[0], false
	}
	if len(values) == 1 && lhsCount > 1 {
		call, ok := ast.Unparen(values[0]).(*ast.CallExpr)
		if ok && idx.isReadFile(call) {
			return values[0], index == 0
		}
	}
	return nil, false
}

func (idx *bodyOriginIndex) indexAssignWrites(stmt *ast.AssignStmt) {
	for i, lhs := range stmt.Lhs {
		id, ok := ast.Unparen(lhs).(*ast.Ident)
		if !ok {
			idx.markIndirectWrite(lhs)
			continue
		}
		if stmt.Tok != token.ASSIGN && stmt.Tok != token.DEFINE {
			idx.addWrite(id.Name, nil)
			continue
		}
		value, readFileSource := idx.writeValue(stmt.Rhs, len(stmt.Lhs), i)
		if readFileSource {
			if binding := idx.bindings[id.Name]; binding != nil {
				binding.readFileSource = true
			}
		}
		idx.addWrite(id.Name, value)
	}
}

func (idx *bodyOriginIndex) markIndirectWrite(lhs ast.Expr) {
	switch target := ast.Unparen(lhs).(type) {
	case *ast.StarExpr:
		if id, ok := ast.Unparen(target.X).(*ast.Ident); ok {
			if binding := idx.bindings[id.Name]; binding != nil {
				binding.escaped = true
			}
		}
	case *ast.SelectorExpr:
		if id, ok := ast.Unparen(target.X).(*ast.Ident); ok {
			if binding := idx.bindings[id.Name]; binding != nil {
				binding.escaped = true
			}
		}
	}
}

func (idx *bodyOriginIndex) addTargetWrite(target ast.Expr, value ast.Expr) {
	if id, ok := ast.Unparen(target).(*ast.Ident); ok {
		idx.addWrite(id.Name, value)
	}
}

func (idx *bodyOriginIndex) addWrite(name string, value ast.Expr) {
	if binding := idx.bindings[name]; binding != nil {
		binding.writes = append(binding.writes, value)
	}
}

func (idx *bodyOriginIndex) indexReadFileUses(body *ast.BlockStmt) {
	var stack []ast.Node
	ast.Inspect(body, func(node ast.Node) bool {
		if node == nil {
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			return false
		}
		if ident, ok := node.(*ast.Ident); ok {
			if binding := idx.bindings[ident.Name]; binding != nil && binding.readFileSource && !idx.readFileWriteTarget(ident, stack) && !idx.readFileStringConversion(ident, stack) {
				binding.readFileUsedElsewhere = true
			}
		}
		stack = append(stack, node)
		return true
	})
}

func (idx *bodyOriginIndex) readFileWriteTarget(ident *ast.Ident, parents []ast.Node) bool {
	if len(parents) == 0 {
		return false
	}
	switch parent := parents[len(parents)-1].(type) {
	case *ast.AssignStmt:
		for _, lhs := range parent.Lhs {
			if ast.Unparen(lhs) == ident {
				return true
			}
		}
	case *ast.ValueSpec:
		if slices.Contains(parent.Names, ident) {
			return true
		}
	case *ast.RangeStmt:
		return ast.Unparen(parent.Key) == ident || ast.Unparen(parent.Value) == ident
	}
	return false
}

func (idx *bodyOriginIndex) readFileStringConversion(ident *ast.Ident, parents []ast.Node) bool {
	if len(parents) == 0 || idx.nameIsDeclared("string") {
		return false
	}
	call, ok := parents[len(parents)-1].(*ast.CallExpr)
	if !ok || len(call.Args) != 1 || ast.Unparen(call.Args[0]) != ident {
		return false
	}
	name, ok := ast.Unparen(call.Fun).(*ast.Ident)
	return ok && name.Name == "string"
}

func (idx *bodyOriginIndex) recordBuilderCall(call *ast.CallExpr) {
	sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok {
		return
	}
	id, ok := ast.Unparen(sel.X).(*ast.Ident)
	if !ok {
		return
	}
	binding := idx.bindings[id.Name]
	if binding == nil || !binding.builder {
		return
	}
	switch sel.Sel.Name {
	case "String":
	case "WriteString", "WriteByte", "WriteRune":
		if len(call.Args) == 1 {
			binding.builderWrites = append(binding.builderWrites, call.Args[0])
		} else {
			binding.builderWrites = append(binding.builderWrites, nil)
		}
	default:
		binding.builderWrites = append(binding.builderWrites, nil)
	}
}

func (idx *bodyOriginIndex) isBuilderType(expr ast.Expr) bool {
	sel, ok := ast.Unparen(expr).(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "Builder" && idx.importedPackage(sel.X, idx.packages.strings)
}

func (idx *bodyOriginIndex) isBuilderLiteral(expr ast.Expr) bool {
	literal, ok := ast.Unparen(expr).(*ast.CompositeLit)
	return ok && idx.isBuilderType(literal.Type)
}

func isBodyScanCall(call *ast.CallExpr) bool {
	sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "Scan"
}

func (idx *bodyOriginIndex) isScanCall(call *ast.CallExpr) bool {
	return isBodyScanCall(call)
}

func (idx *bodyOriginIndex) shadowsStringsContains(call *ast.CallExpr) bool {
	if len(call.Args) != 2 {
		return false
	}
	sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Contains" {
		return false
	}
	id, ok := ast.Unparen(sel.X).(*ast.Ident)
	if !ok || id.Name != "strings" && !idx.packages.strings[id.Name] {
		return false
	}
	binding := idx.bindings[id.Name]
	return binding != nil && binding.declarations > 0 || idx.packageNames[id.Name]
}

func (idx *bodyOriginIndex) isNonBody(expr ast.Expr) bool {
	return idx.exprKnown(expr, make(map[string]bool))
}

func (idx *bodyOriginIndex) exprKnown(expr ast.Expr, stack map[string]bool) bool {
	switch node := ast.Unparen(expr).(type) {
	case *ast.BasicLit:
		return node.Kind == token.STRING
	case *ast.BinaryExpr:
		return node.Op == token.ADD && idx.exprKnown(node.X, stack) && idx.exprKnown(node.Y, stack)
	case *ast.Ident:
		if idx.outerNamesUnknown && !idx.dotImportLocalAt(node.Name, node.Pos()) {
			return false
		}
		return idx.bindingKnown(node.Name, stack)
	case *ast.CallExpr:
		if idx.isReadFile(node) {
			return true
		}
		if ident, ok := ast.Unparen(node.Fun).(*ast.Ident); ok && ident.Name == "string" && !idx.nameIsDeclared(ident.Name) && len(node.Args) == 1 {
			return idx.exprKnown(node.Args[0], stack)
		}
		if idx.isFmtSprint(node) {
			for _, argument := range node.Args {
				if !idx.fmtArgKnown(argument, stack) {
					return false
				}
			}
			return true
		}
		if sel, ok := ast.Unparen(node.Fun).(*ast.SelectorExpr); ok && sel.Sel.Name == "String" {
			if id, ok := ast.Unparen(sel.X).(*ast.Ident); ok {
				binding := idx.uniqueBinding(id.Name)
				return binding != nil && binding.builder && idx.bindingKnown(id.Name, stack)
			}
		}
	}
	return false
}

func (idx *bodyOriginIndex) bindingKnown(name string, stack map[string]bool) bool {
	binding := idx.uniqueBinding(name)
	if binding == nil || binding.escaped || binding.readFileUsedElsewhere || stack[name] {
		return false
	}
	if binding.state == 2 {
		return binding.known
	}
	if len(binding.writes) == 0 && !binding.scanned && !binding.builder && len(binding.builderWrites) == 0 {
		return false
	}
	binding.state = 1
	stack[name] = true
	known := true
	for _, value := range binding.writes {
		if value == nil || !idx.exprKnown(value, stack) {
			known = false
			break
		}
	}
	if known && binding.builder {
		for _, value := range binding.builderWrites {
			if value == nil || !idx.builderArgKnown(value, stack) {
				known = false
				break
			}
		}
	}
	binding.state = 2
	binding.known = known
	delete(stack, name)
	return known
}

func (idx *bodyOriginIndex) builderArgKnown(expr ast.Expr, stack map[string]bool) bool {
	if literal, ok := ast.Unparen(expr).(*ast.BasicLit); ok && (literal.Kind == token.INT || literal.Kind == token.CHAR) {
		return true
	}
	return idx.exprKnown(expr, stack)
}

func (idx *bodyOriginIndex) fmtArgKnown(expr ast.Expr, stack map[string]bool) bool {
	if literal, ok := ast.Unparen(expr).(*ast.BasicLit); ok && literal.Kind != token.STRING {
		return true
	}
	return idx.exprKnown(expr, stack)
}

func (idx *bodyOriginIndex) isReadFile(call *ast.CallExpr) bool {
	return idx.isPackageCall(call, idx.packages.os, "ReadFile") || idx.isPackageCall(call, idx.packages.ioutil, "ReadFile")
}

func (idx *bodyOriginIndex) isFmtSprint(call *ast.CallExpr) bool {
	sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	return ok && strings.HasPrefix(sel.Sel.Name, "Sprint") && idx.importedPackage(sel.X, idx.packages.fmt)
}

func (idx *bodyOriginIndex) isPackageCall(call *ast.CallExpr, packages map[string]bool, method string) bool {
	sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	return ok && sel.Sel.Name == method && idx.importedPackage(sel.X, packages)
}

func (idx *bodyOriginIndex) importedPackage(expr ast.Expr, packages map[string]bool) bool {
	id, ok := ast.Unparen(expr).(*ast.Ident)
	return ok && packages[id.Name] && !idx.nameIsDeclared(id.Name)
}

func sharedHasMarker(shared, marker string) bool {
	for start := 0; ; {
		i := strings.Index(shared[start:], marker)
		if i < 0 {
			return false
		}
		i += start
		beforeOK := i == 0 || !markerWord(shared[i-1])
		end := i + len(marker)
		afterOK := end == len(shared) || !markerWord(shared[end])
		if beforeOK && afterOK {
			return true
		}
		start = i + 1
		if start >= len(shared) {
			return false
		}
	}
}

func markerWord(ch byte) bool {
	return ch == '_' || ch == '-' || ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9'
}

// sharedTextAbove returns the shared page text of the test's directory tree.
func (r *UnfalsifiableTestCaseRule) sharedTextAbove(path string) string {
	dirs := make([]string, 0, len(r.sharedPageText))
	for dir := range r.sharedPageText {
		if strings.HasPrefix(path, dir+string(filepath.Separator)) {
			dirs = append(dirs, dir)
		}
	}
	sort.Strings(dirs)
	parts := make([]string, 0, len(dirs))
	for _, dir := range dirs {
		parts = append(parts, r.sharedPageText[dir])
	}
	return strings.Join(parts, "\n")
}
