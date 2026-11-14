package gorules

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"maps"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
)

func init() {
	rules.Register(NewStringPrefixSliceUnguardedRule())
	rules.Register(NewJSONTagShadowsEmbeddedFieldRule())
	rules.Register(NewEnumComparedToForeignLiteralRule())
	rules.Register(NewHostSuffixWithoutDotRule())
	rules.Register(NewJSONBuiltByFormatRule())
	rules.Register(NewSQLQuoteEscapedByHandRule())
	rules.Register(NewSQLMetricLiteralZeroRule())
	rules.Register(NewTestLiteralsMatchedInProdRule())
}

// TestLiteralsMatchedInProdRule detects boolean classifiers whose literal
// values are passed directly from tests in the same package.
type TestLiteralsMatchedInProdRule struct {
	rules.GoFileFindingRule
	*rules.BaseRule
}

// NewTestLiteralsMatchedInProdRule creates the test literal comparison rule.
func NewTestLiteralsMatchedInProdRule() *TestLiteralsMatchedInProdRule {
	return &TestLiteralsMatchedInProdRule{BaseRule: rules.NewBaseRule(
		"test-literals-matched-in-prod",
		"patterns",
		"Detects boolean classifiers whose string literals are passed directly by package tests",
		core.SeverityMedium,
	)}
}

// AnalyzeFile has no findings; the rule compares tests with production code.
func (r *TestLiteralsMatchedInProdRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that this rule needs no SSA data.
func (r *TestLiteralsMatchedInProdRule) RequiresSSA() bool { return false }

type testLiteralPackage struct {
	name string
	dir  string
}

type matchedLiteralSet struct {
	values map[string]bool
	nodes  map[token.Pos]bool
	fn     *ast.FuncDecl
	file   *core.FileContext
}

// AnalyzeGoProject compares classifier literals with same-package test inputs.
func (r *TestLiteralsMatchedInProdRule) AnalyzeGoProject(project *core.GoProjectContext) ([]*core.Violation, error) {
	tests := make(map[testLiteralPackage]map[string]map[string]bool)
	production := make(map[testLiteralPackage][]*core.FileContext)
	for _, file := range project.Files {
		if file == nil || file.GoAST == nil || !file.IsGoFile() {
			continue
		}
		key := testLiteralPackage{name: file.GoAST.Name.Name, dir: filepath.Dir(file.RelPath)}
		if file.IsTestFile() {
			if strings.HasSuffix(file.GoAST.Name.Name, "_test") {
				continue
			}
			functionInputs := tests[key]
			if functionInputs == nil {
				functionInputs = make(map[string]map[string]bool)
				tests[key] = functionInputs
			}
			for name, values := range testClassifierInputs(file.GoAST) {
				if functionInputs[name] == nil {
					functionInputs[name] = make(map[string]bool)
				}
				for value := range values {
					functionInputs[name][value] = true
				}
			}
		} else {
			production[key] = append(production[key], file)
		}
	}

	var violations []*core.Violation
	keys := slices.SortedFunc(maps.Keys(production), func(a, b testLiteralPackage) int {
		if order := strings.Compare(a.name, b.name); order != 0 {
			return order
		}
		return strings.Compare(a.dir, b.dir)
	})
	for _, key := range keys {
		files := production[key]
		testValues := tests[key]
		if len(testValues) == 0 {
			continue
		}
		var sets []matchedLiteralSet
		for _, file := range files {
			sets = append(sets, collectTestLiteralSets(file)...)
		}
		if len(sets) == 0 {
			continue
		}
		literalIndex := productionLiteralIndex(files)
		reported := make(map[token.Pos]bool)
		for _, set := range sets {
			file, fn := set.file, set.fn
			matches := 0
			for value := range set.values {
				if testValues[fn.Name.Name][value] {
					matches++
				}
			}
			if matches < 3 || hasProductionLiteralSet(literalIndex, set) ||
				file == nil || fn == nil || !project.IsReportFile(file) || hasSpecReference(fn) || reported[fn.Pos()] {
				continue
			}
			line := file.LineFor(fn)
			if file.IsSuppressed(line, r.Name()) {
				continue
			}
			v := r.CreateViolation(file.RelPath, line,
				"Package tests pass these same string literals directly to this boolean classifier — its behavior may be fitted to examples instead of implementing the general rule")
			v.WithCode(strings.TrimSpace(file.GetLine(line)))
			v.WithSuggestion("Implement the general rule, or move the domain dictionary to a shared declaration with its specification or source")
			violations = append(violations, v)
			reported[fn.Pos()] = true
		}
	}
	return violations, nil
}

// testClassifierInputs records string values passed to a classifier directly
// from a test, including values ranged from a literal slice or test table.
func testClassifierInputs(file *ast.File) map[string]map[string]bool {
	inputs := make(map[string]map[string]bool)
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && fn.Body != nil && isTestFunction(fn.Name.Name) {
			collectTestFunctionInputs(fn, inputs)
		}
	}
	return inputs
}

type testRangeSource struct {
	variable *ast.Ident
	body     *ast.BlockStmt
	source   *ast.CompositeLit
}

func collectTestFunctionInputs(fn *ast.FuncDecl, inputs map[string]map[string]bool) {
	sources := testCompositeSources(fn.Body)
	ranges := testRangeSources(fn.Body, sources)
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		name := calledFunctionName(call.Fun)
		if name == "" {
			return true
		}
		for _, arg := range call.Args {
			values := testArgumentLiterals(arg, sourceForTestArgument(arg, ranges))
			addTestInputValues(inputs, name, values)
		}
		return true
	})
}

func testCompositeSources(body *ast.BlockStmt) map[string]*ast.CompositeLit {
	sources := make(map[string]*ast.CompositeLit)
	ast.Inspect(body, func(node ast.Node) bool {
		switch n := node.(type) {
		case *ast.ValueSpec:
			for i, value := range n.Values {
				if i < len(n.Names) {
					addCompositeSource(sources, n.Names[i].Name, value)
				}
			}
		case *ast.AssignStmt:
			for i, value := range n.Rhs {
				if i < len(n.Lhs) {
					id, ok := ast.Unparen(n.Lhs[i]).(*ast.Ident)
					if ok {
						addCompositeSource(sources, id.Name, value)
					}
				}
			}
		}
		return true
	})
	return sources
}

func addCompositeSource(sources map[string]*ast.CompositeLit, name string, value ast.Expr) {
	if lit, ok := ast.Unparen(value).(*ast.CompositeLit); ok {
		sources[name] = lit
	}
}

func testRangeSources(body *ast.BlockStmt, sources map[string]*ast.CompositeLit) []testRangeSource {
	var ranges []testRangeSource
	ast.Inspect(body, func(node ast.Node) bool {
		rangeStmt, ok := node.(*ast.RangeStmt)
		if !ok {
			return true
		}
		if source := rangeCompositeSource(rangeStmt, sources); source != nil {
			variable := rangeIterationVariable(rangeStmt)
			if variable != nil {
				ranges = append(ranges, testRangeSource{variable: variable, body: rangeStmt.Body, source: source})
			}
		}
		return true
	})
	return ranges
}

func rangeIterationVariable(rangeStmt *ast.RangeStmt) *ast.Ident {
	if variable, ok := ast.Unparen(rangeStmt.Value).(*ast.Ident); ok {
		return variable
	}
	variable, _ := ast.Unparen(rangeStmt.Key).(*ast.Ident)
	return variable
}

func rangeCompositeSource(rangeStmt *ast.RangeStmt, sources map[string]*ast.CompositeLit) *ast.CompositeLit {
	if source, ok := ast.Unparen(rangeStmt.X).(*ast.CompositeLit); ok {
		return source
	}
	id, ok := ast.Unparen(rangeStmt.X).(*ast.Ident)
	if !ok {
		return nil
	}
	return sources[id.Name]
}

func sourceForTestArgument(arg ast.Expr, ranges []testRangeSource) map[string]*ast.CompositeLit {
	variable := testArgumentRangeVariable(arg)
	if variable == nil {
		return nil
	}
	selected := innermostRangeSource(variable, ranges)
	if selected == nil {
		return nil
	}
	return map[string]*ast.CompositeLit{variable.Name: selected.source}
}

func testArgumentRangeVariable(arg ast.Expr) *ast.Ident {
	switch value := ast.Unparen(arg).(type) {
	case *ast.Ident:
		return value
	case *ast.SelectorExpr:
		variable, _ := ast.Unparen(value.X).(*ast.Ident)
		return variable
	default:
		return nil
	}
}

func innermostRangeSource(variable *ast.Ident, ranges []testRangeSource) *testRangeSource {
	var selected *testRangeSource
	for i := range ranges {
		candidate := &ranges[i]
		if candidate.variable.Name != variable.Name || candidate.body == nil ||
			variable.Pos() < candidate.body.Pos() || variable.Pos() > candidate.body.End() {
			continue
		}
		if selected == nil || rangeBodySize(candidate) < rangeBodySize(selected) {
			selected = candidate
		}
	}
	return selected
}

func rangeBodySize(source *testRangeSource) token.Pos {
	return source.body.End() - source.body.Pos()
}

func addTestInputValues(inputs map[string]map[string]bool, function string, values map[string]bool) {
	for value := range values {
		if inputs[function] == nil {
			inputs[function] = make(map[string]bool)
		}
		inputs[function][value] = true
	}
}

func isTestFunction(name string) bool {
	return strings.HasPrefix(name, "Test") || strings.HasPrefix(name, "Benchmark") ||
		strings.HasPrefix(name, "Example") || strings.HasPrefix(name, "Fuzz")
}

func calledFunctionName(expr ast.Expr) string {
	switch callee := ast.Unparen(expr).(type) {
	case *ast.Ident:
		return callee.Name
	case *ast.SelectorExpr:
		return callee.Sel.Name
	default:
		return ""
	}
}

func testArgumentLiterals(arg ast.Expr, ranges map[string]*ast.CompositeLit) map[string]bool {
	switch value := ast.Unparen(arg).(type) {
	case *ast.BasicLit:
		if value.Kind == token.STRING {
			if text, err := strconv.Unquote(value.Value); err == nil {
				return map[string]bool{text: true}
			}
		}
	case *ast.Ident:
		if source := ranges[value.Name]; source != nil {
			return compositeStringValues(source)
		}
	case *ast.SelectorExpr:
		if variable, ok := ast.Unparen(value.X).(*ast.Ident); ok {
			if source := ranges[variable.Name]; source != nil {
				return compositeStructFieldValues(source, value.Sel.Name)
			}
		}
	}
	return nil
}

func compositeStringValues(source *ast.CompositeLit) map[string]bool {
	values := make(map[string]bool)
	if array, ok := ast.Unparen(source.Type).(*ast.ArrayType); ok {
		if element, ok := ast.Unparen(array.Elt).(*ast.Ident); !ok || element.Name != "string" {
			return values
		}
	}
	for _, expr := range source.Elts {
		lit, ok := ast.Unparen(expr).(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			continue
		}
		if value, err := strconv.Unquote(lit.Value); err == nil {
			values[value] = true
		}
	}
	return values
}

func compositeStructFieldValues(source *ast.CompositeLit, fieldName string) map[string]bool {
	array, ok := ast.Unparen(source.Type).(*ast.ArrayType)
	if !ok {
		return nil
	}
	structType, ok := ast.Unparen(array.Elt).(*ast.StructType)
	if !ok {
		return nil
	}
	fieldIndex := -1
	index := 0
	for _, field := range structType.Fields.List {
		if len(field.Names) == 0 {
			index++
			continue
		}
		for _, name := range field.Names {
			if name.Name == fieldName {
				fieldIndex = index
			}
			index++
		}
	}
	if fieldIndex < 0 {
		return nil
	}
	values := make(map[string]bool)
	for _, element := range source.Elts {
		var value ast.Expr
		if keyed, ok := ast.Unparen(element).(*ast.CompositeLit); ok {
			element = keyed
		}
		if keyed, ok := element.(*ast.KeyValueExpr); ok {
			key, isName := ast.Unparen(keyed.Key).(*ast.Ident)
			if !isName || key.Name != fieldName {
				continue
			}
			value = keyed.Value
		} else if row, ok := ast.Unparen(element).(*ast.CompositeLit); ok && fieldIndex < len(row.Elts) {
			value = row.Elts[fieldIndex]
		} else {
			continue
		}
		lit, ok := ast.Unparen(value).(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			continue
		}
		if text, err := strconv.Unquote(lit.Value); err == nil {
			values[text] = true
		}
	}
	return values
}

func uniformBoolSwitchLiterals(sw *ast.SwitchStmt) []*ast.BasicLit {
	var literals []*ast.BasicLit
	answer := ""
	for _, stmt := range sw.Body.List {
		clause, ok := stmt.(*ast.CaseClause)
		if !ok || len(clause.List) == 0 {
			continue
		}
		caseStrings := stringLiterals(clause.List)
		if len(caseStrings) == 0 {
			continue
		}
		if len(clause.Body) != 1 {
			return nil
		}
		ret, ok := clause.Body[0].(*ast.ReturnStmt)
		if !ok || len(ret.Results) != 1 {
			return nil
		}
		result, ok := ast.Unparen(ret.Results[0]).(*ast.Ident)
		if !ok || (result.Name != "true" && result.Name != "false") {
			return nil
		}
		if answer != "" && answer != result.Name {
			return nil
		}
		answer = result.Name
		literals = append(literals, caseStrings...)
	}
	if len(literals) < 3 {
		return nil
	}
	return literals
}

func collectTestLiteralSets(file *core.FileContext) []matchedLiteralSet {
	var found []matchedLiteralSet
	mapsByName := mapLiteralSets(file.GoAST)
	for _, decl := range file.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok {
			found = append(found, collectFunctionLiteralSets(file, fn, mapsByName)...)
		}
	}
	return found
}

func collectFunctionLiteralSets(file *core.FileContext, fn *ast.FuncDecl, mapsByName map[string]matchedLiteralSet) []matchedLiteralSet {
	if fn.Body == nil || !isBooleanFunction(fn) {
		return nil
	}
	params := stringParameterNames(fn)
	if len(params) == 0 {
		return nil
	}
	var sets []matchedLiteralSet
	add := func(values []*ast.BasicLit) {
		set := matchedLiteralSet{values: make(map[string]bool), nodes: make(map[token.Pos]bool)}
		for _, lit := range values {
			value, ok := patternkit.GoStringLiteral(lit)
			if ok {
				set.values[value] = true
				set.nodes[lit.Pos()] = true
			}
		}
		if len(set.values) >= 3 {
			sets = append(sets, set)
		}
	}
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		collectFunctionLiteralNode(node, params, mapsByName, &sets, add)
		return true
	})
	for i := range sets {
		sets[i].fn = fn
		sets[i].file = file
	}
	return sets
}

func collectFunctionLiteralNode(node ast.Node, params []string, mapsByName map[string]matchedLiteralSet, sets *[]matchedLiteralSet, add func([]*ast.BasicLit)) {
	switch n := node.(type) {
	case *ast.SwitchStmt:
		tag, ok := ast.Unparen(n.Tag).(*ast.Ident)
		if ok && slices.Contains(params, tag.Name) {
			add(uniformBoolSwitchLiterals(n))
		}
	case *ast.ValueSpec:
		for i, value := range n.Values {
			if i < len(n.Names) {
				if lit, ok := ast.Unparen(value).(*ast.CompositeLit); ok {
					addFunctionMap(mapsByName, n.Names[i].Name, lit)
				}
			}
		}
	case *ast.AssignStmt:
		for i, value := range n.Rhs {
			if i < len(n.Lhs) {
				id, ok := ast.Unparen(n.Lhs[i]).(*ast.Ident)
				lit, litOK := ast.Unparen(value).(*ast.CompositeLit)
				if ok && litOK {
					addFunctionMap(mapsByName, id.Name, lit)
				}
			}
		}
	case *ast.IndexExpr:
		name, nameOK := ast.Unparen(n.X).(*ast.Ident)
		input, inputOK := ast.Unparen(n.Index).(*ast.Ident)
		if nameOK && inputOK && slices.Contains(params, input.Name) {
			if set, exists := mapsByName[name.Name]; exists {
				*sets = append(*sets, set)
			}
		}
	case *ast.CallExpr:
		sel, ok := ast.Unparen(n.Fun).(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Contains" || len(n.Args) != 2 {
			return
		}
		input, ok := ast.Unparen(n.Args[1]).(*ast.Ident)
		if !ok || !slices.Contains(params, input.Name) {
			return
		}
		lit, ok := ast.Unparen(n.Args[0]).(*ast.CompositeLit)
		if ok {
			add(stringLiterals(lit.Elts))
		}
	}
}

func mapLiteralSets(file *ast.File) map[string]matchedLiteralSet {
	mapsByName := make(map[string]matchedLiteralSet)
	addMap := func(name string, lit *ast.CompositeLit) {
		if set, ok := stringMapLiteralSet(lit); ok {
			mapsByName[name] = set
		}
	}
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.VAR {
			continue
		}
		for _, spec := range gen.Specs {
			valueSpec, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, value := range valueSpec.Values {
				if i < len(valueSpec.Names) {
					if lit, ok := ast.Unparen(value).(*ast.CompositeLit); ok {
						addMap(valueSpec.Names[i].Name, lit)
					}
				}
			}
		}
	}
	return mapsByName
}

func addFunctionMap(mapsByName map[string]matchedLiteralSet, name string, lit *ast.CompositeLit) {
	if set, ok := stringMapLiteralSet(lit); ok {
		mapsByName[name] = set
	}
}

func stringMapLiteralSet(lit *ast.CompositeLit) (matchedLiteralSet, bool) {
	if _, ok := lit.Type.(*ast.MapType); !ok {
		return matchedLiteralSet{}, false
	}
	set := matchedLiteralSet{values: make(map[string]bool), nodes: make(map[token.Pos]bool)}
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := ast.Unparen(kv.Key).(*ast.BasicLit)
		if !ok || key.Kind != token.STRING {
			continue
		}
		value, err := strconv.Unquote(key.Value)
		if err == nil {
			set.values[value] = true
			set.nodes[key.Pos()] = true
		}
	}
	return set, len(set.values) >= 3
}

func stringLiterals(exprs []ast.Expr) []*ast.BasicLit {
	var literals []*ast.BasicLit
	for _, expr := range exprs {
		lit, ok := ast.Unparen(expr).(*ast.BasicLit)
		if ok && lit.Kind == token.STRING {
			literals = append(literals, lit)
		}
	}
	return literals
}

func isBooleanFunction(fn *ast.FuncDecl) bool {
	if fn.Type.Results == nil || len(fn.Type.Results.List) == 0 {
		return false
	}
	last := fn.Type.Results.List[len(fn.Type.Results.List)-1]
	id, ok := ast.Unparen(last.Type).(*ast.Ident)
	return ok && id.Name == "bool"
}

func stringParameterNames(fn *ast.FuncDecl) []string {
	var params []string
	if fn.Type.Params == nil {
		return params
	}
	for _, field := range fn.Type.Params.List {
		id, ok := ast.Unparen(field.Type).(*ast.Ident)
		if !ok || id.Name != "string" {
			continue
		}
		for _, name := range field.Names {
			params = append(params, name.Name)
		}
	}
	return params
}

func productionLiteralIndex(files []*core.FileContext) map[string][]token.Pos {
	index := make(map[string][]token.Pos)
	for _, file := range files {
		ast.Inspect(file.GoAST, func(node ast.Node) bool {
			lit, ok := node.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			value, ok := patternkit.GoStringLiteral(lit)
			if ok {
				index[value] = append(index[value], lit.Pos())
			}
			return true
		})
	}
	return index
}

func hasProductionLiteralSet(index map[string][]token.Pos, candidate matchedLiteralSet) bool {
	repeated := 0
	for value := range candidate.values {
		for _, pos := range index[value] {
			inCandidate := candidate.fn != nil && pos >= candidate.fn.Pos() && pos < candidate.fn.End()
			if !candidate.nodes[pos] && !inCandidate {
				repeated++
				break
			}
		}
		if repeated >= 3 {
			return true
		}
	}
	return false
}

func hasSpecReference(fn *ast.FuncDecl) bool {
	if fn.Doc == nil {
		return false
	}
	text := strings.ToLower(fn.Doc.Text())
	return strings.Contains(text, "spec") || strings.Contains(text, "rfc") ||
		strings.Contains(text, "protocol") || strings.Contains(text, "http://") || strings.Contains(text, "https://")
}

// StringPrefixSliceUnguardedRule detects a prefix cut from a string of
// unknown length with a constant bound and no length check:
//
//	adminID := fmt.Sprintf("admin-%s", claims.Email[:8])
//
// A value shorter than the bound panics with "slice bounds out of range": a
// short e-mail turns the request into a 500, a short secret breaks the test
// helper that only wanted to print it. Only values whose length the outside
// decides are judged - parameters, fields, environment variables - and names
// of values fixed-length by construction (a commit sha, a digest, a uuid) are
// left out. Without type information (test files) only a slice printed with
// %s is judged.
type StringPrefixSliceUnguardedRule struct {
	rules.GoFileFindingRule
	*rules.BaseRule
}

// NewStringPrefixSliceUnguardedRule creates the rule
func NewStringPrefixSliceUnguardedRule() *StringPrefixSliceUnguardedRule {
	return &StringPrefixSliceUnguardedRule{BaseRule: rules.NewBaseRule(
		"string-prefix-slice-unguarded",
		"patterns",
		"Detects s[:N] on a string of unknown length with no len(s) check — a shorter value panics with slice bounds out of range",
		core.SeverityMedium,
	)}
}

// AnalyzeFile is a no-op: the project analysis checks every file.
func (r *StringPrefixSliceUnguardedRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *StringPrefixSliceUnguardedRule) RequiresSSA() bool { return false }

// AnalyzeGoProject checks every file, tests included: a test helper that
// panics on a short value fails for a reason unrelated to the test.
func (r *StringPrefixSliceUnguardedRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	return rules.AnalyzeGoRunFiles(ctx, r.Name(), func(fileCtx *core.FileContext, info *types.Info) []*core.Violation {
		if !fileCtx.IsGoFile() || !fileCtx.HasGoAST() {
			return nil
		}
		var violations []*core.Violation
		for _, decl := range fileCtx.GoAST.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil {
				violations = append(violations, r.checkFunction(fileCtx, fn, info)...)
			}
		}
		return violations
	})
}

// fixedLengthWords name values that are fixed-length by construction: a
// commit id, a digest, a uuid.
var fixedLengthWords = []string{"sha", "commit", "head", "digest", "rev", "uuid", "guid"}

// outsideValues returns the identifiers of the function whose length the
// outside decides: its parameters, and locals read from the environment or
// copied from a field. A local computed in the function (a word of
// strings.Fields, a call's result) is left out: its length is the
// function's own business.
func outsideValues(fn *ast.FuncDecl) map[string]bool {
	names := make(map[string]bool)
	for _, field := range fn.Type.Params.List {
		for _, name := range field.Names {
			names[name.Name] = true
		}
	}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Rhs) != 1 {
			return true
		}
		id, ok := assign.Lhs[0].(*ast.Ident)
		if !ok {
			return true
		}
		switch rhs := ast.Unparen(assign.Rhs[0]).(type) {
		case *ast.SelectorExpr:
			names[id.Name] = true
		case *ast.CallExpr:
			if text := types.ExprString(rhs.Fun); text == "os.Getenv" || text == "os.LookupEnv" {
				names[id.Name] = true
			}
		}
		return true
	})
	return names
}

// outsideString reports a cut value whose length comes from outside the
// function: a field, or an outside identifier.
func outsideString(target ast.Expr, outside map[string]bool) bool {
	switch t := target.(type) {
	case *ast.Ident:
		if !outside[t.Name] {
			return false
		}
	case *ast.SelectorExpr:
	default:
		return false
	}
	name := types.ExprString(target)
	if dot := strings.LastIndex(name, "."); dot >= 0 {
		name = name[dot+1:]
	}
	return !slices.ContainsFunc(helpers.IdentifierWords(name), func(w string) bool { return slices.Contains(fixedLengthWords, w) })
}

func (r *StringPrefixSliceUnguardedRule) checkFunction(ctx *core.FileContext, fn *ast.FuncDecl, info *types.Info) []*core.Violation {
	// guarded holds where each expression's length is first taken: a check
	// after the cut does not protect it.
	guarded := make(map[string]token.Pos)
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "len" && len(call.Args) == 1 {
				text := types.ExprString(ast.Unparen(call.Args[0]))
				if _, seen := guarded[text]; !seen {
					guarded[text] = call.Pos()
				}
			}
		}
		return true
	})
	outside := outsideValues(fn)

	var parents map[ast.Node]ast.Node
	if info == nil {
		parents = helpers.ParentMap(fn.Body)
	}
	var violations []*core.Violation
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		slice, ok := n.(*ast.SliceExpr)
		if !ok || slice.Slice3 || slice.High == nil || !zeroOrMissing(slice.Low, info) {
			return true
		}
		// A one-letter cut (capitalizing a word) usually follows an
		// emptiness check this rule does not follow.
		if bound, ok := literalInt(slice.High, info); !ok || bound < 2 {
			return true
		}
		target := ast.Unparen(slice.X)
		if !outsideString(target, outside) {
			return true
		}
		text := types.ExprString(target)
		if pos, ok := guarded[text]; ok && pos < slice.Pos() {
			return true
		}
		if info != nil {
			if !unknownLengthString(target, info) {
				return true
			}
		} else if !printedArgument(slice, parents) {
			return true
		}
		violations = patternkit.JsReport(violations, r.BaseRule, ctx, ctx.LineFor(slice),
			"'"+text+"' is cut to a fixed length with no length check — a shorter value panics with slice bounds out of range",
			"Check len("+text+") first, or cut with a helper that stops at the end of the string")
		return true
	})
	return violations
}

// zeroOrMissing reports a slice low bound that is absent or the constant 0.
func zeroOrMissing(low ast.Expr, info *types.Info) bool {
	if low == nil {
		return true
	}
	value, ok := literalInt(low, info)
	return ok && value == 0
}

// literalInt returns the value of an integer constant expression: with type
// information any constant, without it an integer literal.
func literalInt(expr ast.Expr, info *types.Info) (int64, bool) {
	expr = ast.Unparen(expr)
	if info != nil {
		if value, ok := patternkit.ConstantInt(info, expr); ok {
			return value, true
		}
	}
	lit, ok := expr.(*ast.BasicLit)
	if !ok || lit.Kind != token.INT {
		return 0, false
	}
	return constant.Int64Val(constant.MakeFromLiteral(lit.Value, token.INT, 0))
}

// unknownLengthString reports a non-constant expression of a string type.
func unknownLengthString(expr ast.Expr, info *types.Info) bool {
	tv, ok := info.Types[expr]
	if !ok || tv.Value != nil || tv.Type == nil {
		return false
	}
	basic, ok := tv.Type.Underlying().(*types.Basic)
	return ok && basic.Info()&types.IsString != 0
}

// printedArgument reports a slice printed by a format call with %s or %q:
// without types, that is what says the slice is text.
func printedArgument(slice *ast.SliceExpr, parents map[ast.Node]ast.Node) bool {
	call, ok := parents[slice].(*ast.CallExpr)
	if !ok {
		return false
	}
	for i, arg := range call.Args {
		if arg == slice {
			return false
		}
		lit, ok := arg.(*ast.BasicLit)
		if !ok {
			continue
		}
		format, ok := patternkit.GoStringLiteral(lit)
		if !ok {
			return false
		}
		verbs := patternkit.PrintfVerb.FindAllStringSubmatch(strings.ReplaceAll(format, "%%", ""), -1)
		for j, rest := range call.Args[i+1:] {
			if rest == slice {
				return j < len(verbs) && (verbs[j][1] == "s" || verbs[j][1] == "q")
			}
		}
		return false
	}
	return false
}

// JSONTagShadowsEmbeddedFieldRule detects a field that takes the JSON name of
// a field promoted from an embedded struct:
//
//	type Investment struct {
//	    StrategyName string `json:"strategy"`
//	}
//	type InvestmentDetails struct {
//	    Investment
//	    Strategy interface{} `json:"strategy,omitempty"` // placeholder
//	}
//
// encoding/json keeps the shallower field of a name and drops the deeper one,
// so the details response carries the placeholder (or, with omitempty and a
// nil value, nothing) instead of the strategy. A field of the same Go name is
// a deliberate override and is left out.
type JSONTagShadowsEmbeddedFieldRule struct {
	rules.GoFileFindingRule
	*rules.BaseRule
}

// NewJSONTagShadowsEmbeddedFieldRule creates the rule
func NewJSONTagShadowsEmbeddedFieldRule() *JSONTagShadowsEmbeddedFieldRule {
	return &JSONTagShadowsEmbeddedFieldRule{BaseRule: rules.NewBaseRule(
		"json-tag-shadows-embedded-field",
		"patterns",
		"Detects a struct field whose JSON name is the name of a differently named field of an embedded struct — encoding/json drops the embedded one",
		core.SeverityHigh,
	)}
}

// AnalyzeFile is a no-op: the project analysis checks every file.
func (r *JSONTagShadowsEmbeddedFieldRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *JSONTagShadowsEmbeddedFieldRule) RequiresSSA() bool { return false }

// AnalyzeGoProject checks the struct declarations of the analyzed packages.
func (r *JSONTagShadowsEmbeddedFieldRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	return rules.AnalyzeTypedRunFiles(ctx, r.Name(), r.analyze)
}

func (r *JSONTagShadowsEmbeddedFieldRule) analyze(ctx *core.FileContext, info *types.Info) []*core.Violation {
	var violations []*core.Violation
	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		spec, ok := n.(*ast.TypeSpec)
		if !ok {
			return true
		}
		structType, ok := helpers.DeclaredStructType(spec, info)
		if !ok {
			return true
		}
		promoted := make(map[string]promotedJSONField)
		for i := 0; i < structType.NumFields(); i++ {
			field := structType.Field(i)
			if field.Embedded() {
				if _, named := jsonKey(structType.Tag(i), field.Name()); !named {
					collectPromotedJSON(field.Type(), promoted, 0)
				}
			}
		}
		if len(promoted) == 0 {
			return true
		}
		for i := 0; i < structType.NumFields(); i++ {
			field := structType.Field(i)
			if field.Embedded() || !field.Exported() {
				continue
			}
			key, _ := jsonKey(structType.Tag(i), field.Name())
			deeper, ok := promoted[key]
			if key == "" || !ok || deeper.goName == field.Name() {
				continue
			}
			violations = patternkit.JsReport(violations, r.BaseRule, ctx, ctx.LineForPos(field.Pos()),
				"JSON name \""+key+"\" of "+spec.Name.Name+"."+field.Name()+" is also the name of embedded "+deeper.owner+"."+deeper.goName+
					" — encoding/json writes only the outer field, the embedded value never reaches the client",
				"Give one of the fields another JSON name, or drop the outer field and fill the embedded one")
		}
		return true
	})
	return violations
}

// promotedJSONField is a field an embedded struct contributes to the JSON of
// the outer one.
type promotedJSONField struct {
	owner  string
	goName string
}

// jsonKey returns the JSON name of a field: the tag's name, else the Go name;
// "" for a field the encoder skips. named reports a name given by the tag.
func jsonKey(tag, goName string) (key string, named bool) {
	value, ok := reflect.StructTag(tag).Lookup("json")
	if !ok {
		return goName, false
	}
	name, _, _ := strings.Cut(value, ",")
	switch name {
	case "-":
		return "", true
	case "":
		return goName, false
	}
	return name, true
}

// collectPromotedJSON adds the JSON names an embedded type contributes,
// following its own untagged embedded structs a few levels down.
func collectPromotedJSON(t types.Type, into map[string]promotedJSONField, depth int) {
	if depth > 3 {
		return
	}
	if ptr, ok := t.(*types.Pointer); ok {
		t = ptr.Elem()
	}
	named, ok := types.Unalias(t).(*types.Named)
	if !ok {
		return
	}
	structType, ok := named.Underlying().(*types.Struct)
	if !ok {
		return
	}
	for i := 0; i < structType.NumFields(); i++ {
		field := structType.Field(i)
		if field.Embedded() {
			if _, tagged := jsonKey(structType.Tag(i), field.Name()); !tagged {
				collectPromotedJSON(field.Type(), into, depth+1)
				continue
			}
		}
		if !field.Exported() {
			continue
		}
		key, _ := jsonKey(structType.Tag(i), field.Name())
		if _, seen := into[key]; key != "" && !seen {
			into[key] = promotedJSONField{owner: named.Obj().Name(), goName: field.Name()}
		}
	}
}

// EnumComparedToForeignLiteralRule detects a value of a string enum type
// compared with a string none of the type's constants holds:
//
//	if state != StatePendingApproval && string(state) != "pending" { ... }
//
// The literal is a status of another set; the two sets drift apart and the
// compiler, which would reject a constant of the wrong type, sees a plain
// string. A type without declared constants is not an enum and is left out.
type EnumComparedToForeignLiteralRule struct {
	rules.GoFileFindingRule
	*rules.BaseRule
}

// NewEnumComparedToForeignLiteralRule creates the rule
func NewEnumComparedToForeignLiteralRule() *EnumComparedToForeignLiteralRule {
	return &EnumComparedToForeignLiteralRule{BaseRule: rules.NewBaseRule(
		"enum-compared-to-foreign-literal",
		"patterns",
		"Detects a value of a string enum type compared with a literal that none of the type's constants holds — a status from another set — and such a literal a template passes to a FuncMap function that converts it to the type",
		core.SeverityHigh,
	)}
}

// AnalyzeFile is a no-op: the project analysis checks every file.
func (r *EnumComparedToForeignLiteralRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *EnumComparedToForeignLiteralRule) RequiresSSA() bool { return false }

// AnalyzeGoProject checks the comparisons of the analyzed packages.
func (r *EnumComparedToForeignLiteralRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	enums := enumIndex{own: make(map[*types.Package]bool), values: make(map[*types.Named]map[string]bool)}
	for _, pkg := range ctx.Packages {
		if pkg != nil && pkg.Package != nil && pkg.Package.Types != nil {
			enums.own[pkg.Package.Types] = true
		}
	}
	violations, err := rules.AnalyzeTypedFiles(ctx, r.Name(), func(fileCtx *core.FileContext, info *types.Info) []*core.Violation {
		return r.analyze(fileCtx, info, enums)
	})
	if err != nil {
		return nil, err
	}
	inTemplates, err := r.templateForeignLiterals(ctx, enums)
	if err != nil {
		return nil, fmt.Errorf("%s: templates: %w", r.Name(), err)
	}
	return append(violations, inTemplates...), nil
}

// enumLiteral is a literal that can be an enum value: a word, not the empty
// "unset" check or a wildcard.
var enumLiteral = regexp.MustCompile(`^[A-Za-z][\w.-]*$`)

func (r *EnumComparedToForeignLiteralRule) analyze(ctx *core.FileContext, info *types.Info, enums enumIndex) []*core.Violation {
	var violations []*core.Violation
	check := func(enumSide, literal ast.Expr) {
		text, ok := patternkit.GoConstantString(literal, info)
		if !ok || !enumLiteral.MatchString(text) {
			return
		}
		named, set := enums.lookup(enumSide, info)
		if named == nil || set[text] {
			return
		}
		violations = patternkit.JsReport(violations, r.BaseRule, ctx, ctx.LineFor(literal),
			"\""+text+"\" is not a value of "+named.Obj().Name()+" — the comparison checks a status of another set and can never match a declared one",
			"Compare with a constant of "+named.Obj().Name()+", or declare the value there if the state really exists")
	}
	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.BinaryExpr:
			if node.Op == token.EQL || node.Op == token.NEQ {
				check(node.X, node.Y)
				check(node.Y, node.X)
			}
		case *ast.SwitchStmt:
			if node.Tag == nil {
				return true
			}
			for _, stmt := range node.Body.List {
				if clause, ok := stmt.(*ast.CaseClause); ok {
					for _, expr := range clause.List {
						check(node.Tag, expr)
					}
				}
			}
		}
		return true
	})
	return violations
}

// enumIndex holds the project's packages and the declared values of the
// string enum types seen so far.
type enumIndex struct {
	own    map[*types.Package]bool
	values map[*types.Named]map[string]bool
}

// lookup returns the string enum type of expr — seen through a string()
// conversion — and the values of its declared constants; nil when expr is
// not of a named string type of the project with constants. A library's
// type (a driver's error code) is compared with the codes its documentation
// lists and is left out.
func (e enumIndex) lookup(expr ast.Expr, info *types.Info) (*types.Named, map[string]bool) {
	expr = ast.Unparen(expr)
	if tv, ok := info.Types[expr]; !ok || tv.Value != nil {
		return nil, nil
	}
	named, ok := types.Unalias(info.TypeOf(patternkit.WithoutConversion(info, expr))).(*types.Named)
	if !ok {
		return nil, nil
	}
	return e.enumValues(named)
}

// enumValues returns a named string type of the project and the values of
// its declared constants; nil for any other type or one without constants.
func (e enumIndex) enumValues(named *types.Named) (*types.Named, map[string]bool) {
	if !e.own[named.Obj().Pkg()] {
		return nil, nil
	}
	if basic, ok := named.Underlying().(*types.Basic); !ok || basic.Info()&types.IsString == 0 {
		return nil, nil
	}
	set, seen := e.values[named]
	if !seen {
		set = make(map[string]bool)
		scope := named.Obj().Pkg().Scope()
		for _, name := range scope.Names() {
			c, ok := scope.Lookup(name).(*types.Const)
			if ok && types.Identical(c.Type(), named) && c.Val().Kind() == constant.String {
				set[constant.StringVal(c.Val())] = true
			}
		}
		e.values[named] = set
	}
	if len(set) == 0 {
		return nil, nil
	}
	return named, set
}

// HostSuffixWithoutDotRule detects a host checked against a domain by suffix
// without the dot boundary:
//
//	if !strings.HasSuffix(host, baseDomain) { reject }
//
// evilexample.com ends with example.com: an attacker's domain passes the
// check. Compare host == domain || strings.HasSuffix(host, "."+domain).
type HostSuffixWithoutDotRule struct {
	rules.GoFileFindingRule
	*rules.BaseRule
}

// NewHostSuffixWithoutDotRule creates the rule
func NewHostSuffixWithoutDotRule() *HostSuffixWithoutDotRule {
	return &HostSuffixWithoutDotRule{BaseRule: rules.NewBaseRule(
		"host-suffix-without-dot",
		"security",
		"Detects strings.HasSuffix(host, domain) without a leading dot — evilexample.com passes a check for example.com",
		core.SeverityHigh,
	)}
}

// AnalyzeFile is a no-op: the project analysis checks every file.
func (r *HostSuffixWithoutDotRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *HostSuffixWithoutDotRule) RequiresSSA() bool { return false }

var (
	hostWords     = []string{"host", "hostname", "domain", "origin"}
	domainLiteral = regexp.MustCompile(`^[a-z0-9-]+(?:\.[a-z0-9-]+)+$`)
)

// AnalyzeGoProject checks the production files.
func (r *HostSuffixWithoutDotRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	return rules.AnalyzeGoRunFiles(ctx, r.Name(), r.analyze)
}

func (r *HostSuffixWithoutDotRule) analyze(ctx *core.FileContext, info *types.Info) []*core.Violation {
	if !patternkit.ProductionGoFile(ctx) {
		return nil
	}
	lists := rangedLists(ctx.GoAST, info)
	var violations []*core.Violation
	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 2 || !patternkit.IsPackageFuncCall(ctx.GoAST, info, call, "strings", "HasSuffix") {
			return true
		}
		value, suffix := call.Args[0], ast.Unparen(call.Args[1])
		if !missingDot(value, suffix, info, lists) {
			return true
		}
		violations = patternkit.JsReport(violations, r.BaseRule, ctx, ctx.LineFor(call),
			"Host matched by suffix without the dot — a domain that merely ends with the same letters (evil"+strings.Trim(types.ExprString(suffix), "\"")+") passes",
			"Accept host == domain || strings.HasSuffix(host, \".\"+domain)")
		return true
	})
	return violations
}

// domainBoundary reports a suffix that starts at a label or an address
// boundary: ".example.com", "@example.com".
func domainBoundary(text string) bool {
	return strings.HasPrefix(text, ".") || strings.HasPrefix(text, "@")
}

// rangedList is the loop variable of a range over a list of constants, and
// the constants.
type rangedList struct {
	name       string
	start, end token.Pos
	values     []string
}

// rangedLists returns the range loops of the file whose value variable walks
// a list literal of string constants, written in place or held in a variable
// of the file.
func rangedLists(file *ast.File, info *types.Info) []rangedList {
	literals := make(map[string]*ast.CompositeLit)
	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.ValueSpec:
			for i, name := range node.Names {
				if i < len(node.Values) {
					if lit, ok := ast.Unparen(node.Values[i]).(*ast.CompositeLit); ok {
						literals[name.Name] = lit
					}
				}
			}
		case *ast.AssignStmt:
			for i, lhs := range node.Lhs {
				id, ok := lhs.(*ast.Ident)
				if ok && i < len(node.Rhs) {
					if lit, ok := ast.Unparen(node.Rhs[i]).(*ast.CompositeLit); ok {
						literals[id.Name] = lit
					}
				}
			}
		}
		return true
	})
	var lists []rangedList
	ast.Inspect(file, func(n ast.Node) bool {
		loop, ok := n.(*ast.RangeStmt)
		if !ok {
			return true
		}
		value, ok := loop.Value.(*ast.Ident)
		if !ok {
			return true
		}
		lit, ok := ast.Unparen(loop.X).(*ast.CompositeLit)
		if id, isIdent := ast.Unparen(loop.X).(*ast.Ident); isIdent {
			lit, ok = literals[id.Name]
		}
		if !ok {
			return true
		}
		list := rangedList{name: value.Name, start: loop.Body.Pos(), end: loop.Body.End()}
		for _, elt := range lit.Elts {
			text, ok := patternkit.GoConstantString(elt, info)
			if !ok {
				return true
			}
			list.values = append(list.values, text)
		}
		lists = append(lists, list)
		return true
	})
	return lists
}

// missingDot reports a suffix that is a domain and does not start at a dot.
func missingDot(value, suffix ast.Expr, info *types.Info, lists []rangedList) bool {
	if text, ok := patternkit.GoConstantString(suffix, info); ok {
		return !domainBoundary(text) && domainLiteral.MatchString(text) && hostNamed(value)
	}
	if id, ok := suffix.(*ast.Ident); ok {
		for _, list := range lists {
			if list.name == id.Name && list.start <= id.Pos() && id.Pos() < list.end {
				return slices.ContainsFunc(list.values, func(text string) bool {
					return !domainBoundary(text) && domainLiteral.MatchString(text)
				}) && (hostNamed(value) || hostNamed(suffix))
			}
		}
	}
	if sum, ok := suffix.(*ast.BinaryExpr); ok && sum.Op == token.ADD {
		left := sum.X
		for {
			inner, ok := ast.Unparen(left).(*ast.BinaryExpr)
			if !ok || inner.Op != token.ADD {
				break
			}
			left = inner.X
		}
		if text, ok := patternkit.GoConstantString(left, info); ok && domainBoundary(text) {
			return false
		}
	}
	return hostNamed(suffix)
}

// hostNamed reports an expression whose names speak of a host or a domain.
func hostNamed(expr ast.Expr) bool {
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		id, ok := n.(*ast.Ident)
		if !ok || found {
			return !found
		}
		for _, word := range helpers.IdentifierWords(id.Name) {
			if slices.Contains(hostWords, word) {
				found = true
			}
		}
		return true
	})
	return found
}

// JSONBuiltByFormatRule detects JSON written by a format string with a string
// verb inside the quotes:
//
//	fmt.Fprintf(w, "data: {\"status\":\"connected\",\"userId\":\"%s\"}\n\n", userID)
//
// The value is not escaped: a quote or a newline in it breaks the document (an
// SSE frame ends at the newline) or adds fields. Marshal the value instead.
type JSONBuiltByFormatRule struct {
	rules.GoFileFindingRule
	*rules.BaseRule
}

// NewJSONBuiltByFormatRule creates the rule
func NewJSONBuiltByFormatRule() *JSONBuiltByFormatRule {
	return &JSONBuiltByFormatRule{BaseRule: rules.NewBaseRule(
		"json-built-by-format",
		"patterns",
		"Detects JSON built by fmt with %s or %v inside quotes — the value is not escaped, a quote or a newline breaks the document",
		core.SeverityMedium,
	)}
}

// AnalyzeFile is a no-op: the project analysis checks every file.
func (r *JSONBuiltByFormatRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *JSONBuiltByFormatRule) RequiresSSA() bool { return false }

var (
	formatJSONObject  = regexp.MustCompile(`\{\s*"[\w.-]+"\s*:`)
	formatQuotedValue = regexp.MustCompile(`:\s*"[^"]*%[-+# 0-9.]*[sv]`)
)

// AnalyzeGoProject checks the production files.
func (r *JSONBuiltByFormatRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	return rules.AnalyzeGoRunFiles(ctx, r.Name(), r.analyze)
}

func (r *JSONBuiltByFormatRule) analyze(ctx *core.FileContext, info *types.Info) []*core.Violation {
	if !patternkit.ProductionGoFile(ctx) {
		return nil
	}
	var violations []*core.Violation
	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		index := 0
		switch {
		case patternkit.IsPackageFuncCall(ctx.GoAST, info, call, "fmt", "Sprintf", "Printf"):
		case patternkit.IsPackageFuncCall(ctx.GoAST, info, call, "fmt", "Fprintf", "Appendf"):
			index = 1
		default:
			return true
		}
		if len(call.Args) <= index {
			return true
		}
		format, ok := patternkit.GoConstantString(call.Args[index], info)
		if !ok || !formatJSONObject.MatchString(format) || !formatQuotedValue.MatchString(format) {
			return true
		}
		violations = patternkit.JsReport(violations, r.BaseRule, ctx, ctx.LineFor(call),
			"JSON built by a format string — the value in quotes is not escaped, a quote or a newline in it breaks the document",
			"Build a struct or a map and encode it with json.Marshal")
		return true
	})
	return violations
}

// SQLQuoteEscapedByHandRule detects SQL quoting done by doubling quotes:
//
//	func escapeSQLLiteral(s string) string { return strings.ReplaceAll(s, "'", "''") }
//
// The value is pasted into the SQL text: backslashes and LIKE wildcards pass,
// and the query built around it is invisible to the injection checks. Pass
// the value as a bind parameter; where a literal is unavoidable, use the
// driver's quoting (pq.QuoteLiteral). Doubling a quote is the escape of other
// texts too (a sheet name in a spreadsheet range), so only an escaped value
// that reaches SQL text is reported (see escapedSQLFlow).
type SQLQuoteEscapedByHandRule struct {
	rules.GoFileFindingRule
	*rules.BaseRule
}

// NewSQLQuoteEscapedByHandRule creates the rule
func NewSQLQuoteEscapedByHandRule() *SQLQuoteEscapedByHandRule {
	return &SQLQuoteEscapedByHandRule{BaseRule: rules.NewBaseRule(
		"sql-quote-escaped-by-hand",
		"security",
		"Detects SQL quotes doubled by hand (strings.ReplaceAll(s, \"'\", \"''\")) in place of bind parameters",
		core.SeverityHigh,
	)}
}

// AnalyzeFile is a no-op: the project analysis checks every file.
func (r *SQLQuoteEscapedByHandRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *SQLQuoteEscapedByHandRule) RequiresSSA() bool { return false }

// AnalyzeGoProject checks the production files of a project that talks to
// its database through a driver: there a bind parameter is at hand. A tool
// that only hands SQL text to the psql command has no parameters to use.
func (r *SQLQuoteEscapedByHandRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if !usesSQLDriver(ctx) {
		return nil, nil
	}
	decls, err := patternkit.FuncDeclsByObject(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", r.Name(), err)
	}
	callers, err := patternkit.FuncCallSites(ctx, decls)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", r.Name(), err)
	}
	return rules.AnalyzeTypedRunFiles(ctx, r.Name(), func(file *core.FileContext, info *types.Info) []*core.Violation {
		return r.analyze(file, info, decls, callers)
	})
}

// usesSQLDriver reports a project importing a SQL driver or database/sql.
func usesSQLDriver(ctx *core.GoProjectContext) bool {
	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil {
			continue
		}
		for path := range pkg.Package.Imports {
			if patternkit.SqlDriverPackage(path) {
				return true
			}
		}
	}
	return false
}

func (r *SQLQuoteEscapedByHandRule) analyze(ctx *core.FileContext, info *types.Info, decls map[*types.Func]patternkit.TypedFuncDecl, callers map[*types.Func][]patternkit.FuncCallSite) []*core.Violation {
	if !patternkit.ProductionGoFile(ctx) {
		return nil
	}
	quotePair := func(from, to ast.Expr) bool {
		old, ok := patternkit.GoConstantString(from, info)
		if !ok || old != "'" {
			return false
		}
		replacement, ok := patternkit.GoConstantString(to, info)
		return ok && replacement == "''"
	}
	escapes := func(call *ast.CallExpr) bool {
		switch {
		case patternkit.IsPackageFuncCall(ctx.GoAST, info, call, "strings", "ReplaceAll", "Replace"):
			return len(call.Args) >= 3 && quotePair(call.Args[1], call.Args[2])
		case patternkit.IsPackageFuncCall(ctx.GoAST, info, call, "strings", "NewReplacer"):
			for i := 0; i+1 < len(call.Args); i += 2 {
				if quotePair(call.Args[i], call.Args[i+1]) {
					return true
				}
			}
		}
		return false
	}
	flow := patternkit.NewEscapedSQLFlow(decls, callers)
	var violations []*core.Violation
	report := func(call *ast.CallExpr) {
		violations = patternkit.JsReport(violations, r.BaseRule, ctx, ctx.LineFor(call),
			"SQL quotes doubled by hand — the value is pasted into the query text, other metacharacters pass and the injection checks do not see it",
			"Pass the value as a bind parameter ($1); where a literal is unavoidable use the driver's quoting (pq.QuoteLiteral)")
	}
	for _, decl := range ctx.GoAST.Decls {
		switch decl := decl.(type) {
		case *ast.FuncDecl:
			if decl.Body == nil {
				continue
			}
			fn := patternkit.TypedFuncDecl{Decl: decl, Info: info}
			ast.Inspect(decl.Body, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok && escapes(call) && flow.ValueReaches(fn, call) {
					report(call)
				}
				return true
			})
		case *ast.GenDecl:
			for _, spec := range decl.Specs {
				value, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, expr := range value.Values {
					ast.Inspect(expr, func(n ast.Node) bool {
						if call, ok := n.(*ast.CallExpr); ok && escapes(call) && i < len(value.Names) && flow.VariableReaches(info, info.Defs[value.Names[i]]) {
							report(call)
						}
						return true
					})
				}
			}
		}
	}
	return violations
}

// SQLMetricLiteralZeroRule detects a money metric answered by a literal zero
// in a SELECT list:
//
//	SELECT COALESCE(SUM(amount), 0) AS total_value, 0 AS total_return FROM investments
//
// The column the metric was computed from went away and the query keeps
// answering: every client reads a real-looking zero return. A UNION branch
// that fills a column the other branch has is left out. The Go form is a
// money local that stays at its zero and still enters a calculation:
//
//	totalLiabilities := models.MoneyZero()
//	nav := gav.Sub(totalLiabilities)
type SQLMetricLiteralZeroRule struct {
	rules.GoFileFindingRule
	*rules.BaseRule
}

// NewSQLMetricLiteralZeroRule creates the rule
func NewSQLMetricLiteralZeroRule() *SQLMetricLiteralZeroRule {
	return &SQLMetricLiteralZeroRule{BaseRule: rules.NewBaseRule(
		"sql-metric-literal-zero",
		"patterns",
		"Detects a money metric selected as a literal 0 (0 AS total_return) — the API reports a zero instead of the value",
		core.SeverityMedium,
	)}
}

// AnalyzeFile is a no-op: the project analysis checks every file.
func (r *SQLMetricLiteralZeroRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *SQLMetricLiteralZeroRule) RequiresSSA() bool { return false }

// AnalyzeGoProject checks the production files.
func (r *SQLMetricLiteralZeroRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	return rules.AnalyzeGoRunFiles(ctx, r.Name(), r.analyze)
}

func (r *SQLMetricLiteralZeroRule) analyze(ctx *core.FileContext, info *types.Info) []*core.Violation {
	if !patternkit.ProductionGoFile(ctx) {
		return nil
	}
	var violations []*core.Violation
	for _, local := range patternkit.ZeroMetricPlaceholders(ctx.GoAST, info) {
		violations = patternkit.JsReport(violations, r.BaseRule, ctx, ctx.LineFor(local),
			"Metric "+local.Name+" stays at its zero and still enters the calculation — the result is stored as if the amount had been computed",
			"Compute the amount, or leave the field out until it can be computed")
	}
	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok {
			return true
		}
		query, ok := patternkit.GoStringLiteral(lit)
		if !ok || !patternkit.SqlSelectWord.MatchString(query) || patternkit.SqlUnionWord.MatchString(query) {
			return true
		}
		for _, loc := range patternkit.SqlZeroAsColumn.FindAllStringSubmatchIndex(query, -1) {
			column := strings.ToLower(query[loc[2]:loc[3]])
			if !slices.ContainsFunc(helpers.IdentifierWords(column), func(w string) bool { return slices.Contains(patternkit.SqlMetricWords, w) }) {
				continue
			}
			line := ctx.LineFor(lit) + strings.Count(query[:loc[2]], "\n")
			violations = patternkit.JsReport(violations, r.BaseRule, ctx, line,
				"Metric "+column+" is selected as a literal 0 — clients read a zero as the real value",
				"Compute the metric from the data, or drop the field from the response until it can be computed")
		}
		return true
	})
	return violations
}
