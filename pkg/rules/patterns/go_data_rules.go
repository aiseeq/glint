package patterns

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"reflect"
	"regexp"
	"slices"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewStringPrefixSliceUnguardedRule())
	rules.Register(NewJSONTagShadowsEmbeddedFieldRule())
	rules.Register(NewEnumComparedToForeignLiteralRule())
	rules.Register(NewHostSuffixWithoutDotRule())
	rules.Register(NewJSONBuiltByFormatRule())
	rules.Register(NewSQLQuoteEscapedByHandRule())
	rules.Register(NewSQLMetricLiteralZeroRule())
}

// goConstantString returns the value of a constant string expression: with
// type information any constant, without it a string literal.
func goConstantString(expr ast.Expr, info *types.Info) (string, bool) {
	expr = ast.Unparen(expr)
	if info != nil {
		if tv, ok := info.Types[expr]; ok && tv.Value != nil {
			if tv.Value.Kind() != constant.String {
				return "", false
			}
			return constant.StringVal(tv.Value), true
		}
	}
	lit, ok := expr.(*ast.BasicLit)
	if !ok {
		return "", false
	}
	return goStringLiteral(lit)
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
	return rules.AnalyzeGoFiles(ctx, r.Name(), func(fileCtx *core.FileContext, info *types.Info) []*core.Violation {
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
		violations = jsReport(violations, r.BaseRule, ctx, ctx.LineFor(slice),
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
		if value, ok := constantInt(info, expr); ok {
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
		format, ok := goStringLiteral(lit)
		if !ok {
			return false
		}
		verbs := printfVerb.FindAllStringSubmatch(strings.ReplaceAll(format, "%%", ""), -1)
		for j, rest := range call.Args[i+1:] {
			if rest == slice {
				return j < len(verbs) && (verbs[j][1] == "s" || verbs[j][1] == "q")
			}
		}
		return false
	}
	return false
}

// printfVerb is a printf verb with its letter; %% is removed before.
var printfVerb = regexp.MustCompile(`%[-+# 0-9.]*([a-zA-Z])`)

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
	return rules.AnalyzeTypedFiles(ctx, r.Name(), r.analyze)
}

func (r *JSONTagShadowsEmbeddedFieldRule) analyze(ctx *core.FileContext, info *types.Info) []*core.Violation {
	var violations []*core.Violation
	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		spec, ok := n.(*ast.TypeSpec)
		if !ok {
			return true
		}
		structType, ok := declaredStructOf(spec, info)
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
			violations = jsReport(violations, r.BaseRule, ctx, ctx.LineForPos(field.Pos()),
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

// declaredStructOf returns the checked struct behind a type declaration.
func declaredStructOf(spec *ast.TypeSpec, info *types.Info) (*types.Struct, bool) {
	obj, ok := info.Defs[spec.Name].(*types.TypeName)
	if !ok {
		return nil, false
	}
	structType, ok := obj.Type().Underlying().(*types.Struct)
	return structType, ok
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
	*rules.BaseRule
}

// NewEnumComparedToForeignLiteralRule creates the rule
func NewEnumComparedToForeignLiteralRule() *EnumComparedToForeignLiteralRule {
	return &EnumComparedToForeignLiteralRule{BaseRule: rules.NewBaseRule(
		"enum-compared-to-foreign-literal",
		"patterns",
		"Detects a value of a string enum type compared with a literal that none of the type's constants holds — a status from another set",
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
	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(fileCtx *core.FileContext, info *types.Info) []*core.Violation {
		return r.analyze(fileCtx, info, enums)
	})
}

// enumLiteral is a literal that can be an enum value: a word, not the empty
// "unset" check or a wildcard.
var enumLiteral = regexp.MustCompile(`^[A-Za-z][\w.-]*$`)

func (r *EnumComparedToForeignLiteralRule) analyze(ctx *core.FileContext, info *types.Info, enums enumIndex) []*core.Violation {
	var violations []*core.Violation
	check := func(enumSide, literal ast.Expr) {
		text, ok := goConstantString(literal, info)
		if !ok || !enumLiteral.MatchString(text) {
			return
		}
		named, set := enums.lookup(enumSide, info)
		if named == nil || set[text] {
			return
		}
		violations = jsReport(violations, r.BaseRule, ctx, ctx.LineFor(literal),
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
	if call, ok := expr.(*ast.CallExpr); ok && len(call.Args) == 1 {
		if tv, ok := info.Types[call.Fun]; ok && tv.IsType() {
			expr = ast.Unparen(call.Args[0])
		}
	}
	named, ok := types.Unalias(info.TypeOf(expr)).(*types.Named)
	if !ok || !e.own[named.Obj().Pkg()] {
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
	return rules.AnalyzeGoFiles(ctx, r.Name(), r.analyze)
}

func (r *HostSuffixWithoutDotRule) analyze(ctx *core.FileContext, info *types.Info) []*core.Violation {
	if !productionGoFile(ctx) {
		return nil
	}
	lists := rangedLists(ctx.GoAST, info)
	var violations []*core.Violation
	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 2 || !isPackageFuncCall(ctx.GoAST, info, call, "strings", "HasSuffix") {
			return true
		}
		value, suffix := call.Args[0], ast.Unparen(call.Args[1])
		if !missingDot(value, suffix, info, lists) {
			return true
		}
		violations = jsReport(violations, r.BaseRule, ctx, ctx.LineFor(call),
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
			text, ok := goConstantString(elt, info)
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
	if text, ok := goConstantString(suffix, info); ok {
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
		if text, ok := goConstantString(left, info); ok && domainBoundary(text) {
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
	return rules.AnalyzeGoFiles(ctx, r.Name(), r.analyze)
}

func (r *JSONBuiltByFormatRule) analyze(ctx *core.FileContext, info *types.Info) []*core.Violation {
	if !productionGoFile(ctx) {
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
		case isPackageFuncCall(ctx.GoAST, info, call, "fmt", "Sprintf", "Printf"):
		case isPackageFuncCall(ctx.GoAST, info, call, "fmt", "Fprintf", "Appendf"):
			index = 1
		default:
			return true
		}
		if len(call.Args) <= index {
			return true
		}
		format, ok := goConstantString(call.Args[index], info)
		if !ok || !formatJSONObject.MatchString(format) || !formatQuotedValue.MatchString(format) {
			return true
		}
		violations = jsReport(violations, r.BaseRule, ctx, ctx.LineFor(call),
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
// driver's quoting (pq.QuoteLiteral).
type SQLQuoteEscapedByHandRule struct {
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
	return rules.AnalyzeGoFiles(ctx, r.Name(), r.analyze)
}

// sqlDriverImports are the packages through which Go code runs queries with
// bind parameters.
var sqlDriverImports = []string{"database/sql", "github.com/jmoiron/sqlx", "github.com/jackc/pgx", "gorm.io/gorm"}

// usesSQLDriver reports a project importing a SQL driver or database/sql.
func usesSQLDriver(ctx *core.GoProjectContext) bool {
	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil {
			continue
		}
		for path := range pkg.Package.Imports {
			for _, driver := range sqlDriverImports {
				if path == driver || strings.HasPrefix(path, driver+"/") {
					return true
				}
			}
		}
	}
	return false
}

func (r *SQLQuoteEscapedByHandRule) analyze(ctx *core.FileContext, info *types.Info) []*core.Violation {
	if !productionGoFile(ctx) {
		return nil
	}
	quotePair := func(from, to ast.Expr) bool {
		old, ok := goConstantString(from, info)
		if !ok || old != "'" {
			return false
		}
		replacement, ok := goConstantString(to, info)
		return ok && replacement == "''"
	}
	var violations []*core.Violation
	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		escapes := false
		switch {
		case isPackageFuncCall(ctx.GoAST, info, call, "strings", "ReplaceAll", "Replace"):
			escapes = len(call.Args) >= 3 && quotePair(call.Args[1], call.Args[2])
		case isPackageFuncCall(ctx.GoAST, info, call, "strings", "NewReplacer"):
			for i := 0; i+1 < len(call.Args); i += 2 {
				escapes = escapes || quotePair(call.Args[i], call.Args[i+1])
			}
		}
		if escapes {
			violations = jsReport(violations, r.BaseRule, ctx, ctx.LineFor(call),
				"SQL quotes doubled by hand — the value is pasted into the query text, other metacharacters pass and the injection checks do not see it",
				"Pass the value as a bind parameter ($1); where a literal is unavoidable use the driver's quoting (pq.QuoteLiteral)")
		}
		return true
	})
	return violations
}

// SQLMetricLiteralZeroRule detects a money metric answered by a literal zero
// in a SELECT list:
//
//	SELECT COALESCE(SUM(amount), 0) AS total_value, 0 AS total_return FROM investments
//
// The column the metric was computed from went away and the query keeps
// answering: every client reads a real-looking zero return. A UNION branch
// that fills a column the other branch has is left out.
type SQLMetricLiteralZeroRule struct {
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

var (
	sqlSelectWord   = regexp.MustCompile(`(?i)\bSELECT\b`)
	sqlUnionWord    = regexp.MustCompile(`(?i)\bUNION\b`)
	sqlZeroAsColumn = regexp.MustCompile(`(?i)(?:\bSELECT|,)\s*0(?:\.0+)?(?:\s*::\s*[a-z]+(?:\s*\([\d,\s]+\))?)?\s+AS\s+"?([a-z_][a-z0-9_]*)`)
	sqlMetricWords  = []string{"return", "returns", "profit", "yield", "value", "balance", "amount", "pnl", "gain", "earnings", "income", "revenue", "fee", "fees", "interest"}
)

// AnalyzeGoProject checks the production files.
func (r *SQLMetricLiteralZeroRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	return rules.AnalyzeGoFiles(ctx, r.Name(), r.analyze)
}

func (r *SQLMetricLiteralZeroRule) analyze(ctx *core.FileContext, _ *types.Info) []*core.Violation {
	if !productionGoFile(ctx) {
		return nil
	}
	var violations []*core.Violation
	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok {
			return true
		}
		query, ok := goStringLiteral(lit)
		if !ok || !sqlSelectWord.MatchString(query) || sqlUnionWord.MatchString(query) {
			return true
		}
		for _, loc := range sqlZeroAsColumn.FindAllStringSubmatchIndex(query, -1) {
			column := strings.ToLower(query[loc[2]:loc[3]])
			if !slices.ContainsFunc(helpers.IdentifierWords(column), func(w string) bool { return slices.Contains(sqlMetricWords, w) }) {
				continue
			}
			line := ctx.LineFor(lit) + strings.Count(query[:loc[2]], "\n")
			violations = jsReport(violations, r.BaseRule, ctx, line,
				"Metric "+column+" is selected as a literal 0 — clients read a zero as the real value",
				"Compute the metric from the data, or drop the field from the response until it can be computed")
		}
		return true
	})
	return violations
}
