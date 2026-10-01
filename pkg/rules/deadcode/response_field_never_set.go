package deadcode

import (
	"errors"
	"fmt"
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
	rules.Register(NewResponseFieldNeverSetRule())
}

// ResponseFieldNeverSetRule detects a JSON field of a struct that the code
// builds, whose other fields it fills, but that nothing ever sets:
//
//	type Dashboard struct {
//		TotalDeposits    SafeDecimal `json:"totalDeposits"`
//		TotalWithdrawals SafeDecimal `json:"totalWithdrawals"`   // never assigned
//	}
//
//	return Dashboard{TotalDeposits: deposits}
//
// Every response carries the zero value, and the screen shows zero
// withdrawals or a blank client number - with no error anywhere. A struct a
// decoder fills (json.Unmarshal) is input and left alone. For a struct handed
// by pointer to an interface parameter or a generic one (sqlx Select/Get,
// Scan, a copier, jwt claims, a decode[T] helper), a
// field with a db tag counts as set when some string of the code names the
// column or some query selects every column, and a field without one counts
// as set. A struct converted from
// another struct (View(src)) is filled by the conversion. Input types - a
// …Request, …Filter, …Params, …Claims, …Config - are left to unused-field and
// unused-config-field. never-assigned-field
// covers the nil-able fields the code reads; this rule covers the values the
// code only sends out.
type ResponseFieldNeverSetRule struct {
	*rules.BaseRule
}

// NewResponseFieldNeverSetRule creates the rule
func NewResponseFieldNeverSetRule() *ResponseFieldNeverSetRule {
	return &ResponseFieldNeverSetRule{
		BaseRule: rules.NewBaseRule(
			"response-field-never-set",
			"deadcode",
			"Detects a JSON field of a struct the code builds that nothing ever sets while its other fields are set — the struct always goes out with the zero value",
			core.SeverityMedium,
		),
	}
}

// AnalyzeFile is a no-op: the writers of a field may live in any file.
func (r *ResponseFieldNeverSetRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *ResponseFieldNeverSetRule) RequiresSSA() bool { return false }

// fillSources are the ways a struct is filled other than field by field.
type fillSources struct {
	// converted holds the structs a conversion from another struct builds.
	converted map[*types.Named]bool
	// reflected holds the structs handed by pointer to an interface parameter
	// or to a generic one.
	reflected map[*types.Named]bool
	// words holds the identifier-shaped words of the code's string constants:
	// the columns and aliases its queries name.
	words map[string]bool
	// allColumns holds the structs handed to a call together with a query
	// selecting every column (SELECT *): each column its tags name is filled.
	allColumns map[*types.Named]bool
	// selectAllVars holds the variables initialized with such a query.
	selectAllVars map[*types.Var]bool
	// throughSubfield holds the struct-valued fields filled through their own
	// fields (s.Dates.Start = first fills s.Dates).
	throughSubfield map[token.Pos]bool
}

// AnalyzeGoProject reports the JSON fields of built structs that nothing sets.
func (r *ResponseFieldNeverSetRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, errors.New("response field never set: nil Go project context")
	}
	access, err := projectFieldAccess(ctx)
	if err != nil {
		return nil, fmt.Errorf("response field never set: %w", err)
	}
	mentions, err := projectMentions(ctx)
	if err != nil {
		return nil, fmt.Errorf("response field never set: %w", err)
	}
	sources := collectFillSources(ctx)

	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(fileCtx *core.FileContext, info *types.Info) []*core.Violation {
		var violations []*core.Violation
		ast.Inspect(fileCtx.GoAST, func(n ast.Node) bool {
			spec, ok := n.(*ast.TypeSpec)
			if !ok {
				return true
			}
			structType, ok := spec.Type.(*ast.StructType)
			if !ok || structType.Fields == nil {
				return true
			}
			named, ok := declaredNamedType(spec, info)
			if !ok || inputTypeName(spec.Name.Name) || access.decoded[named] || sources.converted[named] {
				return true
			}
			fields := r.jsonFields(structType, info)
			set := func(f jsonField) bool {
				pos := f.obj.Pos()
				if access.written[pos] || sources.throughSubfield[pos] {
					return true
				}
				if !sources.reflected[named] {
					return false
				}
				return f.column == "" || sources.allColumns[named] || sources.words[f.column]
			}
			built := false
			for _, f := range fields {
				built = built || set(f)
			}
			if !built {
				return true // nothing builds the struct: another rule's business
			}
			for _, f := range fields {
				if set(f) || mentions.mentioned(fileCtx, f.obj.Name()) {
					continue
				}
				line := fileCtx.LineFor(f.ident)
				v := r.CreateViolation(fileCtx.RelPath, line, fmt.Sprintf(
					"Field %s.%s (json %q) is never set while the struct's other fields are — wherever the struct is sent, it carries the zero value",
					spec.Name.Name, f.obj.Name(), f.json))
				v.WithCode(strings.TrimSpace(fileCtx.GetLine(line)))
				v.WithSuggestion(fmt.Sprintf("Fill %s where the other fields are filled (a literal key, a query column), or remove it from the contract", f.obj.Name()))
				v.WithContext("pattern", "response_field_never_set")
				violations = append(violations, v)
			}
			return true
		})
		return violations
	})
}

// selectEveryColumn matches a query selecting every column of a table.
var selectEveryColumn = regexp.MustCompile(`(?is)\bselect\s+(?:[a-z_][a-z0-9_]*\.)?\*\s+from\s+[a-z_"]`)

// inputTypeSuffixes name the structs that carry input - a request, a filter,
// token claims, settings: unused-field and unused-config-field judge those.
var inputTypeSuffixes = []string{"Request", "Req", "Filter", "Filters", "Criteria", "Params", "Query", "Input", "Claims", "Config", "Options", "Opts", "Settings"}

func inputTypeName(name string) bool { return hasAnySuffix(name, inputTypeSuffixes) }

// jsonField is an exported field with an explicit json name.
type jsonField struct {
	obj    *types.Var
	ident  *ast.Ident
	json   string
	column string // the db tag's column, "" without one
}

func (r *ResponseFieldNeverSetRule) jsonFields(structType *ast.StructType, info *types.Info) []jsonField {
	var fields []jsonField
	for _, field := range structType.Fields.List {
		if field.Tag == nil || len(field.Names) == 0 {
			continue
		}
		tag := reflect.StructTag(strings.Trim(field.Tag.Value, "`"))
		jsonTag, ok := tag.Lookup("json")
		name := strings.Split(jsonTag, ",")[0]
		if !ok || name == "-" || name == "" {
			continue
		}
		column := strings.Split(tag.Get("db"), ",")[0]
		if column == "-" {
			column = ""
		}
		for _, ident := range field.Names {
			if !ident.IsExported() {
				continue
			}
			if obj, ok := info.Defs[ident].(*types.Var); ok {
				fields = append(fields, jsonField{obj: obj, ident: ident, json: name, column: column})
			}
		}
	}
	return fields
}

// collectFillSources walks every loaded package once for the conversions,
// the reflection calls and the string constants.
func collectFillSources(ctx *core.GoProjectContext) fillSources {
	sources := fillSources{
		converted:       make(map[*types.Named]bool),
		reflected:       make(map[*types.Named]bool),
		allColumns:      make(map[*types.Named]bool),
		selectAllVars:   make(map[*types.Var]bool),
		words:           make(map[string]bool),
		throughSubfield: make(map[token.Pos]bool),
	}
	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil || pkg.Package.TypesInfo == nil {
			continue
		}
		info := pkg.Package.TypesInfo
		for _, file := range pkg.Package.Syntax {
			ast.Inspect(file, func(n ast.Node) bool {
				switch node := n.(type) {
				case *ast.BasicLit:
					if node.Kind == token.STRING {
						if value, ok := info.Types[node]; ok && value.Value != nil && value.Value.Kind() == constant.String {
							collectIdentifierWords(constant.StringVal(value.Value), sources.words)
						}
					}
				case *ast.CallExpr:
					sources.call(node, info)
				case *ast.AssignStmt:
					for i, lhs := range node.Lhs {
						sources.subfieldWrite(lhs, info)
						if len(node.Lhs) == len(node.Rhs) {
							sources.queryVar(lhs, node.Rhs[i], info)
						}
					}
				case *ast.IncDecStmt:
					sources.subfieldWrite(node.X, info)
				case *ast.UnaryExpr:
					if node.Op == token.AND {
						sources.subfieldWrite(node.X, info)
					}
				}
				return true
			})
		}
	}
	return sources
}

// subfieldWrite marks the fields a write goes through: in s.Dates.Start the
// value of s.Dates is filled.
func (s fillSources) subfieldWrite(target ast.Expr, info *types.Info) {
	sel, ok := ast.Unparen(target).(*ast.SelectorExpr)
	if !ok {
		return
	}
	for {
		inner, ok := ast.Unparen(sel.X).(*ast.SelectorExpr)
		if !ok {
			return
		}
		if pos, isField := selectedField(info, inner); isField {
			s.throughSubfield[pos] = true
		}
		sel = inner
	}
}

// call records a conversion between structs and the struct pointers handed to
// untyped parameters.
func (s fillSources) call(call *ast.CallExpr, info *types.Info) {
	// s.Window.Fill(...) with a pointer receiver fills s.Window.
	if sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr); ok {
		if selection, ok := info.Selections[sel]; ok && selection.Kind() == types.MethodVal {
			if signature, ok := selection.Obj().Type().(*types.Signature); ok && signature.Recv() != nil {
				if _, pointer := signature.Recv().Type().(*types.Pointer); pointer {
					s.subfieldWrite(&ast.SelectorExpr{X: sel.X, Sel: sel.Sel}, info)
				}
			}
		}
	}
	if tv, ok := info.Types[call.Fun]; ok && tv.IsType() {
		if len(call.Args) == 1 {
			if _, fromStruct := structUnder(info.TypeOf(call.Args[0])); fromStruct {
				addReachableStructs(s.converted, tv.Type)
			}
		}
		return
	}
	// The declared signature, not the instantiated one: a parameter *T of a
	// generic decoder is filled by reflection whatever T becomes.
	signature, ok := types.Unalias(info.TypeOf(call.Fun)).(*types.Signature)
	if fn := calledFunc(call, info); fn != nil {
		if slices.Contains(helpers.EncodeFuncs, fn.Name()) {
			return // an encoder reads the fields
		}
		signature, ok = fn.Origin().Type().(*types.Signature)
	}
	if !ok {
		return
	}
	selectsAll := slices.ContainsFunc(call.Args, func(arg ast.Expr) bool {
		if id, ok := ast.Unparen(arg).(*ast.Ident); ok {
			if v, ok := info.Uses[id].(*types.Var); ok && s.selectAllVars[v] {
				return true
			}
		}
		return selectsEveryColumn(arg, info)
	})
	for i, arg := range call.Args {
		param, ok := paramType(signature, i)
		if !ok || !reflectiveParam(param) {
			continue
		}
		if ptr, ok := types.Unalias(info.TypeOf(arg)).(*types.Pointer); ok {
			addReachableStructs(s.reflected, ptr.Elem())
			if selectsAll {
				addReachableStructs(s.allColumns, ptr.Elem())
			}
		}
	}
}

// queryVar records a variable assigned a query selecting every column.
func (s fillSources) queryVar(lhs, rhs ast.Expr, info *types.Info) {
	id, ok := lhs.(*ast.Ident)
	if !ok || !selectsEveryColumn(rhs, info) {
		return
	}
	if v, ok := info.ObjectOf(id).(*types.Var); ok {
		s.selectAllVars[v] = true
	}
}

// selectsEveryColumn reports a string constant selecting every column.
func selectsEveryColumn(expr ast.Expr, info *types.Info) bool {
	value, ok := info.Types[ast.Unparen(expr)]
	return ok && value.Value != nil && value.Value.Kind() == constant.String &&
		selectEveryColumn.MatchString(constant.StringVal(value.Value))
}

// reflectiveParam reports a parameter a callee may fill by reflection: an
// interface (any, jwt.Claims - the decoder sees the dynamic value) or a
// pointer to a type parameter.
func reflectiveParam(t types.Type) bool {
	if ptr, ok := types.Unalias(t).(*types.Pointer); ok {
		_, isTypeParam := types.Unalias(ptr.Elem()).(*types.TypeParam)
		return isTypeParam
	}
	_, isInterface := t.Underlying().(*types.Interface)
	return isInterface
}

// paramType returns the type of the parameter argument i lands in, the
// element type for the variadic tail.
func paramType(signature *types.Signature, i int) (types.Type, bool) {
	params := signature.Params()
	if params.Len() == 0 {
		return nil, false
	}
	if i < params.Len()-1 || (i == params.Len()-1 && !signature.Variadic()) {
		return params.At(i).Type(), true
	}
	if !signature.Variadic() {
		return nil, false
	}
	slice, ok := params.At(params.Len() - 1).Type().(*types.Slice)
	if !ok {
		return nil, false
	}
	return slice.Elem(), true
}
