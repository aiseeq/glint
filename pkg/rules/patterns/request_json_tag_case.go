package patterns

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"reflect"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/tools/go/types/typeutil"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewRequestJSONTagCaseRule())
}

// RequestJSONTagCaseRule detects a request body decoded into fields whose JSON
// names start with a capital letter in a project that names its JSON keys
// in lowerCamel or snake_case:
//
//	var req struct {
//		StrategyID string `json:"StrategyID"`
//		Amount     string `json:"Amount"`
//	}
//	json.NewDecoder(r.Body).Decode(&req)
//
// The project's own client follows the project's style and posts strategyId
// and amount; encoding/json matches keys without regard to case, but not
// names that differ in more than case, so StrategyID stays empty and the
// request fails or, worse, goes through with empty values. Only structs
// decoded from an incoming request are judged: a provider's response keeps
// the provider's names.
type RequestJSONTagCaseRule struct {
	*rules.BaseRule
}

// NewRequestJSONTagCaseRule creates the rule
func NewRequestJSONTagCaseRule() *RequestJSONTagCaseRule {
	return &RequestJSONTagCaseRule{BaseRule: rules.NewBaseRule(
		"request-json-tag-case",
		"patterns",
		"Detects a request body decoded into capitalized JSON names in a project whose JSON keys are lowerCamel or snake_case — the client's keys do not match",
		core.SeverityMedium,
	)}
}

// AnalyzeFile is a no-op: the project's style and the decoded type need the
// whole project.
func (r *RequestJSONTagCaseRule) AnalyzeFile(_ *core.FileContext) []*core.Violation { return nil }

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *RequestJSONTagCaseRule) RequiresSSA() bool { return false }

// A project names its JSON keys in lowercase when at least this share of
// its tags, and at least jsonStyleMinTags of them, start with a lowercase
// letter.
const (
	jsonStyleLowerShare = 0.9
	jsonStyleMinTags    = 10
)

// AnalyzeGoProject reports the capitalized JSON names of the structs request
// bodies are decoded into.
func (r *RequestJSONTagCaseRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	lower, upper := jsonTagCases(ctx)
	total := lower + upper
	if total < jsonStyleMinTags || float64(lower) < jsonStyleLowerShare*float64(total) {
		return nil, nil
	}
	reported := make(map[token.Pos]bool)
	var violations []*core.Violation
	for _, fn := range projectFuncDecls(ctx) {
		for _, target := range requestDecodeTargets(fn) {
			st, ok := pointedStruct(fn.info.TypeOf(target))
			if !ok {
				continue
			}
			for i := range st.NumFields() {
				field := st.Field(i)
				name, ok := capitalizedJSONName(st.Tag(i))
				if !ok || reported[field.Pos()] {
					continue
				}
				reported[field.Pos()] = true
				file, err := ctx.FileForPosition(field.Pos())
				if err != nil {
					return nil, fmt.Errorf("request json tag case: %w", err)
				}
				line := ctx.FileSet.Position(field.Pos()).Line
				if file.IsSuppressed(line, r.Name()) {
					continue
				}
				v := r.CreateViolation(file.RelPath, line, fmt.Sprintf(
					"Request field %s is read from JSON key %q while %d of %d JSON names in the project start in lowercase — a client posting the project's style sends a different key",
					field.Name(), name, lower, total))
				v.WithCode(strings.TrimSpace(file.GetLine(line)))
				v.WithSuggestion("Name the key the way the project's clients send it (lowerCamel or snake_case, as the other tags)")
				violations = append(violations, v)
			}
		}
	}
	return violations, nil
}

// jsonTagCases counts the JSON names of the project's struct fields that
// start with a lowercase and with an uppercase letter.
func jsonTagCases(ctx *core.GoProjectContext) (lower, upper int) {
	for _, pkg := range ctx.Packages {
		if pkg == nil {
			continue
		}
		for _, file := range pkg.Files {
			if file.GoAST == nil || file.IsTestFile() {
				continue
			}
			ast.Inspect(file.GoAST, func(n ast.Node) bool {
				field, ok := n.(*ast.Field)
				if !ok || field.Tag == nil {
					return true
				}
				name, ok := jsonTagName(strings.Trim(field.Tag.Value, "`"))
				if !ok {
					return true
				}
				first, _ := utf8.DecodeRuneInString(name)
				switch {
				case unicode.IsLower(first):
					lower++
				case unicode.IsUpper(first):
					upper++
				}
				return true
			})
		}
	}
	return lower, upper
}

// jsonTagName returns the explicit JSON name of a struct tag.
func jsonTagName(tag string) (string, bool) {
	value, ok := reflect.StructTag(tag).Lookup("json")
	if !ok {
		return "", false
	}
	name, _, _ := strings.Cut(value, ",")
	if name == "" || name == "-" {
		return "", false
	}
	return name, true
}

// capitalizedJSONName returns a JSON name that starts with a capital letter.
func capitalizedJSONName(tag string) (string, bool) {
	name, ok := jsonTagName(tag)
	if !ok {
		return "", false
	}
	first, _ := utf8.DecodeRuneInString(name)
	return name, unicode.IsUpper(first)
}

// requestDecodeTargets returns the expressions a function decodes an
// incoming request's body into: json.NewDecoder(r.Body).Decode(&v), or
// json.Unmarshal(b, &v) with b read from r.Body.
func requestDecodeTargets(fn typedFunc) []ast.Expr {
	info := fn.info
	bodies := make(map[types.Object]bool) // locals holding io.ReadAll(r.Body)
	ast.Inspect(fn.decl.Body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Rhs) != 1 || len(assign.Lhs) == 0 {
			return true
		}
		call, ok := ast.Unparen(assign.Rhs[0]).(*ast.CallExpr)
		if !ok || len(call.Args) != 1 || !isFuncOf(call, info, "ReadAll", "io", "io/ioutil") || requestBody(info, call.Args[0]) == "" {
			return true
		}
		if id, ok := assign.Lhs[0].(*ast.Ident); ok {
			if obj := info.ObjectOf(id); obj != nil {
				bodies[obj] = true
			}
		}
		return true
	})

	var targets []ast.Expr
	ast.Inspect(fn.decl.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch {
		case isFuncOf(call, info, "Decode", "encoding/json") && len(call.Args) == 1:
			sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
			if !ok {
				return true
			}
			decoder, ok := ast.Unparen(sel.X).(*ast.CallExpr)
			if ok && isFuncOf(decoder, info, "NewDecoder", "encoding/json") && len(decoder.Args) == 1 && requestBody(info, decoder.Args[0]) != "" {
				targets = append(targets, call.Args[0])
			}
		case isFuncOf(call, info, "Unmarshal", "encoding/json") && len(call.Args) == 2:
			if id, ok := ast.Unparen(call.Args[0]).(*ast.Ident); ok && bodies[info.Uses[id]] {
				targets = append(targets, call.Args[1])
			}
		}
		return true
	})
	return targets
}

// isFuncOf reports a call of a function or method named name declared in
// one of the packages.
func isFuncOf(call *ast.CallExpr, info *types.Info, name string, pkgs ...string) bool {
	fn, ok := typeutil.Callee(info, call).(*types.Func)
	if !ok || fn.Pkg() == nil || fn.Name() != name {
		return false
	}
	for _, pkg := range pkgs {
		if fn.Pkg().Path() == pkg {
			return true
		}
	}
	return false
}
