package security

import (
	"go/ast"
	"go/constant"
	"go/types"
	"regexp"
	"strings"

	"golang.org/x/tools/go/types/typeutil"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewURLQueryBuiltByFormatRule())
}

// URLQueryBuiltByFormatRule detects a string value put into a URL query by a
// format verb:
//
//	endpoint := fmt.Sprintf("/deposits?startDate=%s", start.Format(time.RFC3339))
//	endpoint += fmt.Sprintf("&cursor=%s", cursor)
//
// The value goes in unescaped: the "+" of a time zone offset reads as a
// space, a cursor or free text holding "&", "=" or "+" adds a parameter or
// changes the value, and the request fails or asks for something else.
// url.Values{}.Encode() or url.QueryEscape escape it. A verb sits in a query
// value when the format text before it ends in ?name= or &name=. Reported
// are the values that carry such characters: a time formatted with a zone
// offset or a space, and a string named for a pagination cursor or free
// text (cursor, after, before, fingerprint, continuation, query, search, q,
// term, text, filter, email, keyword, message, comment, description,
// title). Identifiers and enum words never need escaping and are left
// alone, as are numbers, constants and escaped values.
type URLQueryBuiltByFormatRule struct {
	*rules.BaseRule
}

// NewURLQueryBuiltByFormatRule creates the rule
func NewURLQueryBuiltByFormatRule() *URLQueryBuiltByFormatRule {
	return &URLQueryBuiltByFormatRule{BaseRule: rules.NewBaseRule(
		"url-query-built-by-format",
		"security",
		"Detects a time with a zone, a pagination cursor or free text put into a URL query by a fmt.Sprintf verb (?name=%s, &name=%s) without url.QueryEscape or url.Values",
		core.SeverityMedium,
	)}
}

// AnalyzeFile is a no-op: argument types need type information.
func (r *URLQueryBuiltByFormatRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *URLQueryBuiltByFormatRule) RequiresSSA() bool { return false }

// queryValueEnd matches format text ending where a query value starts.
var queryValueEnd = regexp.MustCompile(`[?&][A-Za-z0-9_.\[\]-]+=$`)

// AnalyzeGoProject reports the Sprintf calls of the project's files that
// format a string into a query value.
func (r *URLQueryBuiltByFormatRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(fileCtx *core.FileContext, info *types.Info) []*core.Violation {
		if fileCtx.IsTestFile() {
			return nil
		}
		var violations []*core.Violation
		ast.Inspect(fileCtx.GoAST, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || !sprintfCall(call, info) || !unescapedQueryValue(call, info) {
				return true
			}
			line := fileCtx.LineFor(call)
			if fileCtx.IsSuppressed(line, r.Name()) {
				return true
			}
			v := r.CreateViolation(fileCtx.RelPath, line,
				"A string goes into a URL query through a format verb unescaped — a \"+\" reads as a space, an \"&\" adds a parameter")
			v.WithCode(strings.TrimSpace(fileCtx.GetLine(line)))
			v.WithSuggestion("Build the query with url.Values{} and Encode(), or wrap the value in url.QueryEscape")
			v.WithContext("pattern", "url_query_built_by_format")
			violations = append(violations, v)
			return true
		})
		return violations
	})
}

func sprintfCall(call *ast.CallExpr, info *types.Info) bool {
	fn, ok := typeutil.Callee(info, call).(*types.Func)
	return ok && fn.Pkg() != nil && fn.Pkg().Path() == "fmt" && fn.Name() == "Sprintf" && len(call.Args) > 1
}

// unescapedQueryValue reports a %s or %v in a query value position whose
// argument is a plain string the call does not escape.
func unescapedQueryValue(call *ast.CallExpr, info *types.Info) bool {
	tv := info.Types[call.Args[0]]
	if tv.Value == nil || tv.Value.Kind() != constant.String {
		return false
	}
	format := constant.StringVal(tv.Value)
	verbs, ok := formatVerbs(format)
	if !ok {
		return false
	}
	for i, verb := range verbs {
		if verb.verb != 's' && verb.verb != 'v' {
			continue
		}
		if i+1 >= len(call.Args) || !queryValueEnd.MatchString(format[:verb.start]) {
			continue
		}
		if needsEscaping(call.Args[i+1], info) {
			return true
		}
	}
	return false
}

// freeTextNouns are the last words of names whose values hold characters
// that a query must escape.
var freeTextNouns = map[string]bool{
	"cursor": true, "after": true, "before": true, "fingerprint": true, "continuation": true,
	"query": true, "search": true, "q": true, "term": true, "text": true, "filter": true,
	"email": true, "keyword": true, "keywords": true, "message": true, "comment": true,
	"description": true, "title": true,
}

// needsEscaping reports a time formatted with a zone or a space, or a
// non-constant plain string named for a cursor or free text.
func needsEscaping(arg ast.Expr, info *types.Info) bool {
	tv, ok := info.Types[arg]
	if !ok || tv.Value != nil {
		return false
	}
	basic, ok := tv.Type.(*types.Basic)
	if !ok || basic.Kind() != types.String {
		return false
	}
	switch e := ast.Unparen(arg).(type) {
	case *ast.CallExpr:
		return zonedTimeFormat(e, info)
	case *ast.Ident:
		return freeTextName(e.Name)
	case *ast.SelectorExpr:
		return freeTextName(e.Sel.Name)
	}
	return false
}

// zonedTimeFormat reports time.Time.Format with a layout holding a zone
// offset or a space.
func zonedTimeFormat(call *ast.CallExpr, info *types.Info) bool {
	fn, ok := typeutil.Callee(info, call).(*types.Func)
	if !ok || fn.Pkg() == nil || fn.Pkg().Path() != "time" || fn.Name() != "Format" || len(call.Args) != 1 {
		return false
	}
	tv := info.Types[call.Args[0]]
	if tv.Value == nil || tv.Value.Kind() != constant.String {
		return false
	}
	layout := constant.StringVal(tv.Value)
	return strings.ContainsAny(layout, " +") || strings.Contains(layout, "Z07") || strings.Contains(layout, "-07")
}

func freeTextName(name string) bool {
	words := helpers.IdentifierWords(name)
	return len(words) > 0 && freeTextNouns[words[len(words)-1]]
}

type formatVerb struct {
	verb  byte
	start int
}

// formatVerbs returns the verbs of a format in argument order with the
// offset of their %. A format with an explicit argument index or a * width
// does not map verbs to arguments one to one and is not parsed.
func formatVerbs(format string) ([]formatVerb, bool) {
	var verbs []formatVerb
	for i := 0; i < len(format); i++ {
		if format[i] != '%' {
			continue
		}
		start := i
		i++
		for i < len(format) && strings.IndexByte("+-# 0123456789.", format[i]) >= 0 {
			i++
		}
		if i >= len(format) {
			return verbs, true
		}
		switch format[i] {
		case '%':
			continue
		case '[', '*':
			return nil, false
		}
		verbs = append(verbs, formatVerb{verb: format[i], start: start})
	}
	return verbs, true
}
