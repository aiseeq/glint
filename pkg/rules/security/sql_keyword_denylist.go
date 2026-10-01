package security

import (
	"go/ast"
	"go/token"
	"strings"
	"unicode"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewSQLKeywordDenylistRule())
}

// SQLKeywordDenylistRule detects SQL text validated against a list of
// dangerous keywords:
//
//	for _, kw := range []string{"DROP ", "UNION ", "--", ";"} {
//	    if strings.Contains(strings.ToUpper(where), kw) { return errForbidden }
//	}
//
// A denylist is bypassed by a tab or a newline instead of the space, a
// comment inside the keyword or a condition like OR 1=1, and it makes the
// code look safe while the SQL is still built from strings. Placeholders
// for values and an allowlist for identifiers are the fix. A function is a
// denylist when strings.Contains checks the text against at least two SQL
// keywords or markers, one of them a keyword and one a comment, a statement
// separator or UNION: a check that classifies a statement (is it a write?)
// does not look for the markers, and a comment scanner has no keyword.
type SQLKeywordDenylistRule struct {
	*rules.BaseRule
}

// NewSQLKeywordDenylistRule creates the rule
func NewSQLKeywordDenylistRule() *SQLKeywordDenylistRule {
	return &SQLKeywordDenylistRule{BaseRule: rules.NewBaseRule(
		"sql-keyword-denylist",
		"security",
		"Detects SQL text validated by strings.Contains against a list of keywords (DROP, UNION, --, ;) — a denylist that tabs, comments and OR 1=1 pass",
		core.SeverityMedium,
	)}
}

var (
	sqlDenylistTokens = map[string]bool{
		"DROP": true, "DELETE": true, "INSERT": true, "UPDATE": true, "ALTER": true, "TRUNCATE": true,
		"CREATE": true, "UNION": true, "EXEC": true, "EXECUTE": true, "SELECT": true, "GRANT": true,
		"--": true, "/*": true, "*/": true, ";": true, "XP_": true, "OR 1=1": true, "' OR": true,
		"INTO OUTFILE": true, "INTO DUMPFILE": true, "LOAD_FILE": true, "SLEEP(": true, "WAITFOR": true,
	}
	sqlDenylistMarkers = map[string]bool{"--": true, "/*": true, ";": true, "UNION": true, "OR 1=1": true, "' OR": true}
)

// AnalyzeFile reports each function that checks text against a SQL denylist.
func (r *SQLKeywordDenylistRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.HasGoAST() || ctx.IsTestFile() {
		return nil
	}
	lists := packageStringLists(ctx.GoAST)
	var violations []*core.Violation
	for _, decl := range ctx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		first := sqlDenylistCheck(fn.Body, lists)
		if first == nil {
			continue
		}
		line := ctx.LineFor(first)
		if ctx.IsSuppressed(line, r.Name()) {
			continue
		}
		v := r.CreateViolation(ctx.RelPath, line,
			"SQL text is checked against a keyword denylist — a tab instead of a space, a comment inside a keyword or OR 1=1 pass it, and the SQL is still built from strings")
		v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
		v.WithSuggestion("Pass values as placeholders and check identifiers against an allowlist; drop the keyword scan")
		v.WithContext("pattern", "sql_keyword_denylist")
		violations = append(violations, v)
	}
	return violations
}

// packageStringLists returns the package-level variables holding a literal
// list of strings.
func packageStringLists(file *ast.File) map[string][]string {
	lists := make(map[string][]string)
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.VAR {
			continue
		}
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok || len(vs.Names) != len(vs.Values) {
				continue
			}
			for i, name := range vs.Names {
				if lit, ok := vs.Values[i].(*ast.CompositeLit); ok {
					lists[name.Name] = stringElements(lit)
				}
			}
		}
	}
	return lists
}

// sqlDenylistCheck returns the first strings.Contains call of a body that
// checks against a SQL denylist, or nil.
func sqlDenylistCheck(body *ast.BlockStmt, lists map[string][]string) *ast.CallExpr {
	// Range variables over a literal list, local or package-level.
	ranged := make(map[string][]string)
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			for i, lhs := range node.Lhs {
				ident, ok := lhs.(*ast.Ident)
				if !ok || i >= len(node.Rhs) {
					continue
				}
				if lit, ok := node.Rhs[i].(*ast.CompositeLit); ok {
					lists[ident.Name] = stringElements(lit)
				}
			}
		case *ast.RangeStmt:
			value, ok := node.Value.(*ast.Ident)
			if !ok {
				return true
			}
			switch x := node.X.(type) {
			case *ast.Ident:
				ranged[value.Name] = lists[x.Name]
			case *ast.CompositeLit:
				ranged[value.Name] = stringElements(x)
			}
		}
		return true
	})
	var first *ast.CallExpr
	tokens := make(map[string]bool)
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 2 {
			return true
		}
		if pkg, ok := callPackage(call); !ok || pkg != "strings" || callName(call) != "Contains" {
			return true
		}
		var checked []string
		switch arg := call.Args[1].(type) {
		case *ast.BasicLit:
			checked = []string{stringLiteral(arg)}
		case *ast.Ident:
			checked = ranged[arg.Name]
		}
		found := false
		for _, text := range checked {
			if word := strings.ToUpper(strings.TrimSpace(text)); sqlDenylistTokens[word] {
				tokens[word] = true
				found = true
			}
		}
		if found && first == nil {
			first = call
		}
		return true
	})
	// A comment scanner checks /* and */ too: a denylist names a SQL
	// keyword besides its markers.
	marker, keyword := false, false
	for word := range tokens {
		marker = marker || sqlDenylistMarkers[word]
		keyword = keyword || strings.IndexFunc(word, unicode.IsLetter) >= 0
	}
	if len(tokens) < 2 || !marker || !keyword {
		return nil
	}
	return first
}

// stringElements returns the string literal elements of a composite literal.
func stringElements(lit *ast.CompositeLit) []string {
	var out []string
	for _, elt := range lit.Elts {
		if text := stringLiteral(elt); text != "" {
			out = append(out, text)
		}
	}
	return out
}
