package security

import (
	"go/ast"
	"go/token"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewIDEncodesDataRule())
}

// IDEncodesDataRule detects an identifier built from data with a prefix and
// taken apart elsewhere to get the data back:
//
//	adminID := fmt.Sprintf("admin-%s", claims.Email)
//	...
//	adminEmail := strings.TrimPrefix(userID, "admin-")
//
// The id is not an id: it names no row, it changes when the email does, and
// every reader that strips the prefix trusts that whatever reaches it was
// built this way — a real user id passes through unchanged and is taken for
// an email. Pass the data as its own value and use the real id. Only a
// prefix that the project both builds ids with and strips from ids counts.
type IDEncodesDataRule struct {
	*rules.BaseRule
	built    map[string]bool // prefixes ids are built with
	stripped map[string]bool // prefixes stripped from ids
}

// NewIDEncodesDataRule creates the rule
func NewIDEncodesDataRule() *IDEncodesDataRule {
	return &IDEncodesDataRule{BaseRule: rules.NewBaseRule(
		"id-encodes-data",
		"security",
		"Detects an id built as prefix+data and parsed back with TrimPrefix elsewhere — the id carries data and any real id passes the parse as data",
		core.SeverityMedium,
	)}
}

// idPrefixUse is a place an id prefix is built into or stripped from an id.
type idPrefixUse struct {
	prefix string
	node   ast.Node
	build  bool
}

// UseProjectFiles indexes the prefixes ids are built with and stripped of.
func (r *IDEncodesDataRule) UseProjectFiles(files []*core.FileContext) {
	r.built, r.stripped = make(map[string]bool), make(map[string]bool)
	for _, ctx := range files {
		for _, use := range idPrefixUses(ctx) {
			if use.build {
				r.built[use.prefix] = true
			} else {
				r.stripped[use.prefix] = true
			}
		}
	}
}

// ResetState drops the prefixes of the previous root.
func (r *IDEncodesDataRule) ResetState() { r.built, r.stripped = nil, nil }

// AnalyzeFile reports the builds and parses of a prefix used both ways.
func (r *IDEncodesDataRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	lr := newLineReporter(ctx, r.BaseRule)
	for _, use := range idPrefixUses(ctx) {
		if !r.built[use.prefix] || !r.stripped[use.prefix] {
			continue
		}
		message := "Id built as \"" + use.prefix + "\" + data, and the data is parsed back out of ids elsewhere — any real id reaching the parse is taken for data"
		if !use.build {
			message = "Data parsed out of an id by stripping \"" + use.prefix + "\" — ids are built from data elsewhere, and a real id passes the parse unchanged"
		}
		lr.report(use.node, message, "Pass the data as its own value and use the record's real id", "id_encodes_data")
	}
	return lr.violations
}

// idPrefixUses returns the prefix builds and strips on id variables of a
// production Go file.
func idPrefixUses(ctx *core.FileContext) []idPrefixUse {
	if !ctx.HasGoAST() || ctx.IsTestFile() {
		return nil
	}
	var uses []idPrefixUse
	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			for i, rhs := range node.Rhs {
				if i < len(node.Lhs) && namesID(node.Lhs[i]) {
					if prefix, ok := builtPrefix(rhs); ok {
						uses = append(uses, idPrefixUse{prefix: prefix, node: rhs, build: true})
					}
				}
			}
		case *ast.CallExpr:
			if call, ok := isStringsCall(node, "TrimPrefix", "CutPrefix"); ok && len(call.Args) == 2 && namesID(call.Args[0]) {
				if prefix := stringLiteral(call.Args[1]); idPrefix(prefix) {
					uses = append(uses, idPrefixUse{prefix: prefix, node: call})
				}
			}
		}
		return true
	})
	return uses
}

// builtPrefix returns the literal prefix of fmt.Sprintf("p%s", x) or "p" + x.
func builtPrefix(expr ast.Expr) (string, bool) {
	switch e := ast.Unparen(expr).(type) {
	case *ast.CallExpr:
		if pkg, ok := callPackage(e); !ok || pkg != "fmt" || callName(e) != "Sprintf" || len(e.Args) < 2 {
			return "", false
		}
		format := stringLiteral(e.Args[0])
		prefix, _, found := strings.Cut(format, "%")
		return prefix, found && idPrefix(prefix)
	case *ast.BinaryExpr:
		if e.Op != token.ADD {
			return "", false
		}
		prefix := stringLiteral(e.X)
		return prefix, idPrefix(prefix)
	}
	return "", false
}

// idPrefix reports a word ending in a separator: "admin-", "user:", "tg_".
func idPrefix(prefix string) bool {
	if len(prefix) < 3 {
		return false
	}
	return strings.ContainsAny(prefix[len(prefix)-1:], "-:_") && !strings.ContainsAny(prefix[:len(prefix)-1], " /%")
}

// namesID reports a variable or field whose last word is id.
func namesID(expr ast.Expr) bool {
	var name string
	switch e := ast.Unparen(expr).(type) {
	case *ast.Ident:
		name = e.Name
	case *ast.SelectorExpr:
		name = e.Sel.Name
	default:
		return false
	}
	words := helpers.IdentifierWords(name)
	return len(words) > 0 && words[len(words)-1] == "id"
}
