package patterns

import (
	"go/ast"
	"go/token"
	"go/types"
	"path/filepath"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewHTTPErrorPlaintextRule())
}

// HTTPErrorPlaintextRule detects http.Error in handlers of a JSON API: a
// package that answers with JSON elsewhere (json.NewEncoder(w), json.Marshal
// written to the ResponseWriter, an application/json content type).
//
// http.Error writes the message as text/plain. A client that parses every
// response as JSON fails on such a body with a parser exception, so the user
// sees "Unexpected token" instead of the reason the request was rejected —
// and the layer that rejected the request stays invisible in the client logs.
type HTTPErrorPlaintextRule struct {
	*rules.BaseRule
}

// NewHTTPErrorPlaintextRule creates the rule
func NewHTTPErrorPlaintextRule() *HTTPErrorPlaintextRule {
	return &HTTPErrorPlaintextRule{
		BaseRule: rules.NewBaseRule(
			"http-error-plaintext",
			"patterns",
			"Detects http.Error in a JSON API: the text/plain body breaks clients that parse responses as JSON",
			core.SeverityMedium,
		),
	}
}

// nonJSONContentTypes mark a handler whose body is read by something other than
// a JSON client: browsers following a redirect, EventSource, image and file
// responses. http.Error is a fine answer there.
var nonJSONContentTypes = []string{
	"text/event-stream",
	"text/html",
	"text/csv",
	"image/",
	"application/pdf",
	"application/octet-stream",
}

// externalConsumerPaths mark handlers whose caller is not our own client:
// provider webhooks and streaming endpoints answer by status code, and their
// body format is dictated by the other side.
var externalConsumerPaths = []string{
	"webhook",
	"callback",
	"/sse/",
	"sse_",
	"_sse",
}

// AnalyzeFile checks one file on its own: it counts as part of a JSON API when
// the file itself answers with JSON.
func (r *HTTPErrorPlaintextRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || ctx.IsTestFile() || ctx.GoAST == nil {
		return nil
	}
	return r.analyze(ctx, nil, answersWithJSON(ctx.GoAST, nil))
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *HTTPErrorPlaintextRule) RequiresSSA() bool { return false }

// AnalyzeGoProject reports http.Error in packages that answer with JSON: a
// package (directory) is a JSON API when any of its non-test files encodes JSON
// into a ResponseWriter or declares the application/json content type.
func (r *HTTPErrorPlaintextRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	jsonDirs := map[string]bool{}
	_, err := rules.AnalyzeGoFiles(ctx, r.Name(), func(fileCtx *core.FileContext, info *types.Info) []*core.Violation {
		if fileCtx.IsGoFile() && !fileCtx.IsTestFile() && answersWithJSON(fileCtx.GoAST, info) {
			jsonDirs[filepath.Dir(fileCtx.Path)] = true
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return rules.AnalyzeGoFiles(ctx, r.Name(), func(fileCtx *core.FileContext, info *types.Info) []*core.Violation {
		if !fileCtx.IsGoFile() || fileCtx.IsTestFile() {
			return nil
		}
		return r.analyze(fileCtx, info, jsonDirs[filepath.Dir(fileCtx.Path)])
	})
}

// analyze reports every http.Error call of a file that belongs to a JSON API
// and serves no other body format.
func (r *HTTPErrorPlaintextRule) analyze(ctx *core.FileContext, info *types.Info, jsonAPI bool) []*core.Violation {
	if !jsonAPI || r.servesExternalConsumer(ctx.RelPath) || servesNonJSONBody(ctx.GoAST) {
		return nil
	}

	var violations []*core.Violation
	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || !isPackageFuncCall(ctx.GoAST, info, call, "net/http", "Error") {
			return true
		}
		line := ctx.LineFor(call)
		v := r.CreateViolation(ctx.RelPath, line,
			"http.Error replies with a text/plain body: a JSON client fails on parsing it instead of showing the reason")
		v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
		v.WithSuggestion("Reply with the same JSON error envelope the rest of the API uses")
		violations = append(violations, v)
		return true
	})
	return violations
}

func (r *HTTPErrorPlaintextRule) servesExternalConsumer(relPath string) bool {
	lower := strings.ToLower(relPath)
	for _, marker := range externalConsumerPaths {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

// servesNonJSONBody reports whether a string literal of the file names a
// non-JSON content type. Comments do not count: they declare nothing.
func servesNonJSONBody(file *ast.File) bool {
	return hasStringLiteral(file, func(value string) bool {
		for _, contentType := range nonJSONContentTypes {
			if strings.Contains(value, contentType) {
				return true
			}
		}
		return false
	})
}

// answersWithJSON reports whether the file writes JSON responses: a string
// literal names application/json, or JSON is encoded into a ResponseWriter
// (json.NewEncoder(w), or json.Marshal and w.Write in one function).
func answersWithJSON(file *ast.File, info *types.Info) bool {
	if hasStringLiteral(file, func(value string) bool { return strings.Contains(value, "application/json") }) {
		return true
	}
	writers := responseWriterParams(file, info)
	isWriter := func(expr ast.Expr) bool {
		if info != nil {
			return isNamedType(info.TypeOf(expr), "net/http", "ResponseWriter")
		}
		ident, ok := ast.Unparen(expr).(*ast.Ident)
		return ok && writers[ident.Name]
	}
	found := false
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		marshals, writes := false, false
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || found {
				return !found
			}
			switch {
			case isPackageFuncCall(file, info, call, "encoding/json", "NewEncoder"):
				found = len(call.Args) == 1 && isWriter(call.Args[0])
			case isPackageFuncCall(file, info, call, "encoding/json", "Marshal", "MarshalIndent"):
				marshals = true
			default:
				if sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr); ok && sel.Sel.Name == "Write" && isWriter(sel.X) {
					writes = true
				}
			}
			return !found
		})
		if found || (marshals && writes) {
			return true
		}
	}
	return false
}

// responseWriterParams collects, for a file without type information, the
// names of parameters declared as http.ResponseWriter.
func responseWriterParams(file *ast.File, info *types.Info) map[string]bool {
	names := map[string]bool{}
	if info != nil {
		return names
	}
	ast.Inspect(file, func(n ast.Node) bool {
		funcType, ok := n.(*ast.FuncType)
		if !ok || funcType.Params == nil {
			return true
		}
		for _, field := range funcType.Params.List {
			sel, ok := field.Type.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "ResponseWriter" {
				continue
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || !helpers.PackageAliases(file, `"net/http"`, "http")[pkg.Name] {
				continue
			}
			for _, name := range field.Names {
				names[name.Name] = true
			}
		}
		return true
	})
	return names
}

// hasStringLiteral reports whether some string literal of the file matches.
func hasStringLiteral(file *ast.File, match func(string) bool) bool {
	found := false
	ast.Inspect(file, func(n ast.Node) bool {
		if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING && match(lit.Value) {
			found = true
		}
		return !found
	})
	return found
}
