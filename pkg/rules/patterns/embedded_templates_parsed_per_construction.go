package patterns

import (
	"go/ast"
	"go/token"
	"path/filepath"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewEmbeddedTemplatesParsedPerConstructionRule())
}

// EmbeddedTemplatesParsedPerConstructionRule reports constructors that parse
// embedded templates on each call instead of using a package-level cache.
type EmbeddedTemplatesParsedPerConstructionRule struct {
	*rules.BaseRule
	functions map[string]map[string]*ast.FuncDecl
	embedded  map[string]map[string]bool
	cached    map[string]map[string]bool
}

// NewEmbeddedTemplatesParsedPerConstructionRule creates the rule.
func NewEmbeddedTemplatesParsedPerConstructionRule() *EmbeddedTemplatesParsedPerConstructionRule {
	return &EmbeddedTemplatesParsedPerConstructionRule{BaseRule: rules.NewBaseRule(
		"embedded-templates-parsed-per-construction",
		"patterns",
		"Detects a New* constructor that reparses templates from an embedded filesystem on each call instead of using a package-level cache",
		core.SeverityMedium,
	)}
}

// UseProjectFiles collects package-local helpers, embedded filesystems and
// functions memoized with sync.OnceValues.
func (r *EmbeddedTemplatesParsedPerConstructionRule) UseProjectFiles(files []*core.FileContext) {
	r.functions = make(map[string]map[string]*ast.FuncDecl)
	r.embedded = make(map[string]map[string]bool)
	r.cached = make(map[string]map[string]bool)
	for _, ctx := range files {
		if !ctx.IsGoFile() || !ctx.HasGoAST() || ctx.IsTestFile() {
			continue
		}
		dir := filepath.Dir(ctx.Path)
		if r.functions[dir] == nil {
			r.functions[dir] = make(map[string]*ast.FuncDecl)
			r.embedded[dir] = make(map[string]bool)
			r.cached[dir] = make(map[string]bool)
		}
		for _, decl := range ctx.GoAST.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if d.Body != nil && d.Recv == nil {
					r.functions[dir][d.Name.Name] = d
				}
			case *ast.GenDecl:
				if d.Tok != token.VAR {
					continue
				}
				collectEmbeddedVars(d, r.embedded[dir])
				collectCachedVars(d, r.cached[dir])
			}
		}
	}
}

// ResetState drops package data between analyzed roots.
func (r *EmbeddedTemplatesParsedPerConstructionRule) ResetState() {
	r.functions, r.embedded, r.cached = nil, nil, nil
}

// AnalyzeFile reports constructors whose call graph reaches an uncached parse.
func (r *EmbeddedTemplatesParsedPerConstructionRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || !ctx.HasGoAST() || ctx.IsTestFile() {
		return nil
	}
	dir := filepath.Dir(ctx.Path)
	funcs, embedded, cached := r.functions[dir], r.embedded[dir], r.cached[dir]
	var findings []*core.Violation
	for _, decl := range ctx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv != nil || fn.Body == nil || !isConstructorName(fn.Name.Name) {
			continue
		}
		call := functionEmbeddedParse(fn, funcs, embedded, cached, make(map[string]bool))
		if call == nil {
			continue
		}
		line := ctx.LineFor(call)
		if ctx.IsSuppressed(line, r.Name()) {
			continue
		}
		v := r.CreateViolation(ctx.RelPath, line,
			fn.Name.Name+" reparses embedded templates on every construction — cache the parsed templates at package level")
		v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
		v.WithSuggestion("Wrap the package-level template parser with sync.OnceValues and call the cached function")
		findings = append(findings, v)
	}
	return findings
}

func collectEmbeddedVars(decl *ast.GenDecl, embedded map[string]bool) {
	if !hasGoEmbedDirective(decl.Doc) {
		return
	}
	for _, spec := range decl.Specs {
		values, ok := spec.(*ast.ValueSpec)
		if !ok {
			continue
		}
		for _, name := range values.Names {
			embedded[name.Name] = true
		}
	}
}

func collectCachedVars(decl *ast.GenDecl, cached map[string]bool) {
	for _, spec := range decl.Specs {
		values, ok := spec.(*ast.ValueSpec)
		if !ok {
			continue
		}
		for i, value := range values.Values {
			if i < len(values.Names) && onceValuesFunc(value) {
				cached[values.Names[i].Name] = true
			}
		}
	}
}

func hasGoEmbedDirective(group *ast.CommentGroup) bool {
	if group == nil {
		return false
	}
	for _, comment := range group.List {
		if strings.HasPrefix(comment.Text, "//go:embed ") {
			return true
		}
	}
	return false
}

func onceValuesFunc(expr ast.Expr) bool {
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok || len(call.Args) == 0 {
		return false
	}
	selector, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	return ok && selector.Sel.Name == "OnceValues"
}

// functionEmbeddedParse returns a call in fn that reaches a ParseFS over an
// embedded filesystem, directly or through package helpers; functions
// memoized by OnceValues are boundaries.
func functionEmbeddedParse(fn *ast.FuncDecl, funcs map[string]*ast.FuncDecl, embedded, cached, seen map[string]bool) ast.Node {
	var result ast.Node
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || result != nil {
			return result == nil
		}
		if isEmbeddedParseFS(call, embedded) {
			if !parseInsideOnceDo(fn.Body, call) {
				result = call
			}
			return false
		}
		name, ok := calledIdent(call)
		if !ok || cached[name] || seen[name] {
			return true
		}
		if helper := funcs[name]; helper != nil {
			seen[name] = true
			if functionEmbeddedParse(helper, funcs, embedded, cached, seen) != nil {
				result = call
			}
		}
		return true
	})
	return result
}

func parseInsideOnceDo(body *ast.BlockStmt, parse *ast.CallExpr) bool {
	protected := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "Do" {
			return true
		}
		for _, arg := range call.Args {
			callback, ok := ast.Unparen(arg).(*ast.FuncLit)
			if !ok {
				continue
			}
			ast.Inspect(callback.Body, func(n ast.Node) bool {
				if n == parse {
					protected = true
					return false
				}
				return !protected
			})
		}
		return !protected
	})
	return protected
}

func isEmbeddedParseFS(call *ast.CallExpr, embedded map[string]bool) bool {
	selector, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "ParseFS" || len(call.Args) == 0 {
		return false
	}
	arg, ok := ast.Unparen(call.Args[0]).(*ast.Ident)
	return ok && embedded[arg.Name]
}

func calledIdent(call *ast.CallExpr) (string, bool) {
	id, ok := ast.Unparen(call.Fun).(*ast.Ident)
	return func() (string, bool) {
		if !ok {
			return "", false
		}
		return id.Name, true
	}()
}
