package patterns

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"text/template/parse"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewGoTemplateRootFieldInsideRangeRule())
	rules.Register(NewGoTemplateDefineCollisionInSharedSetRule())
	rules.Register(NewGoTemplateJSONStringInScriptContextRule())
	rules.Register(NewRelativeFetchURLResolvesAgainstPagePathRule())
	rules.Register(NewI18nKeyUsedButNotDefinedRule())
	rules.Register(NewHtmxSwapTargetExcludesDependentFragmentRule())
}

// templateProjectRule is a rule that checks the templates of a project
// against its Go code; analyze returns findings in either kind of file.
type templateProjectRule struct {
	*rules.BaseRule
	suggestion string
	analyze    func(ctx *core.GoProjectContext) ([]projectFinding, error)
}

// projectFinding is one report of a template rule: a file of the run, a line
// and what is wrong there.
type projectFinding struct {
	path    string
	line    int
	message string
}

// AnalyzeFile is a no-op: the rule compares files across the project.
func (r *templateProjectRule) AnalyzeFile(*core.FileContext) []*core.Violation { return nil }

// RequiresSSA reports that the rule needs no SSA.
func (r *templateProjectRule) RequiresSSA() bool { return false }

// AnalyzeGoProject runs the check and maps its findings to the files of the
// run.
func (r *templateProjectRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%s: nil Go project context", r.Name())
	}
	findings, err := r.analyze(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", r.Name(), err)
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].path != findings[j].path {
			return findings[i].path < findings[j].path
		}
		return findings[i].line < findings[j].line
	})
	var violations []*core.Violation
	for _, f := range findings {
		file, err := ctx.File(f.path)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", r.Name(), err)
		}
		if file.IsSuppressed(f.line, r.Name()) {
			continue
		}
		v := r.CreateViolation(file.RelPath, f.line, f.message)
		v.WithCode(strings.TrimSpace(file.GetLine(f.line)))
		v.WithSuggestion(r.suggestion)
		violations = append(violations, v)
	}
	return violations, nil
}

// projectTemplate is a template file of the run.
type projectTemplate struct {
	file *core.FileContext
	text string
}

// runTemplates returns the template files under the project root that the
// run analyzes.
func runTemplates(ctx *core.GoProjectContext) ([]projectTemplate, error) {
	paths, err := templateFiles(ctx.ProjectRoot)
	if err != nil {
		return nil, err
	}
	var out []projectTemplate
	for _, path := range paths {
		if file, inRun := ctx.RunFile(path); inRun {
			out = append(out, projectTemplate{file: file, text: string(file.Content)})
		}
	}
	return out, nil
}

// goSource is a Go file of the run with its package.
type goSource struct {
	file *ast.File
	path string
	pkg  *core.GoPackageContext
}

// runGoFiles returns the Go files of the typed packages that the run
// analyzes.
func runGoFiles(ctx *core.GoProjectContext) []goSource {
	var out []goSource
	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil || pkg.Package.TypesInfo == nil {
			continue
		}
		for _, file := range pkg.Package.Syntax {
			path := pkg.Package.Fset.Position(file.Pos()).Filename
			if _, inRun := ctx.RunFile(path); inRun {
				out = append(out, goSource{file: file, path: path, pkg: pkg})
			}
		}
	}
	return out
}

// line returns the line of a node of the file.
func (g goSource) line(node ast.Node) int { return g.pkg.Package.Fset.Position(node.Pos()).Line }

// parseTemplates parses a template file into its trees (the file's own and
// the ones it defines), nil when it does not parse.
func parseTemplates(name, text string) map[string]*parse.Tree {
	tree := parse.New(name)
	tree.Mode = parse.SkipFuncCheck
	set := make(map[string]*parse.Tree)
	// silent-error-handling: safe — an .html file of another template engine is not a Go template and has nothing to check
	if _, err := tree.Parse(text, "", "", set); err != nil {
		return nil
	}
	return set
}

// lineAt returns the line of a byte offset of the text.
func lineAt(text string, pos parse.Pos) int {
	if int(pos) > len(text) {
		return 0
	}
	return strings.Count(text[:pos], "\n") + 1
}

// NewGoTemplateRootFieldInsideRangeRule creates go-template-root-field-inside-range:
// inside {{range}} or {{with}} the dot is the element, and a .Field of the
// page data read there - not $.Field - fails at render time on the first
// element; a test with an empty list renders only the {{else}} branch:
//
//	{{range .Rows}} ... {{t .Lang "row.delete"}} ... {{end}}   // .Lang is the page's
func NewGoTemplateRootFieldInsideRangeRule() *templateProjectRule {
	r := &templateProjectRule{
		BaseRule: rules.NewBaseRule(
			"go-template-root-field-inside-range",
			"patterns",
			"Detects a .Field read inside {{range}} or {{with}} that the element type lacks and the page data has — the template fails on the first element",
			core.SeverityHigh,
		),
		suggestion: "Read the page's field as $.Field inside the block",
	}
	r.analyze = func(ctx *core.GoProjectContext) ([]projectFinding, error) {
		templates, err := runTemplates(ctx)
		if err != nil {
			return nil, err
		}
		bound := templateDataTypes(ctx)
		names := make(map[string]int)
		for _, tmpl := range templates {
			names[filepath.Base(tmpl.file.Path)]++
		}
		var findings []projectFinding
		for _, tmpl := range templates {
			base := filepath.Base(tmpl.file.Path)
			roots := bound[base]
			if len(roots) != 1 || names[base] != 1 {
				continue
			}
			trees := parseTemplates(base, tmpl.text)
			for _, name := range sortedTreeNames(trees) {
				if !invokedWithRootOnly(trees, name) {
					continue
				}
				walkTemplateNode(trees[name].Root, roots[0], roots[0], func(pos parse.Pos, field string) {
					findings = append(findings, projectFinding{path: tmpl.file.Path, line: lineAt(tmpl.text, pos), message: fmt.Sprintf(
						".%s is read inside a block where the dot is an element that has no %s — the page data has it: the template fails on the first element (use $.%s)", field, field, field)})
				})
			}
		}
		return findings, nil
	}
	return r
}

// sortedTreeNames returns the names of the trees in a stable order.
func sortedTreeNames(trees map[string]*parse.Tree) []string {
	names := make([]string, 0, len(trees))
	for name := range trees {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// invokedWithRootOnly reports a tree no {{template}} of the file calls with
// anything but the dot of the page.
func invokedWithRootOnly(trees map[string]*parse.Tree, name string) bool {
	ok := true
	for _, tree := range trees {
		visitTemplateCalls(tree.Root, false, func(call *parse.TemplateNode, nested bool) {
			if call.Name != name {
				return
			}
			if nested || call.Pipe == nil || len(call.Pipe.Cmds) != 1 || len(call.Pipe.Cmds[0].Args) != 1 {
				ok = false
				return
			}
			if _, isDot := call.Pipe.Cmds[0].Args[0].(*parse.DotNode); !isDot {
				ok = false
			}
		})
	}
	return ok
}

// visitTemplateCalls calls visit for each {{template}} of a node; nested
// tells one inside a range or with, where the dot is not the page.
func visitTemplateCalls(node parse.Node, nested bool, visit func(*parse.TemplateNode, bool)) {
	switch n := node.(type) {
	case *parse.ListNode:
		if n == nil {
			return
		}
		for _, child := range n.Nodes {
			visitTemplateCalls(child, nested, visit)
		}
	case *parse.TemplateNode:
		visit(n, nested)
	case *parse.IfNode:
		visitTemplateCalls(n.List, nested, visit)
		visitTemplateCalls(n.ElseList, nested, visit)
	case *parse.RangeNode:
		visitTemplateCalls(n.List, true, visit)
		visitTemplateCalls(n.ElseList, nested, visit)
	case *parse.WithNode:
		visitTemplateCalls(n.List, true, visit)
		visitTemplateCalls(n.ElseList, nested, visit)
	}
}

// walkTemplateNode checks the field reads of a node against the type of the
// dot, reporting the ones the dot lacks and the root has.
func walkTemplateNode(node parse.Node, dot, root types.Type, report func(parse.Pos, string)) {
	switch n := node.(type) {
	case *parse.ListNode:
		if n == nil {
			return
		}
		for _, child := range n.Nodes {
			walkTemplateNode(child, dot, root, report)
		}
	case *parse.ActionNode:
		checkTemplatePipe(n.Pipe, dot, root, report)
	case *parse.TemplateNode:
		checkTemplatePipe(n.Pipe, dot, root, report)
	case *parse.IfNode:
		checkTemplatePipe(n.Pipe, dot, root, report)
		walkTemplateNode(n.List, dot, root, report)
		walkTemplateNode(n.ElseList, dot, root, report)
	case *parse.RangeNode:
		checkTemplatePipe(n.Pipe, dot, root, report)
		walkTemplateNode(n.List, elementType(templatePipeType(n.Pipe, dot, root)), root, report)
		walkTemplateNode(n.ElseList, dot, root, report)
	case *parse.WithNode:
		checkTemplatePipe(n.Pipe, dot, root, report)
		walkTemplateNode(n.List, templatePipeType(n.Pipe, dot, root), root, report)
		walkTemplateNode(n.ElseList, dot, root, report)
	}
}

// checkTemplatePipe reports the fields a pipeline reads off the dot that the
// dot's type lacks and the root's has.
func checkTemplatePipe(pipe *parse.PipeNode, dot, root types.Type, report func(parse.Pos, string)) {
	if pipe == nil {
		return
	}
	for _, cmd := range pipe.Cmds {
		for _, arg := range cmd.Args {
			switch a := arg.(type) {
			case *parse.FieldNode:
				if dot != nil && !types.Identical(dot, root) && isStructLike(dot) && templateMember(dot, a.Ident[0]) == nil && templateMember(root, a.Ident[0]) != nil {
					report(a.Position(), a.Ident[0])
				}
			case *parse.PipeNode:
				checkTemplatePipe(a, dot, root, report)
			case *parse.ChainNode:
				if inner, ok := a.Node.(*parse.PipeNode); ok {
					checkTemplatePipe(inner, dot, root, report)
				}
			}
		}
	}
}

// isStructLike reports a struct or a pointer to one: a type whose fields
// are known.
func isStructLike(t types.Type) bool {
	if ptr, ok := t.Underlying().(*types.Pointer); ok {
		t = ptr.Elem()
	}
	_, ok := t.Underlying().(*types.Struct)
	return ok
}

// templateMember returns the type of the field or the first result of the
// method name of t, nil when t has none.
func templateMember(t types.Type, name string) types.Type {
	if t == nil {
		return nil
	}
	if m, ok := t.Underlying().(*types.Map); ok {
		return m.Elem()
	}
	obj, _, _ := types.LookupFieldOrMethod(t, true, nil, name)
	switch o := obj.(type) {
	case *types.Var:
		return o.Type()
	case *types.Func:
		if sig, ok := o.Type().(*types.Signature); ok && sig.Results().Len() > 0 {
			return sig.Results().At(0).Type()
		}
	}
	return nil
}

// templatePipeType returns the type a pipeline of one field chain, $ chain or
// dot yields, nil for anything else.
func templatePipeType(pipe *parse.PipeNode, dot, root types.Type) types.Type {
	if pipe == nil || len(pipe.Cmds) != 1 || len(pipe.Cmds[0].Args) != 1 {
		return nil
	}
	chain := func(t types.Type, idents []string) types.Type {
		for _, ident := range idents {
			t = templateMember(t, ident)
		}
		return t
	}
	switch a := pipe.Cmds[0].Args[0].(type) {
	case *parse.FieldNode:
		return chain(dot, a.Ident)
	case *parse.VariableNode:
		if a.Ident[0] == "$" {
			return chain(root, a.Ident[1:])
		}
	case *parse.DotNode:
		return dot
	}
	return nil
}

// elementType returns what a range over t yields, nil when unknown.
func elementType(t types.Type) types.Type {
	if t == nil {
		return nil
	}
	if ptr, ok := t.Underlying().(*types.Pointer); ok {
		t = ptr.Elem()
	}
	switch u := t.Underlying().(type) {
	case *types.Slice:
		return u.Elem()
	case *types.Array:
		return u.Elem()
	case *types.Map:
		return u.Elem()
	case *types.Chan:
		return u.Elem()
	}
	return nil
}

// templateDataTypes maps the base name of a template file to the struct
// types the Go code renders into it: render(w, "list.html", ListPage{...}).
func templateDataTypes(ctx *core.GoProjectContext) map[string][]types.Type {
	bound := make(map[string][]types.Type)
	for _, src := range runGoFilesAll(ctx) {
		info := src.pkg.Package.TypesInfo
		ast.Inspect(src.file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			for i, arg := range call.Args {
				name, ok := stringLiteral(arg)
				if !ok || !core.IsTemplateName(name) {
					continue
				}
				for _, data := range call.Args[i+1:] {
					t := info.TypeOf(data)
					if t == nil || namedStruct(t) == "" {
						continue
					}
					base := filepath.Base(name)
					if !containsType(bound[base], t) {
						bound[base] = append(bound[base], t)
					}
					break
				}
			}
			return true
		})
	}
	return bound
}

// runGoFilesAll returns every Go file of the typed packages: what renders a
// template need not be among the analyzed files.
func runGoFilesAll(ctx *core.GoProjectContext) []goSource {
	var out []goSource
	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil || pkg.Package.TypesInfo == nil {
			continue
		}
		for _, file := range pkg.Package.Syntax {
			out = append(out, goSource{file: file, path: pkg.Package.Fset.Position(file.Pos()).Filename, pkg: pkg})
		}
	}
	return out
}

// containsType reports a type identical to t in the list.
func containsType(list []types.Type, t types.Type) bool {
	for _, other := range list {
		if types.Identical(other, t) {
			return true
		}
	}
	return false
}

// templateDefine matches {{define "name"}}.
var templateDefine = regexp.MustCompile(`\{\{-?\s*define\s+"([^"]+)"`)

// parseCalls are the template constructors that load several files into one
// set; the patterns start after patternsAt arguments.
var parseCalls = map[string]int{"ParseFS": 1, "ParseGlob": 0, "ParseFiles": 0}

// NewGoTemplateDefineCollisionInSharedSetRule creates go-template-define-collision-in-shared-set:
// one template set parsed from files that {{define}} the same name - the
// last parsed wins, and every page renders that file's body:
//
//	tmpl, err := template.New("").ParseFS(fs, "templates/*.html") // each page defines "content"
func NewGoTemplateDefineCollisionInSharedSetRule() *templateProjectRule {
	r := &templateProjectRule{
		BaseRule: rules.NewBaseRule(
			"go-template-define-collision-in-shared-set",
			"patterns",
			"Detects a ParseFS, ParseGlob or ParseFiles call loading two or more files that {{define}} the same name into one template set — the last parsed wins for every page",
			core.SeverityHigh,
		),
		suggestion: "Parse each page into its own set (Clone the shared layout and add the page), or give each page's block its own name",
	}
	r.analyze = func(ctx *core.GoProjectContext) ([]projectFinding, error) {
		var findings []projectFinding
		for _, src := range runGoFiles(ctx) {
			info := src.pkg.Package.TypesInfo
			var failure error
			ast.Inspect(src.file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || failure != nil {
					return failure == nil
				}
				fn := staticFunc(info, call)
				at, isParse := parseCalls[callName(call)]
				if fn == nil || fn.Pkg() == nil || !isParse || (fn.Pkg().Path() != "html/template" && fn.Pkg().Path() != "text/template") {
					return true
				}
				files, err := matchedTemplateFiles(filepath.Dir(src.path), ctx.ProjectRoot, call.Args[min(at, len(call.Args)):])
				if err != nil {
					failure = err
					return false
				}
				name, defining, err := sharedDefine(files)
				if err != nil {
					failure = err
					return false
				}
				if name != "" {
					findings = append(findings, projectFinding{path: src.path, line: src.line(call), message: fmt.Sprintf(
						"%q is defined by %s parsed into one set — the last parsed wins and every page renders its body", name, strings.Join(defining, " and "))})
				}
				return true
			})
			if failure != nil {
				return nil, failure
			}
		}
		return findings, nil
	}
	return r
}

// matchedTemplateFiles returns the files the literal patterns match, against
// the Go file's directory (embed paths) or, failing that, the project root.
func matchedTemplateFiles(dir, root string, patterns []ast.Expr) ([]string, error) {
	var files []string
	for _, expr := range patterns {
		pattern, ok := stringLiteral(expr)
		if !ok {
			continue
		}
		for _, base := range []string{dir, root} {
			matches, err := filepath.Glob(filepath.Join(base, pattern))
			if err != nil {
				return nil, fmt.Errorf("match template pattern %q: %w", pattern, err)
			}
			if len(matches) > 0 {
				files = append(files, matches...)
				break
			}
		}
	}
	return files, nil
}

// sharedDefine returns a name two or more of the files define, with the
// files that do.
func sharedDefine(files []string) (string, []string, error) {
	definers := make(map[string][]string)
	for _, path := range files {
		info, err := os.Stat(path)
		if err != nil {
			return "", nil, fmt.Errorf("read template %s: %w", path, err)
		}
		if info.IsDir() {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return "", nil, fmt.Errorf("read template %s: %w", path, err)
		}
		seen := make(map[string]bool)
		for _, m := range templateDefine.FindAllStringSubmatch(string(data), -1) {
			if !seen[m[1]] {
				seen[m[1]] = true
				definers[m[1]] = append(definers[m[1]], filepath.Base(path))
			}
		}
	}
	names := make([]string, 0, len(definers))
	for name, defining := range definers {
		if len(defining) > 1 {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return "", nil, nil
	}
	sort.Strings(names)
	return names[0], definers[names[0]], nil
}

var (
	scriptBlock  = regexp.MustCompile(`(?is)<script\b[^>]*>(.*?)</script>`)
	scriptAction = regexp.MustCompile(`\{\{-?\s*\$?\.([\w.]+)\s*-?\}\}`)
)

// NewGoTemplateJSONStringInScriptContextRule creates go-template-json-string-in-script-context:
// a string field holding JSON interpolated as a bare value inside <script>:
// html/template escapes a string there as a JS string literal, and the
// script gets "{\"a\":1}" where it expected an object:
//
//	PairsJSON string                     // json.Marshal output
//	const pairs = {{.PairsJSON}};        // a string, not an object
func NewGoTemplateJSONStringInScriptContextRule() *templateProjectRule {
	r := &templateProjectRule{
		BaseRule: rules.NewBaseRule(
			"go-template-json-string-in-script-context",
			"patterns",
			"Detects a string field named for JSON that a template interpolates as a bare value inside <script> — html/template quotes it, and the script gets a string instead of the object",
			core.SeverityMedium,
		),
		suggestion: "Pass the value itself (html/template encodes it as JSON in a script), or type the field template.JS",
	}
	r.analyze = func(ctx *core.GoProjectContext) ([]projectFinding, error) {
		templates, err := runTemplatesAll(ctx)
		if err != nil {
			return nil, err
		}
		bare := make(map[string]string)
		for _, tmpl := range templates {
			for _, block := range scriptBlock.FindAllStringSubmatchIndex(tmpl, -1) {
				script := tmpl[block[2]:block[3]]
				for _, m := range scriptAction.FindAllStringSubmatchIndex(script, -1) {
					if quoted(script, m[0]) {
						continue
					}
					chain := strings.Split(script[m[2]:m[3]], ".")
					bare[chain[len(chain)-1]] = script[m[0]:m[1]]
				}
			}
		}
		if len(bare) == 0 {
			return nil, nil
		}
		var findings []projectFinding
		for _, src := range runGoFiles(ctx) {
			info := src.pkg.Package.TypesInfo
			ast.Inspect(src.file, func(n ast.Node) bool {
				field, ok := n.(*ast.Field)
				if !ok {
					return true
				}
				for _, name := range field.Names {
					words := helpers.IdentifierWords(name.Name)
					use, interpolated := bare[name.Name]
					if !interpolated || len(words) == 0 || words[len(words)-1] != "json" {
						continue
					}
					if basic, ok := info.TypeOf(field.Type).(*types.Basic); ok && basic.Kind() == types.String {
						findings = append(findings, projectFinding{path: src.path, line: src.line(name), message: fmt.Sprintf(
							"%s holds JSON as a string and a template puts it in a script as %s — html/template quotes a string there, and the script gets a string instead of the object", name.Name, use)})
					}
				}
				return true
			})
		}
		return findings, nil
	}
	return r
}

// runTemplatesAll returns the text of every template file under the project
// root, analyzed by the run or not: a Go field is checked against all of them.
func runTemplatesAll(ctx *core.GoProjectContext) ([]string, error) {
	paths, err := templateFiles(ctx.ProjectRoot)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(paths))
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		out = append(out, string(data))
	}
	return out, nil
}

// quoted reports an offset preceded, on its line, by an odd number of one
// kind of quote: inside a JS string literal.
func quoted(script string, at int) bool {
	start := strings.LastIndex(script[:at], "\n") + 1
	before := script[start:at]
	for _, q := range []string{`"`, `'`, "`"} {
		if strings.Count(before, q)%2 == 1 {
			return true
		}
	}
	return false
}

// RelativeFetchURLRule detects a relative URL a page's script or htmx
// attribute requests: it resolves against the page's own path, so a page
// served at /orders/new asking for 'options' reaches /orders/options.
type RelativeFetchURLRule struct {
	*rules.BaseRule
}

// NewRelativeFetchURLResolvesAgainstPagePathRule creates relative-fetch-url-resolves-against-page-path.
func NewRelativeFetchURLResolvesAgainstPagePathRule() *RelativeFetchURLRule {
	return &RelativeFetchURLRule{BaseRule: rules.NewBaseRule(
		"relative-fetch-url-resolves-against-page-path",
		"patterns",
		"Detects a bare relative URL (no leading /) passed to a fetch call or an hx-get/hx-post attribute in a template — it resolves against the page's path, not the application root",
		core.SeverityMedium,
	)}
}

var (
	htmxRequest  = regexp.MustCompile(`\bhx-(?:get|post|put|patch|delete)\s*=\s*["']([^"']*)["']`)
	fetchCallee  = regexp.MustCompile(`(?i)\b[\w$.]*fetch\w*\s*\(`)
	relativePath = regexp.MustCompile(`^[a-z][a-z0-9_-]*(?:/[a-z0-9_.{}-]*)*$`)
)

// AnalyzeFile reports the relative request URLs of a template.
func (r *RelativeFetchURLRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsTemplate() {
		return nil
	}
	text := string(ctx.Content)
	var lines []int
	for _, m := range htmxRequest.FindAllStringSubmatchIndex(text, -1) {
		if relativePath.MatchString(text[m[2]:m[3]]) {
			lines = append(lines, strings.Count(text[:m[0]], "\n")+1)
		}
	}
	for _, block := range scriptBlock.FindAllStringSubmatchIndex(text, -1) {
		for _, call := range fetchCallee.FindAllStringIndex(text[block[2]:block[3]], -1) {
			open := block[2] + call[1]
			for _, lit := range topLevelStrings(text, open) {
				if relativePath.MatchString(lit.value) {
					lines = append(lines, strings.Count(text[:lit.at], "\n")+1)
				}
			}
		}
	}
	sort.Ints(lines)
	var violations []*core.Violation
	for i, line := range lines {
		if (i > 0 && lines[i-1] == line) || ctx.IsSuppressed(line, r.Name()) {
			continue
		}
		v := r.CreateViolation(ctx.RelPath, line, "The request URL is relative — it resolves against the page's path, so on a nested route it reaches another endpoint")
		v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
		v.WithSuggestion("Start the URL with / (or build it from the page's base path)")
		violations = append(violations, v)
	}
	return violations
}

// stringAt is a string literal of a script and its offset.
type stringAt struct {
	value string
	at    int
}

// topLevelStrings returns the string literals among the arguments of a call
// whose parenthesis opens at open, outside nested calls, arrays and objects.
func topLevelStrings(text string, open int) []stringAt {
	var out []stringAt
	depth := 1
	for i := open; i < len(text) && depth > 0; i++ {
		switch c := text[i]; c {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case '\'', '"', '`':
			end := strings.IndexByte(text[i+1:], c)
			if end < 0 {
				return out
			}
			if depth == 1 {
				out = append(out, stringAt{value: text[i+1 : i+1+end], at: i})
			}
			i += end + 1
		}
	}
	return out
}

var (
	translationKey  = regexp.MustCompile(`^[a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+$`)
	templateAction  = regexp.MustCompile(`\{\{(.*?)\}\}`)
	translateInTmpl = regexp.MustCompile(`(?:^|[\s(|])(?:t|T|tr|translate)\s+(?:[$.\w]+\s+)*"([^"]+)"`)
)

// translateFuncs are the names of the functions that look a key up.
var translateFuncs = map[string]bool{"t": true, "T": true, "tr": true, "translate": true, "Translate": true}

// minTranslationKeys is how many dotted keys a map needs to count as a
// language's messages.
const minTranslationKeys = 8

// messageMap is the message map of one language.
type messageMap struct {
	name string
	keys map[string]int // key -> line
	path string
	pkg  string
}

// NewI18nKeyUsedButNotDefinedRule creates i18n-key-used-but-not-defined: a
// key a template or a handler translates that a language's message map
// lacks, or a key one language has and another lacks - the page shows the
// raw key:
//
//	{{t .Lang "fx.status"}}       // no "fx.status" in var en = map[string]string{...}
func NewI18nKeyUsedButNotDefinedRule() *templateProjectRule {
	r := &templateProjectRule{
		BaseRule: rules.NewBaseRule(
			"i18n-key-used-but-not-defined",
			"patterns",
			"Detects a translation key used in a template or in Go that a language's message map lacks, and a key one language map has and another lacks — the page shows the raw key",
			core.SeverityMedium,
		),
		suggestion: "Add the key to every language map",
	}
	r.analyze = func(ctx *core.GoProjectContext) ([]projectFinding, error) {
		maps := messageMaps(ctx)
		if len(maps) == 0 {
			return nil, nil
		}
		namespaces := make(map[string]bool)
		for _, m := range maps {
			for key := range m.keys {
				namespaces[strings.SplitN(key, ".", 2)[0]] = true
			}
		}
		missing := func(key string) []string {
			if !translationKey.MatchString(key) || !namespaces[strings.SplitN(key, ".", 2)[0]] {
				return nil
			}
			var lacking []string
			for _, m := range maps {
				if _, ok := m.keys[key]; !ok {
					lacking = append(lacking, m.name)
				}
			}
			return lacking
		}
		var findings []projectFinding
		report := func(path string, line int, key string) {
			if lacking := missing(key); len(lacking) > 0 {
				findings = append(findings, projectFinding{path: path, line: line, message: fmt.Sprintf(
					"The translation key %q is missing from %s — the page shows the raw key", key, strings.Join(lacking, ", "))})
			}
		}
		findings = append(findings, unevenMessageMaps(maps)...)
		templates, err := runTemplates(ctx)
		if err != nil {
			return nil, err
		}
		for _, tmpl := range templates {
			for _, action := range templateAction.FindAllStringSubmatchIndex(tmpl.text, -1) {
				for _, m := range translateInTmpl.FindAllStringSubmatch(tmpl.text[action[2]:action[3]], -1) {
					report(tmpl.file.Path, strings.Count(tmpl.text[:action[0]], "\n")+1, m[1])
				}
			}
		}
		for _, src := range runGoFiles(ctx) {
			ast.Inspect(src.file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || !translateFuncs[callName(call)] {
					return true
				}
				for _, arg := range call.Args {
					if key, ok := stringLiteral(arg); ok {
						report(src.path, src.line(arg), key)
					}
				}
				return true
			})
		}
		return dedupeFindings(findings), nil
	}
	return r
}

// messageMaps returns the package-level map[string]string literals of the
// run whose keys are mostly dotted message keys.
func messageMaps(ctx *core.GoProjectContext) []messageMap {
	var maps []messageMap
	for _, src := range runGoFiles(ctx) {
		info := src.pkg.Package.TypesInfo
		for _, decl := range src.file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.VAR {
				continue
			}
			for _, spec := range gen.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok || len(vs.Names) != 1 || len(vs.Values) != 1 {
					continue
				}
				lit, ok := vs.Values[0].(*ast.CompositeLit)
				if !ok || !isStringMap(info.TypeOf(lit)) {
					continue
				}
				m := messageMap{name: vs.Names[0].Name, keys: make(map[string]int), path: src.path, pkg: src.pkg.Package.PkgPath}
				for _, elt := range lit.Elts {
					kv, ok := elt.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					if key, ok := stringLiteral(kv.Key); ok && translationKey.MatchString(key) {
						m.keys[key] = src.line(kv)
					}
				}
				if len(m.keys) >= minTranslationKeys && len(m.keys)*5 >= len(lit.Elts)*4 {
					maps = append(maps, m)
				}
			}
		}
	}
	sort.Slice(maps, func(i, j int) bool { return maps[i].name < maps[j].name })
	return maps
}

// unevenMessageMaps reports a key that one language map of a package has and
// a sibling lacks, at the entry of the first map that has it.
func unevenMessageMaps(maps []messageMap) []projectFinding {
	byPkg := make(map[string][]messageMap)
	for _, m := range maps {
		byPkg[m.pkg] = append(byPkg[m.pkg], m)
	}
	var findings []projectFinding
	for _, pkg := range sortedKeys(byPkg) {
		group := byPkg[pkg]
		keys := make(map[string]bool)
		for _, m := range group {
			for key := range m.keys {
				keys[key] = true
			}
		}
		for _, key := range sortedKeys(keys) {
			var having, lacking []messageMap
			for _, m := range group {
				if _, ok := m.keys[key]; ok {
					having = append(having, m)
				} else {
					lacking = append(lacking, m)
				}
			}
			if len(lacking) > 0 {
				findings = append(findings, projectFinding{path: having[0].path, line: having[0].keys[key], message: fmt.Sprintf(
					"The translation key %q is in %s but missing from %s — that language shows the raw key", key, having[0].name, lacking[0].name)})
			}
		}
	}
	return findings
}

// isStringMap reports map[string]string.
func isStringMap(t types.Type) bool {
	if t == nil {
		return false
	}
	m, ok := t.Underlying().(*types.Map)
	if !ok {
		return false
	}
	key, keyOK := m.Key().Underlying().(*types.Basic)
	elem, elemOK := m.Elem().Underlying().(*types.Basic)
	return keyOK && elemOK && key.Kind() == types.String && elem.Kind() == types.String
}

// dedupeFindings keeps one finding per file and line.
func dedupeFindings(findings []projectFinding) []projectFinding {
	seen := make(map[string]bool)
	var out []projectFinding
	for _, f := range findings {
		key := fmt.Sprintf("%s:%d", f.path, f.line)
		if !seen[key] {
			seen[key] = true
			out = append(out, f)
		}
	}
	return out
}

// HtmxSwapTargetRule detects an hx-get that swaps only the list of a page
// while the count and the pagination of that list live outside the target:
// after the request they still show the first load.
type HtmxSwapTargetRule struct {
	*rules.BaseRule
}

// NewHtmxSwapTargetExcludesDependentFragmentRule creates htmx-swap-target-excludes-dependent-fragment.
func NewHtmxSwapTargetExcludesDependentFragmentRule() *HtmxSwapTargetRule {
	return &HtmxSwapTargetRule{BaseRule: rules.NewBaseRule(
		"htmx-swap-target-excludes-dependent-fragment",
		"patterns",
		"Detects an hx-get whose target holds a list ({{range}} or {{template}}) while the same template shows the list's total or pages outside the target — the swap leaves them stale",
		core.SeverityMedium,
	)}
}

var (
	htmxGetTag   = regexp.MustCompile(`<[a-zA-Z][^>]*\bhx-get\s*=[^>]*>`)
	htmxTargetID = regexp.MustCompile(`\bhx-target\s*=\s*["']#([\w-]+)["']`)
	listCounter  = regexp.MustCompile(`\{\{[^}]*\$?\.((?:\w+\.)*\w*(?:Total|Page|Pages|Count)\w*)\b[^}]*\}\}`)
)

// AnalyzeFile reports the hx-get elements of a template that swap a list
// apart from its counters.
func (r *HtmxSwapTargetRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsTemplate() {
		return nil
	}
	text := string(ctx.Content)
	var violations []*core.Violation
	for _, tag := range htmxGetTag.FindAllStringIndex(text, -1) {
		open := text[tag[0]:tag[1]]
		m := htmxTargetID.FindStringSubmatch(open)
		if m == nil || strings.Contains(open, "hx-select") {
			continue
		}
		start, end := elementByID(text, m[1])
		if start < 0 || !rendersList(text[start:end]) {
			continue
		}
		counter := ""
		for _, c := range listCounter.FindAllStringSubmatchIndex(text, -1) {
			if c[1] <= start || c[0] >= end {
				counter = text[c[2]:c[3]]
				break
			}
		}
		line := strings.Count(text[:tag[0]], "\n") + 1
		if counter == "" || ctx.IsSuppressed(line, r.Name()) {
			continue
		}
		v := r.CreateViolation(ctx.RelPath, line, fmt.Sprintf(
			"The request swaps only #%s, the list, while .%s of that list is rendered outside it — after the request it still shows the first load", m[1], counter))
		v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
		v.WithSuggestion("Target the element that holds the list with its total and pagination, or update them out of band (hx-swap-oob)")
		violations = append(violations, v)
	}
	return violations
}

// rendersList reports an element that renders a list: a {{range}} or a
// {{template}} of the rows.
func rendersList(element string) bool {
	return strings.Contains(element, "{{range") || strings.Contains(element, "{{template")
}

// elementByID returns the byte range of the element with the id, from its
// opening tag to the end of its closing tag; -1 when the file has none.
func elementByID(text, id string) (int, int) {
	idAttr := regexp.MustCompile(`<([a-zA-Z][\w-]*)\b[^>]*\bid\s*=\s*["']` + regexp.QuoteMeta(id) + `["'][^>]*>`)
	loc := idAttr.FindStringSubmatchIndex(text)
	if loc == nil {
		return -1, -1
	}
	name := text[loc[2]:loc[3]]
	tags := regexp.MustCompile(`(?i)<(/?)` + regexp.QuoteMeta(name) + `\b[^>]*>`)
	depth := 0
	for _, t := range tags.FindAllStringSubmatchIndex(text[loc[0]:], -1) {
		if t[3] > t[2] {
			depth--
		} else {
			depth++
		}
		if depth == 0 {
			return loc[0], loc[0] + t[1]
		}
	}
	return loc[0], len(text)
}
