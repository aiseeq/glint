package concurrencyrules

import (
	"go/ast"
	"go/constant"
	"go/types"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
)

func init() {
	rules.Register(NewRegexpCompileInLoopRule())
}

// NewRegexpCompileInLoopRule detects regexp package functions that compile a
// constant pattern repeatedly in a loop or a function marked //glint:hot.
func NewRegexpCompileInLoopRule() *RegexpCompileInLoopRule {
	return &RegexpCompileInLoopRule{BaseRule: rules.NewBaseRule(
		"regexp-compile-in-loop",
		"patterns",
		"Detects a constant regexp pattern compiled on every loop iteration or call in a //glint:hot function",
		core.SeverityLow,
	)}
}

// RegexpCompileInLoopRule reports constant patterns compiled repeatedly in
// loop bodies and hot functions.
type RegexpCompileInLoopRule struct {
	rules.GoFileFindingRule
	*rules.BaseRule
}

// AnalyzeFile is a no-op because regexp calls need type information.
func (r *RegexpCompileInLoopRule) AnalyzeFile(_ *core.FileContext) []*core.Violation { return nil }

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *RegexpCompileInLoopRule) RequiresSSA() bool { return false }

// AnalyzeGoProject checks each selected non-test Go file using its types info.
func (r *RegexpCompileInLoopRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	return rules.AnalyzeTypedRunFiles(ctx, r.Name(), func(file *core.FileContext, info *types.Info) []*core.Violation {
		if file.IsTestFile() {
			return nil
		}
		return regexpCompileFindings(r, file, info)
	})
}

func regexpCompileFindings(rule *RegexpCompileInLoopRule, file *core.FileContext, info *types.Info) []*core.Violation {
	var findings []*core.Violation
	var walk func(ast.Node, int, bool)
	walk = func(node ast.Node, loopDepth int, hot bool) {
		if node == nil {
			return
		}
		ast.Inspect(node, func(n ast.Node) bool {
			if n == nil {
				return false
			}
			switch x := n.(type) {
			case *ast.FuncLit:
				if n != node {
					// A function literal outside a call argument is its own
					// context. Calls below walk their function literals according
					// to how the call executes them.
					walk(x.Body, 0, false)
					return false
				}
			case *ast.ForStmt:
				walk(x.Init, loopDepth, hot)
				walk(x.Cond, loopDepth+1, hot)
				walk(x.Post, loopDepth+1, hot)
				walk(x.Body, loopDepth+1, hot)
				return false
			case *ast.RangeStmt:
				walk(x.X, loopDepth, hot)
				walk(x.Body, loopDepth+1, hot)
				return false
			case *ast.CallExpr:
				if lit, ok := ast.Unparen(x.Fun).(*ast.FuncLit); ok {
					walk(lit.Body, loopDepth, hot)
				} else if regexpCall(info, x) && (loopDepth > 0 || hot) && constantRegexpPattern(info, x) {
					line := file.LineFor(x)
					message := "constant regexp pattern is compiled on every loop iteration or hot function call"
					v := rule.CreateViolation(file.RelPath, line, message)
					v.WithCode(file.GetLine(line))
					v.WithSuggestion("Move the pattern to a package variable, for example var xRe = regexp.MustCompile(\"...\")")
					findings = append(findings, v)
				}
				// Walk call children explicitly: arguments are evaluated where the
				// call is, and a callback literal inherits the loop only when the
				// callee runs it during the call.
				if _, ok := ast.Unparen(x.Fun).(*ast.FuncLit); !ok {
					walk(x.Fun, loopDepth, hot)
				}
				runsCallback := callbackRunsInCall(info, x)
				for _, arg := range x.Args {
					lit, ok := ast.Unparen(arg).(*ast.FuncLit)
					switch {
					case !ok:
						walk(arg, loopDepth, hot)
					case runsCallback:
						walk(lit.Body, loopDepth, hot)
					default:
						walk(lit.Body, 0, false)
					}
				}
				return false
			}
			return true
		})
	}
	for _, decl := range file.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		walk(fn.Body, 0, patternkit.HasDirective(fn.Doc, patternkit.HotFunctionDirective))
	}
	return findings
}

// callbackPackages run a function argument during the call (strings.FieldsFunc,
// sort.Slice, slices.SortFunc, filepath.WalkDir) or, for sync.OnceValue and
// its kin, make a new Once each time they are called. A callee from elsewhere
// may store the callback (http.HandleFunc) or run it only on a cache miss.
var callbackPackages = map[string]bool{
	"bytes": true, "io/fs": true, "maps": true, "path/filepath": true,
	"regexp": true, "slices": true, "sort": true, "strings": true, "sync": true,
}

// callbackRunsInCall reports whether a function literal passed to call runs on
// each execution of the call. sync.Once.Do runs it at most once per Once.
func callbackRunsInCall(info *types.Info, call *ast.CallExpr) bool {
	var ident *ast.Ident
	switch fun := ast.Unparen(call.Fun).(type) {
	case *ast.Ident:
		ident = fun
	case *ast.SelectorExpr:
		ident = fun.Sel
	}
	if ident == nil {
		return false
	}
	fn, _ := info.Uses[ident].(*types.Func)
	if fn == nil || fn.Pkg() == nil || !callbackPackages[fn.Pkg().Path()] {
		return false
	}
	return fn.Pkg().Path() != "sync" || fn.Name() != "Do"
}

func regexpCall(info *types.Info, call *ast.CallExpr) bool {
	var fn *types.Func
	switch fun := ast.Unparen(call.Fun).(type) {
	case *ast.SelectorExpr:
		fn, _ = info.Uses[fun.Sel].(*types.Func)
	case *ast.Ident:
		fn, _ = info.Uses[fun].(*types.Func)
	}
	if fn == nil || fn.Pkg() == nil || fn.Pkg().Path() != "regexp" {
		return false
	}
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Recv() != nil {
		return false
	}
	switch fn.Name() {
	case "MustCompile", "Compile", "MustCompilePOSIX", "CompilePOSIX", "MatchString", "Match", "MatchReader":
		return len(call.Args) > 0
	default:
		return false
	}
}

func constantRegexpPattern(info *types.Info, call *ast.CallExpr) bool {
	value := info.Types[call.Args[0]].Value
	return value != nil && value.Kind() == constant.String
}
