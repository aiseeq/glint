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
			if n != node {
				switch x := n.(type) {
				case *ast.FuncLit:
					// A function literal runs when it is called, not where it is
					// written: sync.Once.Do(func(){…}) in a loop compiles once.
					// One called on the spot is walked with its call below.
					walk(x.Body, 0, false)
					return false
				case *ast.ForStmt:
					walk(x.Init, loopDepth, hot)
					walk(x.Cond, loopDepth, hot)
					walk(x.Post, loopDepth, hot)
					walk(x.Body, loopDepth+1, hot)
					return false
				case *ast.RangeStmt:
					walk(x.X, loopDepth, hot)
					walk(x.Body, loopDepth+1, hot)
					return false
				case *ast.CallExpr:
					if lit, ok := ast.Unparen(x.Fun).(*ast.FuncLit); ok {
						walk(lit.Body, loopDepth, hot)
						for _, arg := range x.Args {
							walk(arg, loopDepth, hot)
						}
						return false
					}
					if regexpCall(info, x) && (loopDepth > 0 || hot) && constantRegexpPattern(info, x) {
						line := file.LineFor(x)
						message := "constant regexp pattern is compiled on every loop iteration or hot function call"
						v := rule.CreateViolation(file.RelPath, line, message)
						v.WithCode(file.GetLine(line))
						v.WithSuggestion("Move the pattern to a package variable, for example var xRe = regexp.MustCompile(\"...\")")
						findings = append(findings, v)
					}
				}
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
