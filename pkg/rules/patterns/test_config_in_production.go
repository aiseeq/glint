package patterns

import (
	"go/ast"
	"go/types"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewTestConfigInProductionRule())
}

// TestConfigInProductionRule detects production code calling a getter whose
// name speaks of a general setting while its body returns the value
// configured for tests:
//
//	func (c *Config) GetStandardOperationTimeout() time.Duration { return c.Timeouts.Test.StandardOperation }
//	recoveryTimeout = cfg.GetStandardOperationTimeout() // a 2s test timeout cuts production requests
//
// The getter's name hides where the value comes from, and the server runs
// with the limits written for tests. A call through an interface is matched
// with the implementations of the project. A getter named for tests
// (TestOperationTimeout) is what it says and is not reported.
type TestConfigInProductionRule struct {
	*rules.BaseRule
}

// NewTestConfigInProductionRule creates the rule
func NewTestConfigInProductionRule() *TestConfigInProductionRule {
	return &TestConfigInProductionRule{BaseRule: rules.NewBaseRule(
		"test-config-in-production",
		"patterns",
		"Detects production code calling a getter that returns a value of the test section of the configuration under a general name",
		core.SeverityHigh,
	)}
}

// AnalyzeFile is a no-op: the getter may be declared in another package.
func (r *TestConfigInProductionRule) AnalyzeFile(_ *core.FileContext) []*core.Violation { return nil }

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *TestConfigInProductionRule) RequiresSSA() bool { return false }

// testConfigGetter is a method returning a value of a test section.
type testConfigGetter struct {
	fn   *types.Func
	path string // the selector it returns, c.Timeouts.Test.StandardOperation
}

// AnalyzeGoProject reports the production calls of test-config getters.
func (r *TestConfigInProductionRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	getters := make(map[string][]testConfigGetter) // by method name
	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil || pkg.Package.TypesInfo == nil {
			continue
		}
		for _, file := range pkg.Files {
			if file.GoAST == nil || file.IsTestFile() {
				continue
			}
			for _, getter := range testConfigGetters(file.GoAST, pkg.Package.TypesInfo) {
				getters[getter.fn.Name()] = append(getters[getter.fn.Name()], getter)
			}
		}
	}
	if len(getters) == 0 {
		return nil, nil
	}
	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(file *core.FileContext, info *types.Info) []*core.Violation {
		var violations []*core.Violation
		ast.Inspect(file.GoAST, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			callee, ok := info.Uses[sel.Sel].(*types.Func)
			if !ok {
				return true
			}
			getter, found := calledTestGetter(callee, getters[callee.Name()])
			if !found {
				return true
			}
			line := file.LineFor(call)
			if file.IsSuppressed(line, r.Name()) {
				return true
			}
			v := r.CreateViolation(file.RelPath, line, callee.Name()+" returns "+getter.path+
				" — production code runs with the value configured for tests")
			v.WithCode(strings.TrimSpace(file.GetLine(line)))
			v.WithSuggestion("Read the production setting meant here, or name the getter for tests and keep it out of production code")
			violations = append(violations, v)
			return true
		})
		return violations
	})
}

// testConfigGetters returns the methods of a file, not named for tests,
// whose body only returns a selector through a field named Test or Tests.
func testConfigGetters(file *ast.File, info *types.Info) []testConfigGetter {
	var getters []testConfigGetter
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv == nil || fn.Body == nil || len(fn.Body.List) != 1 || strings.Contains(fn.Name.Name, "Test") {
			continue
		}
		ret, ok := fn.Body.List[0].(*ast.ReturnStmt)
		if !ok || len(ret.Results) != 1 || !throughTestSection(ret.Results[0]) {
			continue
		}
		obj, ok := info.Defs[fn.Name].(*types.Func)
		if !ok {
			continue
		}
		getters = append(getters, testConfigGetter{fn: obj, path: types.ExprString(ret.Results[0])})
	}
	return getters
}

// throughTestSection reports a selector chain with a field named Test or
// Tests on the way: c.Timeouts.Test.StandardOperation.
func throughTestSection(expr ast.Expr) bool {
	for {
		sel, ok := ast.Unparen(expr).(*ast.SelectorExpr)
		if !ok {
			return false
		}
		inner, isSelector := ast.Unparen(sel.X).(*ast.SelectorExpr)
		if isSelector && (inner.Sel.Name == "Test" || inner.Sel.Name == "Tests") {
			return true
		}
		expr = sel.X
	}
}

// calledTestGetter returns the getter a call reaches: the method itself, or
// an implementation of the interface method called.
func calledTestGetter(callee *types.Func, candidates []testConfigGetter) (testConfigGetter, bool) {
	sig, ok := callee.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return testConfigGetter{}, false
	}
	iface, isInterface := sig.Recv().Type().Underlying().(*types.Interface)
	for _, getter := range candidates {
		if getter.fn == callee {
			return getter, true
		}
		if !isInterface {
			continue
		}
		getterSig, ok := getter.fn.Type().(*types.Signature)
		if !ok {
			continue
		}
		recv := getterSig.Recv()
		if recv != nil && (types.Implements(recv.Type(), iface) || types.Implements(types.NewPointer(recv.Type()), iface)) {
			return getter, true
		}
	}
	return testConfigGetter{}, false
}
