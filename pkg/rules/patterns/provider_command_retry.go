package patterns

import (
	"go/ast"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

var retryCallbackMethods = map[string]bool{
	"Retry":       true,
	"WithRetry":   true,
	"DoWithRetry": true,
}

func init() {
	rules.Register(NewProviderCommandRetryRule())
}

// ProviderCommandRetryRule detects automatic retries of destructive provider commands.
type ProviderCommandRetryRule struct {
	*rules.BaseRule
}

// NewProviderCommandRetryRule creates the rule.
func NewProviderCommandRetryRule() *ProviderCommandRetryRule {
	return &ProviderCommandRetryRule{BaseRule: rules.NewBaseRule(
		"provider-command-retry",
		"patterns",
		"Detects destructive provider commands executed with automatic retry",
		core.SeverityCritical,
	)}
}

type providerCommandRetryAnalyzer struct {
	rule          *ProviderCommandRetryRule
	ctx           *core.FileContext
	retryParams   map[string][]int
	reportedCalls map[*ast.CallExpr]bool
	violations    []*core.Violation
}

// AnalyzeFile checks same-file helper signatures, retry callbacks, and loops.
func (r *ProviderCommandRetryRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || ctx.IsTestFile() || ctx.GoAST == nil {
		return nil
	}

	analyzer := &providerCommandRetryAnalyzer{
		rule:          r,
		ctx:           ctx,
		retryParams:   collectRetryBoolParameters(ctx.GoAST),
		reportedCalls: make(map[*ast.CallExpr]bool),
	}
	for _, declaration := range ctx.GoAST.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Body == nil {
			continue
		}
		analyzer.analyzeFunction(function)
	}
	return analyzer.violations
}

func collectRetryBoolParameters(file *ast.File) map[string][]int {
	declarationCounts := make(map[string]int)
	for _, declaration := range file.Decls {
		if function, ok := declaration.(*ast.FuncDecl); ok {
			declarationCounts[function.Name.Name]++
		}
	}

	parameters := make(map[string][]int)
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Type.Params == nil || declarationCounts[function.Name.Name] != 1 {
			continue
		}
		position := 0
		for _, field := range function.Type.Params.List {
			count := len(field.Names)
			if count == 0 {
				count = 1
			}
			if ident, ok := field.Type.(*ast.Ident); ok && ident.Name == "bool" {
				for index, name := range field.Names {
					if strings.Contains(strings.ToLower(name.Name), "retry") {
						parameters[function.Name.Name] = append(parameters[function.Name.Name], position+index)
					}
				}
			}
			position += count
		}
	}
	return parameters
}

func (a *providerCommandRetryAnalyzer) analyzeFunction(function *ast.FuncDecl) {
	if providerCommandMethods[function.Name.Name] {
		a.detectBoolHelperCalls(function)
	}

	ast.Inspect(function.Body, func(node ast.Node) bool {
		switch current := node.(type) {
		case *ast.CallExpr:
			if retryCallbackMethods[calledFunctionName(current.Fun)] {
				a.detectRetryCallbacks(function.Name.Name, current)
			}
		case *ast.ForStmt:
			variables := derivedLoopVariables(current.Body, forLoopVariables(current))
			a.detectCommands(function.Name.Name, current.Body, "loop", variables)
		case *ast.RangeStmt:
			variables := derivedLoopVariables(current.Body, rangeLoopVariables(current))
			a.detectCommands(function.Name.Name, current.Body, "loop", variables)
		}
		return true
	})
}

func (a *providerCommandRetryAnalyzer) detectBoolHelperCalls(function *ast.FuncDecl) {
	ast.Inspect(function.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		for _, position := range a.retryParams[calledFunctionName(call.Fun)] {
			if position < len(call.Args) && isTrueLiteral(call.Args[position]) {
				a.report(call, function.Name.Name, function.Name.Name, "bool_helper")
				break
			}
		}
		return true
	})
}

func (a *providerCommandRetryAnalyzer) detectRetryCallbacks(function string, retryCall *ast.CallExpr) {
	for _, argument := range retryCall.Args {
		callback, ok := unparenProviderRetryExpr(argument).(*ast.FuncLit)
		if !ok {
			continue
		}
		a.detectCommands(function, callback.Body, "retry_callback", nil)
	}
}

func (a *providerCommandRetryAnalyzer) detectCommands(function string, root ast.Node, evidence string, loopVariables map[string]bool) {
	ast.Inspect(root, func(node ast.Node) bool {
		if _, nestedFunction := node.(*ast.FuncLit); nestedFunction {
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if ok && providerCommandMethods[selector.Sel.Name] &&
			receiverContainsAny(selector.X, providerReceiverMarkers) && !callUsesIdentifiers(call, loopVariables) {
			a.report(call, function, selector.Sel.Name, evidence)
		}
		return true
	})
}

func derivedLoopVariables(root ast.Node, loopVariables map[string]bool) map[string]bool {
	derived := make(map[string]bool, len(loopVariables))
	for name := range loopVariables {
		derived[name] = true
	}
	for changed := true; changed; {
		changed = false
		ast.Inspect(root, func(node ast.Node) bool {
			switch current := node.(type) {
			case *ast.FuncLit:
				return false
			case *ast.RangeStmt:
				if expressionsUseIdentifiers([]ast.Expr{current.X}, derived) {
					changed = addDerivedIdentifiers([]ast.Expr{current.Key, current.Value}, derived) || changed
				}
			case *ast.AssignStmt:
				if expressionsUseIdentifiers(current.Rhs, derived) {
					changed = addDerivedIdentifiers(current.Lhs, derived) || changed
				}
			case *ast.ValueSpec:
				if expressionsUseIdentifiers(current.Values, derived) {
					for _, name := range current.Names {
						if name.Name != "_" && !derived[name.Name] {
							derived[name.Name] = true
							changed = true
						}
					}
				}
			}
			return true
		})
	}
	return derived
}

func addDerivedIdentifiers(expressions []ast.Expr, identifiers map[string]bool) bool {
	changed := false
	for _, expression := range expressions {
		identifier, ok := expression.(*ast.Ident)
		if ok && identifier.Name != "_" && !identifiers[identifier.Name] {
			identifiers[identifier.Name] = true
			changed = true
		}
	}
	return changed
}

func forLoopVariables(loop *ast.ForStmt) map[string]bool {
	variables := make(map[string]bool)
	assignment, ok := loop.Init.(*ast.AssignStmt)
	if !ok {
		return variables
	}
	for _, expression := range assignment.Lhs {
		if identifier, ok := expression.(*ast.Ident); ok && identifier.Name != "_" {
			variables[identifier.Name] = true
		}
	}
	return variables
}

func rangeLoopVariables(loop *ast.RangeStmt) map[string]bool {
	variables := make(map[string]bool)
	for _, expression := range []ast.Expr{loop.Key, loop.Value} {
		if identifier, ok := expression.(*ast.Ident); ok && identifier.Name != "_" {
			variables[identifier.Name] = true
		}
	}
	return variables
}

func callUsesIdentifiers(call *ast.CallExpr, identifiers map[string]bool) bool {
	return expressionsUseIdentifiers(call.Args, identifiers)
}

func expressionsUseIdentifiers(expressions []ast.Expr, identifiers map[string]bool) bool {
	if len(identifiers) == 0 {
		return false
	}
	uses := false
	for _, expression := range expressions {
		ast.Inspect(expression, func(node ast.Node) bool {
			identifier, ok := node.(*ast.Ident)
			if ok && identifiers[identifier.Name] {
				uses = true
				return false
			}
			return !uses
		})
		if uses {
			return true
		}
	}
	return false
}

func (a *providerCommandRetryAnalyzer) report(call *ast.CallExpr, function, command, evidence string) {
	if a.reportedCalls[call] {
		return
	}
	a.reportedCalls[call] = true
	line := lineFromNode(a.ctx, call)
	if a.ctx.IsSuppressed(line, a.rule.Name()) {
		return
	}

	violation := a.rule.CreateViolation(a.ctx.RelPath, line,
		"destructive provider command '"+command+"' executes with automatic retry")
	violation.WithCode(a.ctx.GetLine(line))
	violation.WithSuggestion("Execute destructive provider commands once; reconcile status without resending or require explicit human approval")
	violation.WithContext("pattern", "provider_command_retry")
	violation.WithContext("function", function)
	violation.WithContext("command", command)
	violation.WithContext("retry_evidence", evidence)
	a.violations = append(a.violations, violation)
}

func calledFunctionName(expression ast.Expr) string {
	switch function := unparenProviderRetryExpr(expression).(type) {
	case *ast.Ident:
		return function.Name
	case *ast.SelectorExpr:
		return function.Sel.Name
	default:
		return ""
	}
}

func isTrueLiteral(expression ast.Expr) bool {
	ident, ok := unparenProviderRetryExpr(expression).(*ast.Ident)
	return ok && ident.Name == "true"
}

func unparenProviderRetryExpr(expression ast.Expr) ast.Expr {
	for {
		parenthesized, ok := expression.(*ast.ParenExpr)
		if !ok {
			return expression
		}
		expression = parenthesized.X
	}
}
