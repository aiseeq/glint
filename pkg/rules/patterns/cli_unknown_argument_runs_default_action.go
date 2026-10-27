package patterns

import (
	"go/ast"
	"go/token"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewCLIUnknownArgumentRunsDefaultActionRule())
}

// CLIUnknownArgumentRunsDefaultActionRule reports a command dispatch in main
// that handles a recognized argument and then continues into the default
// action without rejecting unrecognized arguments.
type CLIUnknownArgumentRunsDefaultActionRule struct {
	*rules.BaseRule
}

// NewCLIUnknownArgumentRunsDefaultActionRule creates the rule.
func NewCLIUnknownArgumentRunsDefaultActionRule() *CLIUnknownArgumentRunsDefaultActionRule {
	return &CLIUnknownArgumentRunsDefaultActionRule{BaseRule: rules.NewBaseRule(
		"cli-unknown-argument-runs-default-action",
		"patterns",
		"Detects a CLI command branch on the first argument that returns to a default action without rejecting unknown arguments",
		core.SeverityMedium,
	)}
}

// AnalyzeFile reports a command dispatch that lets unknown arguments reach the default action.
func (r *CLIUnknownArgumentRunsDefaultActionRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || ctx.IsTestFile() || ctx.GoAST == nil {
		return nil
	}
	return r.analyzeFile(ctx, stringCommandConstants(ctx.GoAST))
}

func (r *CLIUnknownArgumentRunsDefaultActionRule) analyzeFile(ctx *core.FileContext, stringConstants map[string]bool) []*core.Violation {
	if !ctx.IsGoFile() || ctx.IsTestFile() || ctx.GoAST == nil || ctx.GoAST.Name.Name != "main" {
		return nil
	}

	var main *ast.FuncDecl
	for _, decl := range ctx.GoAST.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil && fn.Name.Name == "main" {
			main = fn
			break
		}
	}
	if main == nil || main.Body == nil {
		return nil
	}

	for index, stmt := range main.Body.List {
		if index+1 == len(main.Body.List) || !isReturningCommandDispatch(stmt, stringConstants) {
			continue
		}
		if hasPositionalArgumentInput(main.Body.List[index+1:], stringConstants) {
			return nil
		}
		return []*core.Violation{r.report(ctx, stmt)}
	}
	return nil
}

// RequiresSSA reports that the rule needs typed syntax but not SSA.
func (r *CLIUnknownArgumentRunsDefaultActionRule) RequiresSSA() bool { return false }

// AnalyzeGoProject analyzes the Go files in a project.
func (r *CLIUnknownArgumentRunsDefaultActionRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	var violations []*core.Violation
	for _, pkg := range ctx.Packages {
		constants := make(map[string]bool)
		for _, file := range pkg.Files {
			for name := range stringCommandConstants(file.GoAST) {
				constants[name] = true
			}
		}
		for _, file := range pkg.Files {
			violations = append(violations, r.analyzeFile(file, constants)...)
		}
	}
	return violations, nil
}

func (r *CLIUnknownArgumentRunsDefaultActionRule) report(ctx *core.FileContext, node ast.Node) *core.Violation {
	line := ctx.LineFor(node)
	v := r.CreateViolation(ctx.RelPath, line,
		"The recognized command returns, then the default action runs for every other argument — reject unknown arguments before starting it")
	v.WithCode(ctx.GetLine(line))
	v.WithSuggestion("Add a default branch that prints usage and exits with a non-zero status")
	return v
}

func isReturningCommandDispatch(stmt ast.Stmt, stringConstants map[string]bool) bool {
	switch dispatch := stmt.(type) {
	case *ast.IfStmt:
		return commandArgumentComparison(dispatch.Cond, stringConstants) && blockTerminates(dispatch.Body)
	case *ast.SwitchStmt:
		return isFirstCommandArgument(dispatch.Tag) && hasReturningCommandCase(dispatch)
	}
	return false
}

func hasPositionalArgumentInput(statements []ast.Stmt, stringConstants map[string]bool) bool {
	for _, stmt := range statements {
		if isReturningCommandDispatch(stmt, stringConstants) {
			continue
		}
		found := false
		ast.Inspect(stmt, func(node ast.Node) bool {
			if node == nil || found {
				return !found
			}
			switch value := node.(type) {
			case *ast.CallExpr:
				if isFlagArgumentRead(value) {
					found = true
					return false
				}
				if isLenOfOSArgs(value) {
					return false
				}
			case *ast.IndexExpr:
				found = isOSArgs(value.X)
			case *ast.SliceExpr:
				found = isOSArgs(value.X)
			}
			return !found
		})
		if found {
			return true
		}
	}
	return false
}

func isOSArgs(expr ast.Expr) bool {
	selector, ok := ast.Unparen(expr).(*ast.SelectorExpr)
	return ok && selector.Sel.Name == "Args" && isPackageIdent(selector.X, "os")
}

func isFlagArgumentRead(call *ast.CallExpr) bool {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || !isPackageIdent(selector.X, "flag") {
		return false
	}
	switch selector.Sel.Name {
	case "Args", "Arg", "NArg":
		return true
	}
	return false
}

func isLenOfOSArgs(call *ast.CallExpr) bool {
	ident, ok := call.Fun.(*ast.Ident)
	return ok && ident.Name == "len" && len(call.Args) == 1 && isOSArgs(call.Args[0])
}

func commandArgumentComparison(expr ast.Expr, stringConstants map[string]bool) bool {
	found := false
	ast.Inspect(expr, func(node ast.Node) bool {
		comparison, ok := node.(*ast.BinaryExpr)
		if !ok || comparison.Op != token.EQL {
			return true
		}
		found = (isFirstCommandArgument(comparison.X) && isCommandString(comparison.Y, stringConstants)) ||
			(isFirstCommandArgument(comparison.Y) && isCommandString(comparison.X, stringConstants))
		return !found
	})
	return found
}

func stringCommandConstants(file *ast.File) map[string]bool {
	constants := make(map[string]bool)
	if file == nil {
		return constants
	}
	for _, decl := range file.Decls {
		group, ok := decl.(*ast.GenDecl)
		if !ok || group.Tok != token.CONST {
			continue
		}
		for _, spec := range group.Specs {
			value, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for _, expr := range value.Values {
				literal, ok := ast.Unparen(expr).(*ast.BasicLit)
				if !ok || literal.Kind != token.STRING {
					continue
				}
				for _, name := range value.Names {
					constants[name.Name] = true
				}
			}
		}
	}
	return constants
}

func isCommandString(expr ast.Expr, constants map[string]bool) bool {
	switch value := ast.Unparen(expr).(type) {
	case *ast.BasicLit:
		return value.Kind == token.STRING
	case *ast.Ident:
		return constants[value.Name]
	}
	return false
}

func isFirstCommandArgument(expr ast.Expr) bool {
	switch value := ast.Unparen(expr).(type) {
	case *ast.IndexExpr:
		selector, ok := value.X.(*ast.SelectorExpr)
		index, indexOK := value.Index.(*ast.BasicLit)
		return ok && selector.Sel.Name == "Args" && isPackageIdent(selector.X, "os") &&
			indexOK && index.Kind == token.INT && index.Value == "1"
	case *ast.CallExpr:
		selector, ok := value.Fun.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "Arg" || !isPackageIdent(selector.X, "flag") || len(value.Args) != 1 {
			return false
		}
		index, ok := ast.Unparen(value.Args[0]).(*ast.BasicLit)
		return ok && index.Kind == token.INT && index.Value == "0"
	}
	return false
}

func isPackageIdent(expr ast.Expr, name string) bool {
	ident, ok := expr.(*ast.Ident)
	return ok && ident.Name == name
}

func blockTerminates(block *ast.BlockStmt) bool {
	if block == nil || len(block.List) == 0 {
		return false
	}
	switch last := block.List[len(block.List)-1].(type) {
	case *ast.ReturnStmt:
		return true
	case *ast.ExprStmt:
		call, ok := last.X.(*ast.CallExpr)
		if !ok {
			return false
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		return ok && selector.Sel.Name == "Exit" && isPackageIdent(selector.X, "os")
	}
	return false
}

func hasReturningCommandCase(dispatch *ast.SwitchStmt) bool {
	if dispatch.Body == nil {
		return false
	}
	returningCase := false
	for _, stmt := range dispatch.Body.List {
		clause, ok := stmt.(*ast.CaseClause)
		if !ok || len(clause.List) == 0 || len(clause.Body) == 0 {
			return false
		}
		last, ok := clause.Body[len(clause.Body)-1].(*ast.ReturnStmt)
		if !ok || last == nil {
			return false
		}
		returningCase = true
	}
	return returningCase
}
