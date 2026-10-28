package gorules

import (
	"go/ast"
	"go/token"
	"go/types"
	"strconv"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

var catchAllWords = [...]string{"any", "unknown", "interface"}

func init() {
	rules.Register(NewCodegenCatchAllTypeWithoutReportRule())
}

// CodegenCatchAllTypeWithoutReportRule detects type generators that silently
// replace unsupported types with a catch-all type.
type CodegenCatchAllTypeWithoutReportRule struct {
	*rules.BaseRule
}

// NewCodegenCatchAllTypeWithoutReportRule creates the rule.
func NewCodegenCatchAllTypeWithoutReportRule() *CodegenCatchAllTypeWithoutReportRule {
	return &CodegenCatchAllTypeWithoutReportRule{BaseRule: rules.NewBaseRule(
		"codegen-catch-all-type-without-report",
		"patterns",
		"Detects type generators that map unsupported types to any or unknown without reporting an error",
		core.SeverityMedium,
	)}
}

// AnalyzeFile checks Go syntax for silent catch-all type mappings.
func (r *CodegenCatchAllTypeWithoutReportRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || ctx.GoAST == nil || ctx.IsTestFile() || !isTypeGeneratorFile(ctx.GoAST) {
		return nil
	}
	return r.analyze(ctx, checkedCatchAllWordsAST([]*ast.File{ctx.GoAST}))
}

func (r *CodegenCatchAllTypeWithoutReportRule) analyze(ctx *core.FileContext, checked map[string]bool) []*core.Violation {
	var violations []*core.Violation
	seen := make(map[token.Pos]bool)
	report := func(node ast.Node, message string) {
		if node == nil || seen[node.Pos()] {
			return
		}
		seen[node.Pos()] = true
		line := ctx.LineFor(node)
		if ctx.IsSuppressed(line, r.Name()) {
			return
		}
		v := r.CreateViolation(ctx.RelPath, line, message)
		v.WithCode(ctx.GetLine(line))
		v.WithSuggestion("Return an error or report the unsupported type instead of emitting any or unknown")
		violations = append(violations, v)
	}

	ast.Inspect(ctx.GoAST, func(node ast.Node) bool {
		switch n := node.(type) {
		case *ast.FuncDecl:
			if !hasTypeMappingLookup(n) {
				return true
			}
			ast.Inspect(n.Body, func(child ast.Node) bool {
				ret, ok := child.(*ast.ReturnStmt)
				if !ok {
					return true
				}
				for _, result := range ret.Results {
					if catchAllString(result) && !checkedCatchAll(result, checked) && !returnsErrorAlongside(ret, result) {
						report(result, "Type mapping returns a catch-all output without reporting the unsupported input")
					}
				}
				return true
			})
		case *ast.CompositeLit:
			// A mapping table value with a DefaultType field applies the catch-all
			// to every type represented by that package key.
			for _, elt := range n.Elts {
				value, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				mapping, ok := value.Value.(*ast.CompositeLit)
				if !ok {
					continue
				}
				for _, field := range mapping.Elts {
					kv, ok := field.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					key, keyOK := kv.Key.(*ast.Ident)
					if keyOK && key.Name == "DefaultType" && catchAllString(kv.Value) && !checkedCatchAll(kv.Value, checked) {
						report(kv.Value, "Package mapping assigns every type a catch-all output without reporting unsupported types")
					}
				}
			}
		}
		return true
	})
	return violations
}

// hasTypeMappingLookup identifies conversion functions structurally by a
// lookup in a mapping table. Ordinary enum and syntax formatters do not do
// this and are outside the rule's scope.
func hasTypeMappingLookup(fn *ast.FuncDecl) bool {
	if fn.Body == nil {
		return false
	}
	found := false
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		if _, ok := node.(*ast.IndexExpr); ok {
			found = true
			return false
		}
		return true
	})
	return found
}

func returnsErrorAlongside(ret *ast.ReturnStmt, catchAll ast.Expr) bool {
	if len(ret.Results) < 2 {
		return false
	}
	for _, result := range ret.Results {
		if result == catchAll {
			continue
		}
		if ident, ok := result.(*ast.Ident); ok && ident.Name == "nil" {
			continue
		}
		return true
	}
	return false
}

// RequiresSSA reports that syntax alone is sufficient.
func (r *CodegenCatchAllTypeWithoutReportRule) RequiresSSA() bool { return false }

// AnalyzeGoProject checks every Go source file in the project.
func (r *CodegenCatchAllTypeWithoutReportRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	checkedByFile := make(map[*core.FileContext]map[string]bool)
	for _, pkg := range ctx.Packages {
		if pkg == nil {
			continue
		}
		checked := checkedCatchAllWords(pkg.Files)
		for _, file := range pkg.Files {
			checkedByFile[file] = checked
		}
	}
	return rules.AnalyzeGoFiles(ctx, r.Name(), func(file *core.FileContext, _ *types.Info) []*core.Violation {
		if !isTypeGeneratorFile(file.GoAST) {
			return nil
		}
		if checkedByFile[file] == nil {
			checkedByFile[file] = checkedCatchAllWords([]*core.FileContext{file})
		}
		return r.analyze(file, checkedByFile[file])
	})
}

func isTypeGeneratorFile(file *ast.File) bool {
	if file == nil {
		return false
	}
	for _, imp := range file.Imports {
		path := strings.Trim(imp.Path.Value, "\"")
		switch path {
		case "go/ast", "go/types", "reflect", "golang.org/x/tools/go/packages":
			return true
		}
	}
	return false
}

func checkedCatchAllWords(files []*core.FileContext) map[string]bool {
	asts := make([]*ast.File, 0, len(files))
	for _, file := range files {
		if file != nil {
			asts = append(asts, file.GoAST)
		}
	}
	return checkedCatchAllWordsAST(asts)
}

func checkedCatchAllWordsAST(files []*ast.File) map[string]bool {
	checked := make(map[string]bool)
	for _, file := range files {
		if file == nil {
			continue
		}
		ast.Inspect(file, func(node ast.Node) bool {
			lit, ok := node.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING || !isCheckedLiteral(file, lit) {
				return true
			}
			value, ok := stringLiteralValue(lit)
			if !ok {
				return true
			}
			for _, word := range catchAllWords {
				if hasWholeWord(value, word) {
					checked[word] = true
				}
			}
			return true
		})
	}
	return checked
}

func isCheckedLiteral(file *ast.File, lit *ast.BasicLit) bool {
	found := false
	ast.Inspect(file, func(node ast.Node) bool {
		if found {
			return false
		}
		switch n := node.(type) {
		case *ast.CallExpr:
			selector, ok := n.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := selector.X.(*ast.Ident)
			if !ok {
				return true
			}
			valid := (pkg.Name == "regexp" && (selector.Sel.Name == "MustCompile" || selector.Sel.Name == "Compile" || selector.Sel.Name == "MatchString")) ||
				(pkg.Name == "strings" && (selector.Sel.Name == "Contains" || selector.Sel.Name == "Index"))
			if valid {
				for _, arg := range n.Args {
					if arg == lit {
						found = true
						return false
					}
				}
			}
		case *ast.BinaryExpr:
			if n.Op == token.EQL && (n.X == lit || n.Y == lit) {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

func checkedCatchAll(expr ast.Expr, checked map[string]bool) bool {
	value, ok := stringLiteralValue(expr)
	if !ok {
		return false
	}
	for _, word := range catchAllWords {
		if checked[word] && hasWholeWord(value, word) {
			return true
		}
	}
	return false
}

func hasWholeWord(value, word string) bool {
	for offset := 0; ; {
		index := strings.Index(value[offset:], word)
		if index < 0 {
			return false
		}
		start := offset + index
		end := start + len(word)
		isWordByte := func(b byte) bool {
			return b == '_' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9'
		}
		leftBoundary := start == 0 || !isWordByte(value[start-1]) || start >= 2 && value[start-2:start] == `\b`
		rightBoundary := end == len(value) || !isWordByte(value[end]) || end+2 <= len(value) && value[end:end+2] == `\b`
		if leftBoundary && rightBoundary {
			return true
		}
		offset = end
		if offset >= len(value) {
			return false
		}
	}
}

func stringLiteralValue(expr ast.Expr) (string, bool) {
	lit, ok := expr.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	value, err := strconv.Unquote(lit.Value)
	return value, err == nil
}

func catchAllString(expr ast.Expr) bool {
	lit, ok := expr.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return false
	}
	switch lit.Value {
	case `"any"`, "`any`", `"unknown"`, "`unknown`", `"interface{}"`, "`interface{}`":
		return true
	default:
		return false
	}
}
