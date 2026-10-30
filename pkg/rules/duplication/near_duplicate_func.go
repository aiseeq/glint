package duplication

import (
	"bytes"
	"errors"
	"fmt"
	"go/ast"
	"go/format"
	"go/token"
	"go/types"
	"maps"
	"path/filepath"
	"sort"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() { rules.Register(NewNearDuplicateFuncRule()) }

const (
	defaultNearDuplicateMaxDifferences = 2
	minNearDuplicateFuncStatements     = 5
)

// NearDuplicateFuncRule finds functions in one package whose bodies differ in
// only a small number of expressions and could share one implementation.
type NearDuplicateFuncRule struct {
	*rules.BaseRule
	maxDifferences int
}

// NewNearDuplicateFuncRule creates the near-duplicate function rule.
func NewNearDuplicateFuncRule() *NearDuplicateFuncRule {
	return &NearDuplicateFuncRule{
		BaseRule: rules.NewBaseRule("near-duplicate-func", "duplication",
			"Detects functions in one package whose bodies differ in up to max_differences expressions (two by default) — a shared function parameter prevents the copies from drifting apart",
			core.SeverityMedium).DeclareSettings(rules.NewSettingSpec("max_differences", "int", defaultNearDuplicateMaxDifferences, "Maximum differences allowed between near duplicate functions.", 3)),
		maxDifferences: defaultNearDuplicateMaxDifferences,
	}
}

// Configure applies rule settings.
func (r *NearDuplicateFuncRule) Configure(settings map[string]any) error {
	if err := r.BaseRule.Configure(settings); err != nil {
		return err
	}
	limit := r.GetIntSetting("max_differences", defaultNearDuplicateMaxDifferences)
	if limit < 1 {
		return fmt.Errorf("%s: max_differences must be at least 1", r.Name())
	}
	r.maxDifferences = limit
	return nil
}

// AnalyzeFile is a no-op because this rule compares functions across a project.
func (r *NearDuplicateFuncRule) AnalyzeFile(_ *core.FileContext) []*core.Violation { return nil }

// RequiresSSA reports that typed syntax is sufficient for this rule.
func (r *NearDuplicateFuncRule) RequiresSSA() bool { return false }

// AnalyzeGoProject reports functions whose bodies differ in a small number of expressions.
func (r *NearDuplicateFuncRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, errors.New("near duplicate func: nil Go project context")
	}
	var reports []nearFuncReport
	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil || pkg.Package.TypesInfo == nil {
			return nil, errors.New("near duplicate func: package has no typed syntax")
		}
		if testDoublePackage(pkg.Package.PkgPath) {
			continue
		}
		groups := make(map[string][]*nearFunc)
		for _, file := range pkg.Package.Syntax {
			if ast.IsGenerated(file) {
				continue
			}
			path := ctx.FileSet.Position(file.Pos()).Filename
			if strings.HasSuffix(filepath.Base(path), "_test.go") {
				continue
			}
			for _, decl := range file.Decls {
				fd, ok := decl.(*ast.FuncDecl)
				if !ok || fd.Body == nil {
					continue
				}
				candidate := newNearFunc(path, fd, pkg.Package.TypesInfo, ctx.FileSet)
				if candidate.statements >= minNearDuplicateFuncStatements {
					groups[candidate.group] = append(groups[candidate.group], candidate)
				}
			}
		}
		for _, group := range groups {
			reports = append(reports, nearFuncGroupReports(group, r.maxDifferences)...)
		}
	}
	sort.Slice(reports, func(i, j int) bool {
		if reports[i].copy.path != reports[j].copy.path {
			return reports[i].copy.path < reports[j].copy.path
		}
		return reports[i].copy.fd.Pos() < reports[j].copy.fd.Pos()
	})
	var out []*core.Violation
	for _, report := range reports {
		file, inRun := ctx.RunFile(report.copy.path)
		if !inRun {
			continue
		}
		line := ctx.FileSet.Position(report.copy.fd.Pos()).Line
		if file.IsSuppressed(line, r.Name()) {
			continue
		}
		origLine := ctx.FileSet.Position(report.original.fd.Pos()).Line
		origFile, err := filepath.Rel(ctx.ProjectRoot, report.original.path)
		if err != nil {
			return nil, fmt.Errorf("near duplicate func: original of %s:%d: %w", file.RelPath, line, err)
		}
		origFile = filepath.ToSlash(origFile)
		origName := funcDisplayName(report.original.fd)
		copyName := funcDisplayName(report.copy.fd)
		expression := nearFuncDifferenceText(report.original.fset, report.differences)
		v := r.CreateViolation(file.RelPath, line, fmt.Sprintf("%s is a near-duplicate of %s:%d (%s); differs in expression %s", copyName, origFile, origLine, origName, expression))
		v.WithSuggestion("Extract the differing expression as a parameter of one shared function")
		v.WithContext("original_file", origFile)
		v.WithContext("original_line", origLine)
		v.WithContext("original_func", origName)
		v.WithContext("expression", expression)
		out = append(out, v)
	}
	return out, nil
}

type nearFunc struct {
	path       string
	fd         *ast.FuncDecl
	info       *types.Info
	fset       *token.FileSet
	group      string
	statements int
	normalizer *blockNormalizer
}

type nearFuncReport struct {
	copy, original *nearFunc
	differences    []nearExprDifference
}

type nearFuncPair struct {
	expressions []nearExprDifference
	valid       bool
}

func nearFuncGroupReports(group []*nearFunc, limit int) []nearFuncReport {
	sort.Slice(group, func(i, j int) bool { return nearFuncLess(group[i], group[j]) })
	pairs := make([][]nearFuncPair, len(group))
	for i := range pairs {
		pairs[i] = make([]nearFuncPair, len(group))
	}
	for i := range group {
		for j := i + 1; j < len(group); j++ { //nolint:quadratic-loop // candidates share the same coarse structural key

			if !nearFuncReceiversCompatible(group[i], group[j]) {
				continue
			}
			differences, ok := nearFuncDifferences(group[i], group[j], limit)
			if !ok || len(differences) == 0 || !nearDifferencesCompatible(group[i], group[j], differences) {
				continue
			}
			pairs[i][j] = nearFuncPair{expressions: differences, valid: true}
			pairs[j][i] = pairs[i][j]
		}
	}

	var reports []nearFuncReport
	seen := make([]bool, len(group))
	for start := range group {
		if seen[start] {
			continue
		}
		component := []int{start}
		seen[start] = true
		for cursor := 0; cursor < len(component); cursor++ {
			current := component[cursor]
			for next := range group { //nolint:quadratic-loop // component traversal is limited to one structural-key group
				if !seen[next] && pairs[current][next].valid {
					seen[next] = true
					component = append(component, next)
				}
			}
		}
		if len(component) < 2 {
			continue
		}
		anchor := component[0]
		for _, copyIndex := range component[1:] {
			original := anchor
			if !pairs[anchor][copyIndex].valid {
				original = -1
				for _, candidate := range component {
					pair := pairs[candidate][copyIndex]
					if !pair.valid {
						continue
					}
					if original < 0 || len(pair.expressions) < len(pairs[original][copyIndex].expressions) {
						original = candidate
					}
				}
			}
			if original >= 0 {
				reports = append(reports, nearFuncReport{
					copy: group[copyIndex], original: group[original],
					differences: pairs[original][copyIndex].expressions,
				})
			}
		}
	}
	return reports
}

func nearFuncLess(a, b *nearFunc) bool {
	if a.path != b.path {
		return a.path < b.path
	}
	ap, bp := a.fset.Position(a.fd.Pos()), b.fset.Position(b.fd.Pos())
	if ap.Line != bp.Line {
		return ap.Line < bp.Line
	}
	return a.fd.Pos() < b.fd.Pos()
}

func nearFuncReceiversCompatible(a, b *nearFunc) bool {
	left, lok := a.info.Defs[a.fd.Name].(*types.Func)
	right, rok := b.info.Defs[b.fd.Name].(*types.Func)
	if !lok || !rok {
		return false
	}
	leftSig, lok := left.Type().(*types.Signature)
	rightSig, rok := right.Type().(*types.Signature)
	if !lok || !rok {
		return false
	}
	if leftSig.Recv() == nil || rightSig.Recv() == nil {
		return leftSig.Recv() == nil && rightSig.Recv() == nil
	}
	return types.Identical(leftSig.Recv().Type(), rightSig.Recv().Type())
}

func nearDifferencesCompatible(a, b *nearFunc, differences []nearExprDifference) bool {
	for _, difference := range differences {
		if !nearDifferenceAllowed(difference.parent, difference.childIndex, difference.left, difference.right) ||
			!nearExpressionCompatible(difference.left, difference.right, a, b) {
			return false
		}
	}
	return true
}

func nearExpressionCompatible(left, right ast.Node, a, b *nearFunc) bool {
	leftExpr, leftOK := left.(ast.Expr)
	rightExpr, rightOK := right.(ast.Expr)
	if !leftOK || !rightOK {
		return false
	}
	leftType, rightType := a.info.TypeOf(leftExpr), b.info.TypeOf(rightExpr)
	if leftType == nil || rightType == nil || !types.Identical(leftType, rightType) {
		return false
	}
	if ls, ok := left.(*ast.SelectorExpr); ok {
		rs, ok := right.(*ast.SelectorExpr)
		if !ok {
			return false
		}
		// Two names of another package are two values, whatever they are called.
		if ls.Sel.Name != rs.Sel.Name && (!qualifiedIdent(ls, a.info) || !qualifiedIdent(rs, b.info)) {
			return false
		}
	}
	// Two calls that differ only in the function called become one call of a
	// function parameter, which needs the two functions to have one type.
	if lc, ok := left.(*ast.CallExpr); ok {
		if rc, ok := right.(*ast.CallExpr); ok && sameCallArgs(lc, rc, a, b) {
			leftFun, rightFun := a.info.TypeOf(lc.Fun), b.info.TypeOf(rc.Fun)
			return leftFun != nil && rightFun != nil && types.Identical(leftFun, rightFun)
		}
	}
	return true
}

func sameCallArgs(left, right *ast.CallExpr, a, b *nearFunc) bool {
	if len(left.Args) != len(right.Args) {
		return false
	}
	for i := range left.Args {
		if normalizedNode(left.Args[i], a) != normalizedNode(right.Args[i], b) {
			return false
		}
	}
	return true
}

// qualifiedIdent reports pkg.Name, a name another package declares.
func qualifiedIdent(sel *ast.SelectorExpr, info *types.Info) bool {
	id, ok := ast.Unparen(sel.X).(*ast.Ident)
	if !ok {
		return false
	}
	_, isPkg := info.ObjectOf(id).(*types.PkgName)
	return isPkg
}

func newNearFunc(path string, fd *ast.FuncDecl, info *types.Info, fset *token.FileSet) *nearFunc {
	var statementKinds []string
	statements := 0
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		if stmt, ok := n.(ast.Stmt); ok {
			if _, block := stmt.(*ast.BlockStmt); !block {
				statements++
				statementKinds = append(statementKinds, nodeKind(stmt))
			}
		}
		return true
	})
	norm := newBlockNormalizer(info, fd.Body)
	norm.walk(fd.Body)
	return &nearFunc{path: path, fd: fd, info: info, fset: fset, group: strings.Join(statementKinds, "/"), statements: statements, normalizer: norm}
}

// nearExprDifference records one differing expression and its position in the AST.
type nearExprDifference struct {
	left, right ast.Node
	parent      ast.Node
	childIndex  int
}

// nearFuncDifferences collects all differing expression pairs in one parallel AST walk.
func nearFuncDifferences(a, b *nearFunc, limit int) ([]nearExprDifference, bool) {
	var differences []nearExprDifference
	var walk func(ast.Node, ast.Node, ast.Node, int) bool
	walk = func(left, right, parent ast.Node, childIndex int) bool {
		if normalizedNode(left, a) == normalizedNode(right, b) {
			return true
		}
		_, leftExpr := left.(ast.Expr)
		_, rightExpr := right.(ast.Expr)
		if leftExpr && rightExpr && nodeKind(left) != nodeKind(right) {
			return appendNearDifference(&differences, left, right, parent, childIndex, limit)
		}
		if nodeKind(left) != nodeKind(right) {
			return false
		}
		leftChildren, rightChildren := directASTChildren(left), directASTChildren(right)
		if len(leftChildren) != len(rightChildren) {
			return leftExpr && rightExpr && appendNearDifference(&differences, left, right, parent, childIndex, limit)
		}
		if len(leftChildren) == 0 {
			if leftExpr && rightExpr && nearDifferenceAllowed(parent, childIndex, left, right) {
				return appendNearDifference(&differences, left, right, parent, childIndex, limit)
			}
			return true
		}
		start := len(differences)
		for i := range leftChildren {
			if !walk(leftChildren[i], rightChildren[i], left, i) {
				return false
			}
		}
		if len(differences) != start || !leftExpr {
			return true
		}
		// The children differ only where no parameter can go, as the name
		// after a package selector: the whole expression is the difference.
		return appendNearDifference(&differences, left, right, parent, childIndex, limit)
	}
	if !walk(a.fd.Body, b.fd.Body, nil, -1) {
		return nil, false
	}
	return differences, true
}

func appendNearDifference(differences *[]nearExprDifference, left, right, parent ast.Node, childIndex, limit int) bool {
	if !nearDifferenceAllowed(parent, childIndex, left, right) {
		return false
	}
	*differences = append(*differences, nearExprDifference{left: left, right: right, parent: parent, childIndex: childIndex})
	return len(*differences) <= limit
}

func nearDifferenceAllowed(parent ast.Node, childIndex int, left, right ast.Node) bool {
	if _, ok := left.(*ast.BasicLit); ok {
		_, rightOK := right.(*ast.BasicLit)
		return rightOK
	}
	switch parent.(type) {
	case *ast.CallExpr:
		return childIndex > 0 // The first child is the callee; remaining children are arguments.
	case *ast.BinaryExpr, *ast.UnaryExpr:
		return true
	default:
		return false
	}
}

func normalizedNode(node ast.Node, fn *nearFunc) string {
	n := &blockNormalizer{info: fn.info, lo: fn.fd.Body.Pos(), hi: fn.fd.Body.End(), locals: make(map[types.Object]int), packageNames: true}
	maps.Copy(n.locals, fn.normalizer.locals)
	n.walk(node)
	return n.b.String()
}

func directASTChildren(node ast.Node) []ast.Node {
	var children []ast.Node
	first := true
	ast.Inspect(node, func(child ast.Node) bool {
		if child == nil {
			return false
		}
		if first {
			first = false
			return true
		}
		children = append(children, child)
		return false
	})
	return children
}

func nearFuncDifferenceText(fset *token.FileSet, differences []nearExprDifference) string {
	expressions := make([]string, 0, len(differences))
	for _, difference := range differences {
		expressions = append(expressions, nearExprPair(fset, difference.left, difference.right))
	}
	if len(expressions) == 0 {
		return "<expression>"
	}
	return strings.Join(expressions, ", ")
}

func nearExprPair(fset *token.FileSet, a, b ast.Node) string {
	render := func(node ast.Node) string {
		var out bytes.Buffer
		if err := format.Node(&out, fset, node); err != nil { //nolint:silent-error-handling // formatting a valid AST node is best-effort for diagnostics
			return "<expression>"
		}
		return out.String()
	}
	return fmt.Sprintf("%q vs %q", render(a), render(b))
}
