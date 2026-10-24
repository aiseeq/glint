package duplication

import (
	"errors"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"maps"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewRenamedDuplicateBlockRule())
}

// RenamedDuplicateBlockRule detects a loop or a branch of one function written
// again inside another function under other names instead of a call:
//
//	// zone/zone.go
//	func (m Marks) Next(posts, rivals []*geo.Unit, in, out float64) Marks {
//		marked := Marks{}
//		for _, p := range posts {
//			d := math.Inf(1)
//			for _, r := range rivals { d = min(d, r.Pos.Dist(p.Pos)) }
//			if d <= in || (m[p.Tag] && d <= out) { marked[p.Tag] = true }
//		}
//		return marked
//	}
//
//	// watch/watch.go, inside (*Tracker).step
//	for _, post := range in.Posts {
//		best := math.Inf(1)
//		for _, rival := range in.Rivals { best = min(best, rival.Pos.Dist(post.Pos)) }
//		if best <= enterRange || s.rivalAtPost[post.Tag] && best <= leaveRange { marked[post.Tag] = true }
//	}
//
// Every line of the copy differs in text, so cross-file-duplicate and
// duplicate-block, which compare windows of lines, find nothing in common.
// This rule compares the syntax: a variable declared inside the statement
// becomes its number in order of appearance, and a value that comes from
// outside the statement — a parameter, the receiver, a field of either, a
// variable declared before the statement, a constant — becomes one
// placeholder, since the copy takes its inputs from wherever its function
// keeps them. What the code does with the values stays: operators, literals,
// the fields and methods it reaches through its own variables, the functions
// it calls. Statements too small to carry a computation of their own (a lookup
// in a slice, grouping into a map, a sum, an error guard) are left out by size.
//
// The copy is reported against the occurrence that makes up the largest share
// of its function — the function to call. Repeats inside one function are left
// to the textual rules; test files, generated files and test-double packages
// are left out.
type RenamedDuplicateBlockRule struct {
	*rules.BaseRule
}

// NewRenamedDuplicateBlockRule creates the rule
func NewRenamedDuplicateBlockRule() *RenamedDuplicateBlockRule {
	return &RenamedDuplicateBlockRule{BaseRule: rules.NewBaseRule(
		"renamed-duplicate-block",
		"duplication",
		"Detects a loop or a branch of one function written again in another function under other names instead of a call — two copies of one computation that drift apart",
		core.SeverityMedium,
	)}
}

// AnalyzeFile is a no-op: the copies are compared across the module.
func (r *RenamedDuplicateBlockRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *RenamedDuplicateBlockRule) RequiresSSA() bool { return false }

// minRenamedBlockStatements and minRenamedBlockNodes are the size a statement
// must reach to be compared: the statements inside it, itself included and
// blocks not counted, and the syntax nodes of its normalized form. Below them
// lie the idioms every function writes its own way: a lookup or a filter over
// a slice and an error guard have three or four statements, an AST visitor
// switching over two or three node types has five with fewer than forty nodes.
const (
	minRenamedBlockStatements = 5
	minRenamedBlockNodes      = 40
)

// renamedBlock is one compared statement.
type renamedBlock struct {
	file string
	stmt ast.Stmt
	fn   *ast.FuncDecl
	// share is the statement's part of its function's body, in nodes.
	share float64
}

// AnalyzeGoProject reports each copy of a statement found in another function.
func (r *RenamedDuplicateBlockRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, errors.New("renamed duplicate block: nil Go project context")
	}
	byKey := make(map[string][]*renamedBlock)
	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil || pkg.Package.TypesInfo == nil {
			return nil, errors.New("renamed duplicate block: package has no typed syntax")
		}
		if testDoublePackage(pkg.Package.PkgPath) {
			continue
		}
		// Every file of the package, not only the analyzed ones: the original
		// of a copy in the run may lie outside it.
		for _, file := range pkg.Package.Syntax {
			if ast.IsGenerated(file) {
				continue
			}
			path := ctx.FileSet.Position(file.Pos()).Filename
			for _, decl := range file.Decls {
				if fd, ok := decl.(*ast.FuncDecl); ok && fd.Body != nil {
					collectRenamedBlocks(byKey, path, fd, pkg.Package.TypesInfo)
				}
			}
		}
	}

	var reports []renamedReport
	for _, key := range slices.Sorted(maps.Keys(byKey)) {
		group := byKey[key]
		original := group[0]
		for _, b := range group[1:] {
			if originalBefore(ctx.FileSet, b, original) {
				original = b
			}
		}
		for _, b := range group {
			if b.fn != original.fn {
				reports = append(reports, renamedReport{copy: b, original: original})
			}
		}
	}
	return r.violations(ctx, outermostReports(reports))
}

// renamedReport is a copy and the occurrence it is reported against.
type renamedReport struct {
	copy, original *renamedBlock
}

// outermostReports sorts the reports by file and position and drops a copy
// nested in another reported copy: it is part of that copy.
func outermostReports(reports []renamedReport) []renamedReport {
	sort.Slice(reports, func(i, j int) bool {
		a, b := reports[i].copy, reports[j].copy
		if a.file != b.file {
			return a.file < b.file
		}
		if a.stmt.Pos() != b.stmt.Pos() {
			return a.stmt.Pos() < b.stmt.Pos()
		}
		return a.stmt.End() > b.stmt.End()
	})
	var out []renamedReport
	var last *renamedBlock
	for _, rep := range reports {
		if last != nil && last.file == rep.copy.file && rep.copy.stmt.End() <= last.stmt.End() {
			continue
		}
		last = rep.copy
		out = append(out, rep)
	}
	return out
}

func (r *RenamedDuplicateBlockRule) violations(ctx *core.GoProjectContext, reports []renamedReport) ([]*core.Violation, error) {
	var violations []*core.Violation
	for _, rep := range reports {
		file, inRun := ctx.RunFile(rep.copy.file)
		if !inRun {
			continue
		}
		line := ctx.FileSet.Position(rep.copy.stmt.Pos()).Line
		if file.IsSuppressed(line, r.Name()) {
			continue
		}
		origLine := ctx.FileSet.Position(rep.original.stmt.Pos()).Line
		origFile, err := filepath.Rel(ctx.ProjectRoot, rep.original.file)
		if err != nil {
			return nil, fmt.Errorf("renamed duplicate block: original of %s:%d: %w", file.RelPath, line, err)
		}
		origFile = filepath.ToSlash(origFile)
		origFunc := funcDisplayName(rep.original.fn)
		v := r.CreateViolation(file.RelPath, line, fmt.Sprintf(
			"Repeats %s:%d (in %s) under other names — two copies of one computation: a fix lands in one and the other drifts",
			origFile, origLine, origFunc))
		v.WithCode(strings.TrimSpace(file.GetLine(line)))
		v.WithSuggestion("Call " + origFunc + ", or move the computation into a function both call, instead of repeating it")
		v.WithContext("original_file", origFile)
		v.WithContext("original_line", origLine)
		v.WithContext("original_func", origFunc)
		violations = append(violations, v)
	}
	return violations, nil
}

// originalBefore reports whether a is the better original than b: the larger
// share of its function, then an exported function, then the earlier position.
func originalBefore(fset *token.FileSet, a, b *renamedBlock) bool {
	if a.share != b.share {
		return a.share > b.share
	}
	if ea, eb := a.fn.Name.IsExported(), b.fn.Name.IsExported(); ea != eb {
		return ea
	}
	if a.file != b.file {
		return a.file < b.file
	}
	return fset.Position(a.stmt.Pos()).Offset < fset.Position(b.stmt.Pos()).Offset
}

// collectRenamedBlocks adds the large enough compound statements of a
// function to byKey under their normalized form.
func collectRenamedBlocks(byKey map[string][]*renamedBlock, path string, fd *ast.FuncDecl, info *types.Info) {
	funcNodes := 0
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		if n != nil {
			funcNodes++
		}
		return true
	})
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		stmt, ok := n.(ast.Stmt)
		if !ok {
			return true
		}
		switch stmt.(type) {
		case *ast.ForStmt, *ast.RangeStmt, *ast.IfStmt, *ast.SwitchStmt, *ast.TypeSwitchStmt, *ast.SelectStmt:
		default:
			return true
		}
		norm := newBlockNormalizer(info, stmt)
		norm.walk(stmt)
		if norm.stmts < minRenamedBlockStatements || norm.nodes < minRenamedBlockNodes {
			// Nothing inside a statement too small is large enough either.
			return false
		}
		key := norm.b.String()
		byKey[key] = append(byKey[key], &renamedBlock{
			file: path, stmt: stmt, fn: fd,
			share: float64(norm.nodes) / float64(funcNodes),
		})
		return true
	})
}

// funcDisplayName is Name, or Type.Name of a method.
func funcDisplayName(fd *ast.FuncDecl) string {
	if fd.Recv != nil && len(fd.Recv.List) > 0 {
		if recv := helpers.ReceiverTypeName(fd.Recv.List[0].Type); recv != "" {
			return recv + "." + fd.Name.Name
		}
	}
	return fd.Name.Name
}

// freeValue is the placeholder of a value that comes from outside the statement.
const freeValue = "$F"

// blockNormalizer prints a statement with its own variables numbered and the
// values from outside it as one placeholder, counting its nodes and statements.
type blockNormalizer struct {
	info   *types.Info
	lo, hi token.Pos
	locals map[types.Object]int
	b      strings.Builder
	nodes  int
	stmts  int
}

func newBlockNormalizer(info *types.Info, stmt ast.Stmt) *blockNormalizer {
	return &blockNormalizer{info: info, lo: stmt.Pos(), hi: stmt.End(), locals: make(map[types.Object]int)}
}

func (n *blockNormalizer) walk(root ast.Node) {
	ast.Inspect(root, func(node ast.Node) bool {
		if node == nil {
			n.b.WriteByte(')')
			return false
		}
		switch x := node.(type) {
		case *ast.ParenExpr:
			n.walk(x.X)
			return false
		case *ast.Ident:
			n.leaf(n.ident(x))
			return false
		case *ast.BasicLit:
			n.leaf(x.Value)
			return false
		case *ast.SelectorExpr:
			if atom, ok := n.selector(x); ok {
				n.leaf(atom)
				return false
			}
		case *ast.Comment, *ast.CommentGroup:
			return false
		}
		if _, ok := node.(ast.Stmt); ok {
			if _, block := node.(*ast.BlockStmt); !block {
				n.stmts++
			}
		}
		n.nodes++
		n.b.WriteByte('(')
		n.b.WriteString(nodeKind(node))
		return true
	})
}

func (n *blockNormalizer) leaf(text string) {
	n.nodes++
	n.b.WriteByte(' ')
	n.b.WriteString(text)
}

// nodeKind names a node with the operator or token that tells two nodes of
// one type apart.
func nodeKind(node ast.Node) string {
	kind := strings.TrimPrefix(fmt.Sprintf("%T", node), "*ast.")
	switch x := node.(type) {
	case *ast.BinaryExpr:
		return kind + x.Op.String()
	case *ast.UnaryExpr:
		return kind + x.Op.String()
	case *ast.AssignStmt:
		return kind + x.Tok.String()
	case *ast.IncDecStmt:
		return kind + x.Tok.String()
	case *ast.BranchStmt:
		return kind + x.Tok.String()
	case *ast.RangeStmt:
		return kind + x.Tok.String()
	case *ast.GenDecl:
		return kind + x.Tok.String()
	case *ast.ChanType:
		return kind + strconv.Itoa(int(x.Dir))
	case *ast.CallExpr:
		if x.Ellipsis.IsValid() {
			return kind + "..."
		}
	}
	return kind
}

// ident prints an identifier: a variable of the statement by its number, a
// value from outside as the placeholder, any other name as written.
func (n *blockNormalizer) ident(id *ast.Ident) string {
	if id.Name == "_" {
		return "_"
	}
	switch obj := n.info.ObjectOf(id).(type) {
	case *types.Var:
		if obj.IsField() {
			return id.Name
		}
		if obj.Pos() >= n.lo && obj.Pos() < n.hi {
			num, ok := n.locals[obj]
			if !ok {
				num = len(n.locals)
				n.locals[obj] = num
			}
			return "$L" + strconv.Itoa(num)
		}
		return freeValue
	case *types.Const:
		if obj.Pkg() == nil {
			return id.Name // true, false, iota
		}
		return freeValue
	case *types.TypeName:
		return "T." + id.Name
	case *types.Label:
		return "label"
	}
	return id.Name
}

// selector prints a selector as one atom when it names a member of another
// package or a field path from a value from outside the statement.
func (n *blockNormalizer) selector(sel *ast.SelectorExpr) (string, bool) {
	if atom, ok := n.packageMember(sel); ok {
		return atom, true
	}
	if n.freeRoot(sel) {
		return freeValue, true
	}
	return "", false
}

// packageMember prints pkg.Name: a variable or a constant of the package as
// the placeholder, a function or a type by its package path.
func (n *blockNormalizer) packageMember(sel *ast.SelectorExpr) (string, bool) {
	id, ok := ast.Unparen(sel.X).(*ast.Ident)
	if !ok {
		return "", false
	}
	pkg, ok := n.info.ObjectOf(id).(*types.PkgName)
	if !ok {
		return "", false
	}
	switch n.info.ObjectOf(sel.Sel).(type) {
	case *types.Var, *types.Const:
		return freeValue, true
	}
	return pkg.Imported().Path() + "." + sel.Sel.Name, true
}

// freeRoot reports an expression that is a value from outside the statement
// or a field path from one.
func (n *blockNormalizer) freeRoot(expr ast.Expr) bool {
	switch x := ast.Unparen(expr).(type) {
	case *ast.Ident:
		return n.ident(x) == freeValue
	case *ast.SelectorExpr:
		if atom, ok := n.packageMember(x); ok {
			return atom == freeValue
		}
		selection := n.info.Selections[x]
		return selection != nil && selection.Kind() == types.FieldVal && n.freeRoot(x.X)
	case *ast.StarExpr:
		return n.freeRoot(x.X)
	}
	return false
}
