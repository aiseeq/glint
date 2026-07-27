package patterns

import (
	"fmt"
	"go/ast"
	"go/token"
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewQuadraticLoopRule())
}

// rescanFuncs replace inside a string and return a fresh one, so calling them in
// a loop whose condition searches the same string rescans it every time.
var rescanFuncs = map[string]bool{"ReplaceAll": true, "Replace": true}

// QuadraticLoopRule detects work that grows with the square of the input:
//
//	for i := range windows {          // every window…
//	    for j := range windows {      // …compared with every other one
//
//	for strings.Contains(line, "  ") {         // scan the whole string…
//	    line = strings.ReplaceAll(line, "  ", " ")  // …after each replacement
//
// Both shapes are correct and stay fast on the examples they were written
// against; they turn into minutes once the input grows. Both cost glint itself
// dearly: the nested window comparison made a 900-file project take over two
// minutes, and the rescanning replace was the hot spot of line normalization.
//
// Not flagged: loops over two different collections (O(n*m) is what the code
// asks for), an inner loop over a field of the outer element, and a body that
// does nothing but count.
type QuadraticLoopRule struct {
	*rules.BaseRule
}

// NewQuadraticLoopRule creates the rule
func NewQuadraticLoopRule() *QuadraticLoopRule {
	return &QuadraticLoopRule{
		BaseRule: rules.NewBaseRule(
			"quadratic-loop",
			"patterns",
			"Detects work that grows quadratically: a collection scanned inside itself, or a string rescanned after every replacement",
			core.SeverityMedium,
		),
	}
}

// AnalyzeFile looks for the two quadratic shapes in one file.
func (r *QuadraticLoopRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if ctx.IsTestFile() {
		return nil
	}
	if ctx.IsTypeScriptFile() || ctx.IsJavaScriptFile() {
		return r.analyzeFrontend(ctx)
	}
	if !ctx.IsGoFile() || ctx.GoAST == nil {
		return nil
	}

	var violations []*core.Violation
	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		outer, body, ok := loopOver(n)
		if !ok {
			return true
		}
		if outer != "" {
			violations = append(violations, r.nestedScans(ctx, n, outer, body)...)
		}
		if v, ok := r.rescanningReplace(ctx, n); ok {
			violations = append(violations, v)
		}
		return true
	})

	return violations
}

// nestedScans reports the loops inside this one that walk the same collection.
func (r *QuadraticLoopRule) nestedScans(ctx *core.FileContext, outerLoop ast.Node, collection string, body *ast.BlockStmt) []*core.Violation {
	var violations []*core.Violation

	ast.Inspect(body, func(n ast.Node) bool {
		if n == outerLoop {
			return true
		}
		inner, innerBody, ok := loopOver(n)
		if !ok || inner != collection {
			return true
		}
		if !hasSubstantialBody(innerBody) {
			return true
		}

		line := ctx.LineFor(n)
		v := r.CreateViolation(ctx.RelPath, line,
			fmt.Sprintf("Nested scan over %q: every element is compared with every other one, so the work grows with the square of the input", collection))
		v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
		v.WithSuggestion(fmt.Sprintf("Index %s by the key being matched (map[key][]T) and look the partner up, instead of walking the collection again", collection))
		v.WithContext("pattern", "quadratic_nested_scan")
		v.WithContext("collection", collection)
		violations = append(violations, v)
		return true
	})

	return violations
}

// rescanningReplace reports `for strings.Contains(s, x) { s = strings.ReplaceAll(s, x, y) }`.
func (r *QuadraticLoopRule) rescanningReplace(ctx *core.FileContext, n ast.Node) (*core.Violation, bool) {
	forStmt, ok := n.(*ast.ForStmt)
	if !ok || forStmt.Cond == nil {
		return nil, false
	}
	subject, ok := searchedString(forStmt.Cond)
	if !ok || !replacesInLoop(forStmt.Body, subject) {
		return nil, false
	}

	line := ctx.LineFor(forStmt)
	v := r.CreateViolation(ctx.RelPath, line,
		fmt.Sprintf("Each pass rescans the whole of %q after replacing inside it, so the cost grows with the square of its length", subject))
	v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
	v.WithSuggestion(fmt.Sprintf("Walk %s once, building the result in a strings.Builder, instead of replacing and searching again", subject))
	v.WithContext("pattern", "quadratic_rescan")
	v.WithContext("variable", subject)
	return v, true
}

// loopOver returns the collection a loop walks, rendered as source text, along
// with its body. A `for i := 0; i < len(x); i++` counts as a walk over x.
func loopOver(n ast.Node) (string, *ast.BlockStmt, bool) {
	switch loop := n.(type) {
	case *ast.RangeStmt:
		return receiverChain(loop.X), loop.Body, true
	case *ast.ForStmt:
		if loop.Cond == nil {
			return "", loop.Body, true
		}
		return lengthBound(loop.Cond), loop.Body, true
	}
	return "", nil, false
}

// lengthBound returns the collection of an `i < len(items)` condition, allowing
// the bound to be adjusted: `i <= len(items)-blockSize` walks items just as much.
func lengthBound(cond ast.Expr) string {
	binary, ok := cond.(*ast.BinaryExpr)
	if !ok || (binary.Op != token.LSS && binary.Op != token.LEQ) {
		return ""
	}

	collection := ""
	ast.Inspect(binary.Y, func(n ast.Node) bool {
		if collection != "" {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 1 {
			return true
		}
		if fun, ok := call.Fun.(*ast.Ident); !ok || fun.Name != "len" {
			return true
		}
		collection = receiverChain(call.Args[0])
		return false
	})
	return collection
}

// hasSubstantialBody reports whether the loop body does more than counting:
// a comparison or a call is what makes the repetition expensive.
func hasSubstantialBody(body *ast.BlockStmt) bool {
	if body == nil {
		return false
	}
	substantial := false
	ast.Inspect(body, func(n ast.Node) bool {
		if substantial {
			return false
		}
		switch node := n.(type) {
		case *ast.IfStmt, *ast.SwitchStmt, *ast.TypeSwitchStmt:
			substantial = true
		case *ast.CallExpr:
			if fun, ok := node.Fun.(*ast.Ident); ok && (fun.Name == "len" || fun.Name == "cap") {
				return true
			}
			substantial = true
		}
		return !substantial
	})
	return substantial
}

// searchedString returns the string a `strings.Contains(s, …)` condition scans.
func searchedString(cond ast.Expr) (string, bool) {
	call, ok := cond.(*ast.CallExpr)
	if !ok || len(call.Args) < 1 {
		return "", false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Contains" {
		return "", false
	}
	if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "strings" {
		return "", false
	}
	subject := receiverChain(call.Args[0])
	return subject, subject != ""
}

// replacesInLoop reports whether the body assigns a replacement of the subject
// back to it.
func replacesInLoop(body *ast.BlockStmt, subject string) bool {
	replaces := false

	ast.Inspect(body, func(n ast.Node) bool {
		if replaces {
			return false
		}
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
			return true
		}
		if receiverChain(assign.Lhs[0]) != subject {
			return true
		}
		call, ok := assign.Rhs[0].(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || !rescanFuncs[sel.Sel.Name] {
			return true
		}
		if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "strings" {
			replaces = true
		}
		return !replaces
	})

	return replaces
}

// frontendScanStart matches the ways JavaScript walks a collection: a for…of
// loop and the array methods that visit every element.
var frontendScanStart = regexp.MustCompile(`for\s*\(\s*(?:const|let|var)\s+\w+\s+of\s+([\w.]+)\s*\)|\b([\w.]+)\.(?:forEach|map|filter|some|every|find|findIndex|reduce)\s*\(`)

// frontendRescan matches a loop condition that searches the whole string again
// after each replacement.
var frontendRescan = regexp.MustCompile(`while\s*\(\s*([\w.]+)\.(?:includes|indexOf|search|match)\s*\(`)

// analyzeFrontend applies the same two shapes to TypeScript and JavaScript,
// where a collection is scanned by method calls rather than by range.
func (r *QuadraticLoopRule) analyzeFrontend(ctx *core.FileContext) []*core.Violation {
	var violations []*core.Violation

	for i := 0; i < len(ctx.Lines); i++ {
		line := ctx.Lines[i]
		// Only a scan that opens a block can contain another one. A chain —
		// items.map(...).filter(...) — walks the result of the previous step,
		// and a second statement further down is a separate pass, not a nested
		// one.
		if collection, ok := frontendScanned(line); ok && strings.HasSuffix(strings.TrimSpace(line), "{") {
			block, end := collectBraceBlock(ctx.Lines, i)
			if inner, ok := frontendNestedScan(block, collection); ok {
				violations = append(violations, r.frontendNested(ctx, i+1, collection, inner))
			}
			if end > i {
				i = end
			}
			continue
		}
		if match := frontendRescan.FindStringSubmatch(line); match != nil {
			block, _ := collectBraceBlock(ctx.Lines, i)
			if frontendReplacesInBlock(block, match[1]) {
				violations = append(violations, r.frontendRescan(ctx, i+1, match[1]))
			}
		}
	}

	return violations
}

func (r *QuadraticLoopRule) frontendNested(ctx *core.FileContext, line int, collection string, innerLine int) *core.Violation {
	v := r.CreateViolation(ctx.RelPath, line,
		fmt.Sprintf("Nested scan over %q: every element is compared with every other one, so the work grows with the square of the input", collection))
	v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
	v.WithSuggestion(fmt.Sprintf("Index %s by the key being matched (a Map or a lookup object) and read the partner from it, instead of scanning again", collection))
	v.WithContext("pattern", "quadratic_nested_scan")
	v.WithContext("collection", collection)
	v.WithContext("inner_line", innerLine)
	return v
}

func (r *QuadraticLoopRule) frontendRescan(ctx *core.FileContext, line int, subject string) *core.Violation {
	v := r.CreateViolation(ctx.RelPath, line,
		fmt.Sprintf("Each pass rescans the whole of %q after replacing inside it, so the cost grows with the square of its length", subject))
	v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
	v.WithSuggestion(fmt.Sprintf("Use a single replaceAll with a global regular expression over %s instead of searching again after each pass", subject))
	v.WithContext("pattern", "quadratic_rescan")
	v.WithContext("variable", subject)
	return v
}

// frontendScanned returns the collection a line starts walking over.
func frontendScanned(line string) (string, bool) {
	match := frontendScanStart.FindStringSubmatch(line)
	if match == nil {
		return "", false
	}
	collection := match[1]
	if collection == "" {
		collection = match[2]
	}
	return collection, collection != ""
}

// frontendNestedScan reports whether the block walks the same collection again,
// on a line other than the one that opened the outer scan.
func frontendNestedScan(block string, collection string) (int, bool) {
	lines := strings.Split(block, "\n")
	for i, line := range lines[1:] {
		inner, ok := frontendScanned(line)
		if ok && inner == collection {
			return i + 2, true
		}
	}
	return 0, false
}

// frontendReplacesInBlock reports whether the block assigns a replacement of the
// subject back to it.
func frontendReplacesInBlock(block string, subject string) bool {
	for _, line := range strings.Split(block, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, subject+" =") && !strings.Contains(trimmed, subject+" = ") {
			continue
		}
		if strings.Contains(trimmed, subject+".replace") {
			return true
		}
	}
	return false
}
