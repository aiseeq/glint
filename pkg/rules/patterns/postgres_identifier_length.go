package patterns

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewPostgresIdentifierExceedsLimitRule())
}

// NewPostgresIdentifierExceedsLimitRule creates the rule that detects a
// database, schema or table name built by fmt.Sprintf whose longest value
// passes PostgreSQL's 63-byte limit for identifiers:
//
//	func dbName(t *testing.T) string {
//		name := strings.ToLower(t.Name())
//		if len(name) > 40 {
//			name = name[:40]
//		}
//		return fmt.Sprintf("app_test_%s_%d_%s", name, time.Now().UnixNano(), hex.EncodeToString(b)) // b: 4 bytes
//	}
//	db.Exec(fmt.Sprintf("CREATE DATABASE %s", dbName(t)))
//
// PostgreSQL cuts a longer name to 63 bytes with only a NOTICE: the part
// meant to keep names apart (a timestamp, a random suffix) is what gets cut,
// and two names that differ there become the same database. The width counts
// the literal text and the parts whose length is bounded: a string cut to N,
// a %d of UnixNano (19 digits), the hex of k bytes (2k).
func NewPostgresIdentifierExceedsLimitRule() *typedFuncRule {
	return &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"postgres-identifier-exceeds-63-bytes",
			"patterns",
			"Detects a database, schema or table name built with fmt.Sprintf whose bounded parts already pass 63 bytes — PostgreSQL cuts the name, and the part that keeps names apart is lost",
			core.SeverityMedium,
		),
		suggestion: "Shorten the fixed parts or the cut so the name stays within 63 bytes, keeping the part that makes it unique whole",
		check:      longIdentifiers,
	}
}

// postgresIdentifierLimit is NAMEDATALEN - 1.
const postgresIdentifierLimit = 63

// ddlName matches a statement creating a database, a schema or a table
// whose name is the first verb or the end of the literal.
var ddlName = regexp.MustCompile(`(?i)\bCREATE\s+(?:DATABASE|SCHEMA|(?:UNLOGGED\s+|TEMP(?:ORARY)?\s+)?TABLE)\s+(?:IF\s+NOT\s+EXISTS\s+)?(%[sqv]|"?$)`)

// longIdentifiers reports the names of the CREATE statements of a function
// whose bounded width passes the limit, where the name is built.
func longIdentifiers(scope funcScope, fn *ast.FuncDecl) []funcFinding {
	var findings []funcFinding
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		expr, ok := n.(ast.Expr)
		if !ok {
			return true
		}
		name := createdName(scope.info, expr)
		if name == nil {
			return true
		}
		built, info, decl := nameBuilder(scope, fn, name)
		if built == nil {
			return false
		}
		width, parts := sprintfWidth(info, decl, built)
		if width > postgresIdentifierLimit {
			findings = append(findings, funcFinding{node: built, message: fmt.Sprintf(
				"The name created here can be %d bytes (%s) — PostgreSQL cuts identifiers to 63 bytes, and the part that keeps names apart is cut off",
				width, strings.Join(parts, " + "))})
		}
		return false
	})
	return findings
}

// createdName returns the name a CREATE DATABASE/SCHEMA/TABLE statement is
// given: the argument of the Sprintf verb after the keyword, or the operand
// after a literal ending with it.
func createdName(info *types.Info, expr ast.Expr) ast.Expr {
	switch e := ast.Unparen(expr).(type) {
	case *ast.CallExpr:
		if !isFmtSprintf(info, e) || len(e.Args) < 2 {
			return nil
		}
		format, ok := stringConstant(info, e.Args[0])
		if !ok {
			return nil
		}
		loc := ddlName.FindStringSubmatchIndex(format)
		if loc == nil || loc[2] < 0 || loc[2] >= len(format) || format[loc[2]] != '%' {
			return nil
		}
		verb := strings.Count(strings.ReplaceAll(format[:loc[2]], "%%", ""), "%")
		if 1+verb >= len(e.Args) {
			return nil
		}
		return e.Args[1+verb]
	case *ast.BinaryExpr:
		if e.Op != token.ADD {
			return nil
		}
		operands := concatOperands(e)
		for i := 0; i+1 < len(operands); i++ {
			text, ok := stringConstant(info, operands[i])
			if ok && ddlName.MatchString(strings.TrimRight(text, " ")) && strings.HasSuffix(text, " ") {
				return operands[i+1]
			}
		}
	}
	return nil
}

// isFmtSprintf reports a call of fmt.Sprintf.
func isFmtSprintf(info *types.Info, call *ast.CallExpr) bool {
	fn := staticFunc(info, call)
	return fn != nil && fn.Pkg() != nil && fn.Pkg().Path() == "fmt" && fn.Name() == "Sprintf"
}

// nameBuilder returns the Sprintf that builds a name, with the types and the
// function it is in: the name itself, the value of a variable defined once,
// or the result of a project function returning one Sprintf.
func nameBuilder(scope funcScope, fn *ast.FuncDecl, name ast.Expr) (*ast.CallExpr, *types.Info, *ast.FuncDecl) {
	expr := ast.Unparen(name)
	if ident, ok := expr.(*ast.Ident); ok {
		expr = singleDefinitions(scope.info, fn.Body)[scope.info.ObjectOf(ident)]
	}
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return nil, nil, nil
	}
	if isFmtSprintf(scope.info, call) {
		return call, scope.info, fn
	}
	callee, ok := scope.callee(call)
	if !ok {
		return nil, nil, nil
	}
	var built *ast.CallExpr
	ast.Inspect(callee.decl.Body, func(n ast.Node) bool {
		if _, ok := n.(*ast.FuncLit); ok {
			return false
		}
		ret, ok := n.(*ast.ReturnStmt)
		if !ok || len(ret.Results) != 1 {
			return true
		}
		if sprintf, ok := ast.Unparen(ret.Results[0]).(*ast.CallExpr); ok && isFmtSprintf(callee.info, sprintf) {
			built = sprintf
		}
		return true
	})
	if built == nil {
		return nil, nil, nil
	}
	return built, callee.info, callee.decl
}

// sprintfVerb matches a verb of a format, flags and width aside.
var sprintfVerb = regexp.MustCompile(`%[-+# 0]*\d*(?:\.\d+)?([a-zA-Z%])`)

// sprintfWidth returns the longest value of a Sprintf counting the literal
// text and the arguments whose width is bounded, with the parts it added.
func sprintfWidth(info *types.Info, fn *ast.FuncDecl, call *ast.CallExpr) (int, []string) {
	format, ok := stringConstant(info, call.Args[0])
	if !ok {
		return 0, nil
	}
	literal := len(sprintfVerb.ReplaceAllStringFunc(format, func(verb string) string {
		if verb == "%%" {
			return "%"
		}
		return ""
	}))
	width := literal
	parts := []string{fmt.Sprintf("%d of text", literal)}
	arg := 1
	for _, match := range sprintfVerb.FindAllStringSubmatch(format, -1) {
		if match[1] == "%" {
			continue
		}
		if arg >= len(call.Args) {
			break
		}
		if w, what := boundedWidth(info, fn, call.Args[arg], match[1]); w > 0 {
			width += w
			parts = append(parts, fmt.Sprintf("%d of %s", w, what))
		}
		arg++
	}
	return width, parts
}

// clockDigits are the digits of the Unix clock readings now and for
// centuries ahead.
var clockDigits = map[string]int{"Unix": 10, "UnixMilli": 13, "UnixMicro": 16, "UnixNano": 19}

// boundedWidth returns the longest text an argument formats to under a verb,
// 0 when it is not bounded, and what bounds it.
func boundedWidth(info *types.Info, fn *ast.FuncDecl, arg ast.Expr, verb string) (int, string) {
	arg = ast.Unparen(arg)
	if text, ok := stringConstant(info, arg); ok && verb == "s" {
		return len(text), "a constant"
	}
	switch e := arg.(type) {
	case *ast.CallExpr:
		sel, ok := e.Fun.(*ast.SelectorExpr)
		if !ok {
			return 0, ""
		}
		if digits, ok := clockDigits[sel.Sel.Name]; ok && verb == "d" && isTimeValue(info, sel.X) {
			return digits, "a " + sel.Sel.Name + " reading"
		}
		if callee := staticFunc(info, e); callee != nil && callee.Pkg() != nil && callee.Pkg().Path() == "encoding/hex" &&
			callee.Name() == "EncodeToString" && len(e.Args) == 1 && verb == "s" {
			if n := byteLength(info, fn, e.Args[0]); n > 0 {
				return 2 * n, fmt.Sprintf("the hex of %d bytes", n)
			}
		}
	case *ast.Ident:
		obj := info.ObjectOf(e)
		if obj == nil {
			return 0, ""
		}
		if verb == "x" {
			if n := byteLength(info, fn, e); n > 0 {
				return 2 * n, fmt.Sprintf("the hex of %d bytes", n)
			}
		}
		if verb == "s" {
			if n := truncation(info, fn, obj); n > 0 {
				return n, fmt.Sprintf("%s cut to %d", e.Name, n)
			}
			if def := singleDefinitions(info, fn.Body)[obj]; def != nil {
				return boundedWidth(info, fn, def, verb)
			}
		}
	}
	return 0, ""
}

// isTimeValue reports an expression of type time.Time.
func isTimeValue(info *types.Info, expr ast.Expr) bool {
	named, ok := info.TypeOf(expr).(*types.Named)
	return ok && named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == "time" && named.Obj().Name() == "Time"
}

// byteLength returns the length of a byte slice the function makes with a
// constant length: b := make([]byte, 12).
func byteLength(info *types.Info, fn *ast.FuncDecl, expr ast.Expr) int {
	ident, ok := ast.Unparen(expr).(*ast.Ident)
	if !ok {
		return 0
	}
	call, ok := singleDefinitions(info, fn.Body)[info.ObjectOf(ident)].(*ast.CallExpr)
	if !ok || len(call.Args) != 2 {
		return 0
	}
	if fun, ok := call.Fun.(*ast.Ident); !ok || fun.Name != "make" {
		return 0
	}
	tv, ok := info.Types[call.Args[1]]
	if !ok || tv.Value == nil || tv.Value.Kind() != constant.Int {
		return 0
	}
	n, _ := constant.Int64Val(tv.Value)
	return int(n)
}

// truncation returns N of an assignment v = v[:N] of the variable in the
// function: the value is cut to at most N bytes.
func truncation(info *types.Info, fn *ast.FuncDecl, obj types.Object) int {
	n := 0
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		assign, ok := node.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
			return true
		}
		lhs, ok := assign.Lhs[0].(*ast.Ident)
		if !ok || info.ObjectOf(lhs) != obj {
			return true
		}
		slice, ok := ast.Unparen(assign.Rhs[0]).(*ast.SliceExpr)
		if !ok || slice.Low != nil || slice.High == nil {
			return true
		}
		if x, ok := slice.X.(*ast.Ident); !ok || info.ObjectOf(x) != obj {
			return true
		}
		if tv, ok := info.Types[slice.High]; ok && tv.Value != nil && tv.Value.Kind() == constant.Int {
			high, _ := constant.Int64Val(tv.Value)
			n = int(high)
		}
		return true
	})
	return n
}
