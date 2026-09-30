package patterns

import (
	"go/ast"
	"go/token"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewTimeDerivedIDRule())
}

// TimeDerivedIDRule detects identifiers made from the clock:
//
//	userID := fmt.Sprintf("user-%d", time.Now().UnixNano())
//	return fmt.Sprintf("jti_%s_%d", adminID, issued.UnixNano())
//	uniqueIndex := int(time.Now().UnixNano() % 50)
//	const clientNumber = String(100002 + (Date.now() % 899998))
//
// Two calls in the same tick — parallel requests, parallel test workers —
// get the same identifier, and anyone who knows roughly when it was made can
// guess it. The clock reduced modulo a small number picks one of a few
// values and collides as soon as two runs overlap — in test code too, where
// parallel workers share the database. A value that also carries a random
// part, a UUID or a counter is left alone.
type TimeDerivedIDRule struct {
	*rules.BaseRule
	tsClockName *regexp.Regexp
	tsDecl      *regexp.Regexp
}

// NewTimeDerivedIDRule creates the rule
func NewTimeDerivedIDRule() *TimeDerivedIDRule {
	return &TimeDerivedIDRule{
		BaseRule: rules.NewBaseRule(
			"time-derived-id",
			"patterns",
			"Detects identifiers formatted from the clock or taken as the clock modulo a small number",
			core.SeverityMedium,
		),
		tsClockName: regexp.MustCompile(`\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=]+)?=\s*(?:Date\.now\(\)|new Date\(\)\.getTime\(\)|performance\.now\(\))\s*;?\s*$`),
		tsDecl:      regexp.MustCompile(`\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=]+)?=\s*(.+)$`),
	}
}

// clockMethods read a time.Time as a number that changes with every call.
var clockMethods = map[string]bool{"Unix": true, "UnixNano": true, "UnixMilli": true, "UnixMicro": true, "Nanosecond": true}

// maxClockModulus is the largest modulus that squeezes the clock into few
// enough values to collide; a larger one only trims its digits.
const maxClockModulus = 10_000_000

// disambiguator names a part that keeps two values of the same tick apart.
var disambiguator = regexp.MustCompile(`(?i)rand|uuid|atomic|counter|seq`)

// uniqueNumberName names a number meant to tell records apart.
var uniqueNumberName = regexp.MustCompile(`(?i)unique|number|account|wallet|client|user`)

// AnalyzeFile reports the identifiers a Go or TypeScript file makes from the clock.
func (r *TimeDerivedIDRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	switch {
	case ctx.HasGoAST():
		return r.analyzeGo(ctx)
	case ctx.IsTypeScriptFile() || ctx.IsJavaScriptFile():
		if isVendoredOrGeneratedPath(ctx.RelPath) {
			return nil
		}
		return r.analyzeScript(ctx)
	}
	return nil
}

func (r *TimeDerivedIDRule) violation(ctx *core.FileContext, line int, message, pattern string) *core.Violation {
	v := r.CreateViolation(ctx.RelPath, line, message)
	v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
	v.WithSuggestion("Take the identifier from the database, a UUID or crypto/rand; a number unique per record from a sequence")
	v.WithContext("pattern", pattern)
	return v
}

func (r *TimeDerivedIDRule) analyzeGo(ctx *core.FileContext) []*core.Violation {
	var violations []*core.Violation
	reported := make(map[int]bool)
	report := func(node ast.Node, message, pattern string) {
		line := ctx.LineFor(node)
		if reported[line] || ctx.IsSuppressed(line, r.Name()) {
			return
		}
		reported[line] = true
		violations = append(violations, r.violation(ctx, line, message, pattern))
	}
	for _, decl := range ctx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		clock := make(map[string]bool)
		check := func(target string, value ast.Expr, at ast.Node) {
			if disambiguated(value) {
				return
			}
			// Tests name their records after the clock all the time; what
			// collides there is a clock squeezed into a few values.
			if isIDName(target) && !ctx.IsTestFile() && clockFormatted(value, clock) {
				report(at, "The identifier is made from the clock — two calls in the same tick get the same one, and it is guessed from the time",
					"id_from_clock")
			}
			if (isIDName(target) || uniqueNumberName.MatchString(target)) && clockModulo(value, clock) {
				report(at, "The clock modulo a small number picks one of a few values — two runs in the same window get the same one",
					"clock_modulo")
			}
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.AssignStmt:
				if len(node.Lhs) != len(node.Rhs) {
					return true
				}
				for i, rhs := range node.Rhs {
					check(assignedName(node.Lhs[i]), rhs, node)
					if ident, ok := node.Lhs[i].(*ast.Ident); ok && clockNumber(rhs, clock) {
						clock[ident.Name] = true
					}
				}
			case *ast.KeyValueExpr:
				if key, ok := node.Key.(*ast.Ident); ok {
					check(key.Name, node.Value, node)
				}
			case *ast.ReturnStmt:
				if len(node.Results) == 1 {
					check(fn.Name.Name, node.Results[0], node)
				}
			}
			return true
		})
	}
	return violations
}

// assignedName returns the name an assignment writes: x or s.X.
func assignedName(expr ast.Expr) string {
	switch e := ast.Unparen(expr).(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		return e.Sel.Name
	}
	return ""
}

// isClockCall reports t.Unix(), t.UnixNano(), t.UnixMilli(), t.UnixMicro().
func isClockCall(expr ast.Expr) bool {
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok || len(call.Args) != 0 {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	return ok && clockMethods[sel.Sel.Name]
}

// readsClock reports an expression that reads the clock or a name holding it.
func readsClock(expr ast.Expr, clock map[string]bool) bool {
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		if e, ok := n.(ast.Expr); ok && isClockCall(e) {
			found = true
		}
		if ident, ok := n.(*ast.Ident); ok && clock[ident.Name] {
			found = true
		}
		return !found
	})
	return found
}

// clockNumber reports a number computed from the clock: the clock itself, a
// conversion of it, arithmetic on it. A string formatted from it is the
// identifier already reported where it is made.
func clockNumber(expr ast.Expr, clock map[string]bool) bool {
	switch e := ast.Unparen(expr).(type) {
	case *ast.Ident:
		return clock[e.Name]
	case *ast.UnaryExpr:
		return clockNumber(e.X, clock)
	case *ast.BinaryExpr:
		if isStringLit(e.X) || isStringLit(e.Y) {
			return false
		}
		return clockNumber(e.X, clock) || clockNumber(e.Y, clock)
	case *ast.CallExpr:
		if isClockCall(e) {
			return true
		}
		switch helpers.ExprText(e.Fun) {
		case "int", "int32", "int64", "uint", "uint32", "uint64", "float64":
			return len(e.Args) == 1 && clockNumber(e.Args[0], clock)
		}
	}
	return false
}

func isStringLit(expr ast.Expr) bool {
	lit, ok := ast.Unparen(expr).(*ast.BasicLit)
	return ok && lit.Kind == token.STRING
}

// clockFormatted reports a value that is the clock, or the clock formatted
// into a string: fmt.Sprintf, strconv, a conversion, a concatenation.
func clockFormatted(expr ast.Expr, clock map[string]bool) bool {
	switch e := ast.Unparen(expr).(type) {
	case *ast.Ident:
		return clock[e.Name]
	case *ast.BinaryExpr:
		return e.Op == token.ADD && (clockFormatted(e.X, clock) || clockFormatted(e.Y, clock))
	case *ast.CallExpr:
		if isClockCall(e) {
			return true
		}
		switch helpers.ExprText(e.Fun) {
		case "fmt.Sprintf", "fmt.Sprint", "strconv.FormatInt", "strconv.FormatUint", "strconv.Itoa",
			"string", "int", "int64", "uint64":
			for _, arg := range e.Args {
				if clockFormatted(arg, clock) {
					return true
				}
			}
		}
	}
	return false
}

// clockModulo reports the clock, or a value computed from it, modulo a number
// written in the code and small enough to leave few values.
func clockModulo(expr ast.Expr, clock map[string]bool) bool {
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		bin, ok := n.(*ast.BinaryExpr)
		if ok && bin.Op == token.REM && readsClock(bin.X, clock) {
			if lit, isLit := ast.Unparen(bin.Y).(*ast.BasicLit); isLit && lit.Kind == token.INT {
				n, err := strconv.ParseInt(lit.Value, 0, 64)
				found = err == nil && n <= maxClockModulus
			}
		}
		return !found
	})
	return found
}

// disambiguated reports a value that also carries a random part, a UUID or a
// counter.
func disambiguated(expr ast.Expr) bool {
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		if ident, ok := n.(*ast.Ident); ok && disambiguator.MatchString(ident.Name) {
			found = true
		}
		return !found
	})
	return found
}

// isIDName reports a name that holds an identifier: id, userID, RequestID,
// generateJTI, user_id, nonce.
func isIDName(name string) bool {
	switch strings.ToLower(name) {
	case "id", "jti", "nonce", "uuid":
		return true
	}
	if strings.HasSuffix(name, "_id") {
		return true
	}
	for _, suffix := range []string{"ID", "Id", "JTI", "Jti", "Nonce", "UUID", "Uuid"} {
		if rest, ok := strings.CutSuffix(name, suffix); ok && rest != "" {
			last := rune(rest[len(rest)-1])
			return unicode.IsLower(last) || unicode.IsDigit(last)
		}
	}
	return false
}

func (r *TimeDerivedIDRule) analyzeScript(ctx *core.FileContext) []*core.Violation {
	code := helpers.FileJSCode(ctx)
	clocks := []string{`Date\.now\(\)`}
	for _, line := range code {
		if m := r.tsClockName.FindStringSubmatch(line); m != nil {
			clocks = append(clocks, `\b`+regexp.QuoteMeta(m[1])+`\b`)
		}
	}
	modulo := regexp.MustCompile(`(?:` + strings.Join(clocks, "|") + `)\s*%\s*\d`)
	var violations []*core.Violation
	for i, line := range code {
		m := r.tsDecl.FindStringSubmatch(line)
		if m == nil || !(isIDName(m[1]) || uniqueNumberName.MatchString(m[1])) || !modulo.MatchString(m[2]) {
			continue
		}
		if disambiguator.MatchString(m[2]) || ctx.IsSuppressed(i+1, r.Name()) {
			continue
		}
		violations = append(violations, r.violation(ctx, i+1,
			"The clock modulo a small number picks one of a few values — two runs in the same window get the same one", "clock_modulo"))
	}
	return violations
}
