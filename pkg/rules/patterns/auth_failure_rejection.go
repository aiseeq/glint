package patterns

import (
	"errors"
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
	rules.Register(NewAuthFailureClassifiedAsRejectionRule())
}

// AuthFailureClassifiedAsRejectionRule detects a classifier that answers yes
// for the whole 4xx range of a status, leaves some codes out of it, and
// leaves 401 and 403 in:
//
//	switch apiErr.StatusCode {
//	case http.StatusRequestTimeout, http.StatusTooManyRequests:
//		return "", false
//	}
//	if apiErr.StatusCode < 400 || apiErr.StatusCode >= 500 {
//		return "", false
//	}
//	return reason, true
//
// The excluded codes show what the function decides: whether the other side
// answered on the merits - refused the payment, rejected the request for
// good. 401 and 403 are no such answer: they say our credentials failed (a
// token expired, a key rotated), and the classifier turns a valid operation
// into a terminal rejection. A function whose 4xx range answers no (a retry
// decision), a bare range test without exclusions, and a function whose doc
// comment speaks of credentials or 401/403 - the decision about them taken
// on purpose - are left alone.
type AuthFailureClassifiedAsRejectionRule struct {
	*rules.BaseRule
}

// NewAuthFailureClassifiedAsRejectionRule creates the rule
func NewAuthFailureClassifiedAsRejectionRule() *AuthFailureClassifiedAsRejectionRule {
	return &AuthFailureClassifiedAsRejectionRule{BaseRule: rules.NewBaseRule(
		"auth-failure-classified-as-rejection",
		"patterns",
		"Detects a classifier taking the 4xx range of a status for a verdict on the request, with exclusions that leave 401 and 403 in — our failed credentials become the other side's rejection",
		core.SeverityHigh,
	)}
}

// AnalyzeFile is a no-op: status codes are recognized by their constant value.
func (r *AuthFailureClassifiedAsRejectionRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *AuthFailureClassifiedAsRejectionRule) RequiresSSA() bool { return false }

// AnalyzeGoProject reports the 4xx verdicts that take in 401 and 403.
func (r *AuthFailureClassifiedAsRejectionRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, errors.New("auth failure classified as rejection: nil Go project context")
	}
	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(file *core.FileContext, info *types.Info) []*core.Violation {
		var violations []*core.Violation
		for _, decl := range file.GoAST.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || !returnsBoolLast(info, fn) || namesCredentialCodes(fn.Doc) {
				continue
			}
			for _, check := range clientRangeVerdicts(info, fn) {
				codes := comparedStatusCodes(info, fn.Body, check.status)
				if codes[401] || codes[403] || !excludesOther4xx(codes) {
					continue
				}
				line := file.LineFor(check.expr)
				if file.IsSuppressed(line, r.Name()) {
					continue
				}
				v := r.CreateViolation(file.RelPath, line,
					"Every 4xx but the excluded codes is taken for the other side's verdict, and 401/403 are not excluded — a failure of our own credentials becomes a terminal rejection")
				v.WithCode(strings.TrimSpace(file.GetLine(line)))
				v.WithSuggestion("Exclude 401 and 403 with the other codes that say nothing about the request, and treat them as our own failure (outcome unknown, credentials to refresh)")
				violations = append(violations, v)
			}
		}
		return violations
	})
}

// credentialCodeWords are how a doc comment shows that 401 and 403 were weighed.
var credentialCodeWords = regexp.MustCompile(`(?i)credential|unauthori[sz]ed|forbidden|\b40[13]\b`)

// namesCredentialCodes reports a doc comment speaking of credentials or of
// 401/403.
func namesCredentialCodes(doc *ast.CommentGroup) bool {
	return doc != nil && credentialCodeWords.MatchString(doc.Text())
}

// returnsBoolLast reports a function whose last result is a bool.
func returnsBoolLast(info *types.Info, fn *ast.FuncDecl) bool {
	results := fn.Type.Results
	if results == nil || len(results.List) == 0 {
		return false
	}
	basic, ok := info.TypeOf(results.List[len(results.List)-1].Type).(*types.Basic)
	return ok && basic.Kind() == types.Bool
}

// rangeVerdict is a test of the 4xx range of a status the function answers
// true for.
type rangeVerdict struct {
	expr   ast.Expr
	status string
}

// clientRangeVerdicts returns the 4xx range tests whose range answers true:
// `if s < 400 || s >= 500 { return false }` before a final `return true`,
// `if s >= 400 && s < 500 { return true }`, or `return s >= 400 && s < 500`.
func clientRangeVerdicts(info *types.Info, fn *ast.FuncDecl) []rangeVerdict {
	var verdicts []rangeVerdict
	endsTrue := lastReturnsLiteral(fn.Body, "true")
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.IfStmt:
			if status, inside := clientRange(info, node.Cond); status != "" {
				answer := lastReturnsLiteral(node.Body, "true")
				if (inside && answer) || (!inside && lastReturnsLiteral(node.Body, "false") && endsTrue) {
					verdicts = append(verdicts, rangeVerdict{expr: node.Cond, status: status})
				}
			}
		case *ast.ReturnStmt:
			if len(node.Results) > 0 {
				last := node.Results[len(node.Results)-1]
				if status, inside := clientRange(info, last); status != "" && inside {
					verdicts = append(verdicts, rangeVerdict{expr: last, status: status})
				}
			}
		}
		return true
	})
	return verdicts
}

// lastReturnsLiteral reports a block ending in a return whose last result is
// the identifier name (true, false).
func lastReturnsLiteral(body *ast.BlockStmt, name string) bool {
	if len(body.List) == 0 {
		return false
	}
	ret, ok := body.List[len(body.List)-1].(*ast.ReturnStmt)
	return ok && len(ret.Results) > 0 && isIdentNamed(ret.Results[len(ret.Results)-1], name)
}

// clientRange returns the status a condition tests against the 4xx range,
// and whether it is true inside the range (s >= 400 && s < 500) or outside
// it (s < 400 || s >= 500).
func clientRange(info *types.Info, cond ast.Expr) (string, bool) {
	bin, ok := ast.Unparen(cond).(*ast.BinaryExpr)
	if !ok || (bin.Op != token.LAND && bin.Op != token.LOR) {
		return "", false
	}
	left, lowOp, lowValue := statusComparison(info, bin.X)
	right, highOp, highValue := statusComparison(info, bin.Y)
	if left == "" || left != right {
		return "", false
	}
	if bin.Op == token.LAND {
		above400 := (lowOp == token.GEQ && lowValue == 400) || (lowOp == token.GTR && lowValue == 399)
		below500 := (highOp == token.LSS && highValue == 500) || (highOp == token.LEQ && highValue == 499)
		if above400 && below500 {
			return left, true
		}
		return "", false
	}
	below400 := (lowOp == token.LSS && lowValue == 400) || (lowOp == token.LEQ && lowValue == 399)
	above500 := (highOp == token.GEQ && highValue == 500) || (highOp == token.GTR && highValue == 499)
	if below400 && above500 {
		return left, false
	}
	return "", false
}

// statusComparison splits `s OP n` with a constant n into s, OP and n.
func statusComparison(info *types.Info, expr ast.Expr) (string, token.Token, int64) {
	bin, ok := ast.Unparen(expr).(*ast.BinaryExpr)
	if !ok {
		return "", token.ILLEGAL, 0
	}
	value, ok := intConstant(info, bin.Y)
	if !ok {
		return "", token.ILLEGAL, 0
	}
	return types.ExprString(bin.X), bin.Op, value
}

// intConstant returns the value of an integer constant expression.
func intConstant(info *types.Info, expr ast.Expr) (int64, bool) {
	tv, ok := info.Types[expr]
	if !ok || tv.Value == nil || tv.Value.Kind() != constant.Int {
		return 0, false
	}
	return constant.Int64Val(tv.Value)
}

// comparedStatusCodes returns the constants the function compares the
// status with: s == 429, switch s { case 408, 429: }.
func comparedStatusCodes(info *types.Info, body *ast.BlockStmt, status string) map[int64]bool {
	codes := make(map[int64]bool)
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.BinaryExpr:
			if (node.Op == token.EQL || node.Op == token.NEQ) && types.ExprString(node.X) == status {
				if value, ok := intConstant(info, node.Y); ok {
					codes[value] = true
				}
			}
		case *ast.SwitchStmt:
			if node.Tag == nil || types.ExprString(node.Tag) != status {
				return true
			}
			for _, clause := range node.Body.List {
				if caseClause, ok := clause.(*ast.CaseClause); ok {
					for _, expr := range caseClause.List {
						if value, ok := intConstant(info, expr); ok {
							codes[value] = true
						}
					}
				}
			}
		}
		return true
	})
	return codes
}

// excludesOther4xx reports a code above 400 and below 500 among the codes.
func excludesOther4xx(codes map[int64]bool) bool {
	for code := range codes {
		if code > 400 && code < 500 {
			return true
		}
	}
	return false
}
