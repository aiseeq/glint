package patterns

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"

	"golang.org/x/crypto/sha3"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewHardcodedABISelectorRule())
}

// HardcodedABISelectorRule detects a contract function selector written by
// hand that is not the selector of the signature written beside it:
//
//	const stakeSelector = '0x07836a45' // stake(uint256)   — it is 0xa694fc3a
//
// A selector is the first four bytes of keccak256 of the function signature;
// copied from somewhere by hand it is easily the selector of another function
// or of another version of the contract, and the transaction then reverts or
// calls the wrong method. When the line (or the comment line above it) names
// the signature, the rule computes the selector and reports a literal that
// differs. A literal with no signature beside it is left alone: code that
// recognizes the calls of other parties' contracts keeps their selectors as
// observed data.
type HardcodedABISelectorRule struct {
	*rules.BaseRule
}

// NewHardcodedABISelectorRule creates the rule
func NewHardcodedABISelectorRule() *HardcodedABISelectorRule {
	return &HardcodedABISelectorRule{BaseRule: rules.NewBaseRule(
		"hardcoded-abi-selector",
		"patterns",
		"Detects a contract function selector written as a 0x literal that is not the selector of the signature beside it — derive it from the ABI or the signature",
		core.SeverityHigh,
	)}
}

var (
	selectorLiteral = regexp.MustCompile("['\"`]0x([0-9a-fA-F]{8})['\"`]")
	// solidityTypeText is one parameter type of a function signature.
	solidityTypeText  = `(?:u?int\d*|address|bool|bytes\d*|string)(?:\[\d*\])*`
	functionSignature = regexp.MustCompile(`\b([A-Za-z_]\w*)\(\s*((?:` + solidityTypeText + `(?:\s*,\s*` + solidityTypeText + `)*)?)\s*\)`)
	bareInteger       = regexp.MustCompile(`\b(u?int)\b`)
)

// functionSelector returns the selector of a canonical signature, as 8 hex
// digits in lower case.
func functionSelector(signature string) string {
	hash := sha3.NewLegacyKeccak256()
	hash.Write([]byte(signature))
	return hex.EncodeToString(hash.Sum(nil)[:4])
}

// canonicalSignature spells a signature the way the selector hashes it: no
// spaces, uint and int with their size.
func canonicalSignature(name, params string) string {
	params = strings.Join(strings.Fields(params), "")
	params = bareInteger.ReplaceAllString(params, "${1}256")
	return name + "(" + params + ")"
}

// AnalyzeFile reports the selector literals of a TS/JS or Go file that differ
// from their signature.
func (r *HardcodedABISelectorRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsTypeScriptFile() && !ctx.IsJavaScriptFile() && !ctx.IsGoFile() {
		return nil
	}
	if ctx.IsTestFile() || ctx.IsGenerated() || !strings.Contains(string(ctx.Content), "0x") {
		return nil
	}
	// The JS masks read Go well enough here: both have the same quotes and
	// comments.
	code, text := helpers.FileJSCode(ctx), helpers.FileJSText(ctx)
	var violations []*core.Violation
	for i, line := range text {
		if !strings.Contains(line, "0x") {
			continue
		}
		for _, loc := range selectorLiteral.FindAllStringSubmatchIndex(line, -1) {
			if code[i][loc[0]] != line[loc[0]] {
				continue // a quote inside a literal, not one
			}
			selector := strings.ToLower(line[loc[2]:loc[3]])
			signature, wrong := mismatchedSignature(ctx.Lines, code, i, loc, selector)
			if !wrong || ctx.IsSuppressed(i+1, r.Name()) {
				continue
			}
			v := r.CreateViolation(ctx.RelPath, i+1, fmt.Sprintf(
				"Selector 0x%s is not the selector of %s, which is 0x%s — the call goes to another function or reverts",
				selector, signature, functionSelector(signature)))
			v.WithCode(strings.TrimSpace(ctx.Lines[i]))
			v.WithSuggestion("Derive the selector from the signature (keccak256(\"stake(uint256)\")[:4], ethers Interface.getFunction(...).selector, abi.Pack) or encode the call from the contract ABI")
			violations = append(violations, v)
		}
	}
	return violations
}

// mismatchedSignature returns the signature written beside the selector
// literal at loc of line i — in a comment or a literal of that line, or on a
// comment line above it — when the selector is not its selector. A literal
// beside the signature it encodes, or beside none, gives false.
func mismatchedSignature(lines, code []string, i int, loc []int, selector string) (string, bool) {
	prose := literalAndCommentText(lines[i], code[i], loc[0], loc[1])
	if i > 0 && strings.TrimSpace(code[i-1]) == "" {
		prose += " " + lines[i-1]
	}
	var first string
	for _, m := range functionSignature.FindAllStringSubmatch(prose, -1) {
		signature := canonicalSignature(m[1], m[2])
		if functionSelector(signature) == selector {
			return "", false
		}
		if first == "" {
			first = signature
		}
	}
	return first, first != ""
}

// literalAndCommentText keeps the parts of a line that are not code — the
// contents of literals and comments — except the span from..to.
func literalAndCommentText(raw, code string, from, to int) string {
	out := []byte(raw)
	for j := range out {
		if j < len(code) && code[j] == raw[j] || j >= from && j < to {
			out[j] = ' '
		}
	}
	return string(out)
}
