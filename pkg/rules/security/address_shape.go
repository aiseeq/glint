package security

import (
	"go/ast"
	"regexp"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewAddressValidatedByShapeRule())
}

// AddressValidatedByShapeRule detects an address validator that looks only at
// the length and the first characters:
//
//	func isChainAAddress(a string) bool {
//	    if len(a) < 34 || len(a) > 42 { return false }
//	    return strings.HasPrefix(a, "TR")
//	}
//
// Any string of that shape passes: a mistyped address, one of another chain,
// a test placeholder. Funds sent to it are lost. Real validation decodes the
// address and checks its checksum (base58check, EIP-55) or calls a library
// that does. Validators of network or mail addresses (Private, Local, IP,
// Email in the name) classify rather than validate and are left alone, and so
// is a bool predicate the file never calls negated: switched on, it picks a
// chain for an address, it does not admit one.
type AddressValidatedByShapeRule struct {
	*rules.BaseRule
}

// NewAddressValidatedByShapeRule creates the rule
func NewAddressValidatedByShapeRule() *AddressValidatedByShapeRule {
	return &AddressValidatedByShapeRule{BaseRule: rules.NewBaseRule(
		"address-validated-by-shape",
		"security",
		"Detects an address validator that checks only length and prefix — a mistyped or foreign address passes and funds sent to it are lost",
		core.SeverityHigh,
	)}
}

var (
	addressValidatorName = regexp.MustCompile(`^(?:is|IsValid|isValid|valid|Valid|validate|Validate|check|Check)\w*Address$`)
	nonChainAddressWords = map[string]bool{
		"private": true, "local": true, "loopback": true, "internal": true, "public": true, "ip": true,
		"email": true, "mail": true, "net": true, "network": true, "host": true, "remote": true,
		"listen": true, "bind": true, "server": true, "peer": true, "billing": true, "shipping": true, "street": true,
	}
	shapeOnlyCalls = map[string]bool{"len": true, "HasPrefix": true, "HasSuffix": true, "New": true, "Errorf": true}
)

// AnalyzeFile reports validators that check only an address's shape.
func (r *AddressValidatedByShapeRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.HasGoAST() || ctx.IsTestFile() {
		return nil
	}
	lr := newLineReporter(ctx, r.BaseRule)
	gates := negatedCalls(ctx.GoAST)
	for _, decl := range ctx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || fn.Recv != nil || !addressValidatorName.MatchString(fn.Name.Name) || namesNonChainAddress(fn.Name.Name) {
			continue
		}
		// A bool predicate only switched on picks a chain for an address it
		// is given; one that turns an address away (!isX(a)) validates it.
		if returnsBool(fn.Type) && !gates[fn.Name.Name] {
			continue
		}
		if prefixOnly(fn.Body) {
			lr.report(fn.Name, fn.Name.Name+" checks only the length and prefix of the address — a mistyped or foreign address passes",
				"Decode the address and check its checksum (base58check, EIP-55), or use the chain library's validator", "address_validated_by_shape")
		}
	}
	return lr.violations
}

// negatedCalls returns the functions a file calls under a negation: !isX(a).
func negatedCalls(file *ast.File) map[string]bool {
	negated := make(map[string]bool)
	ast.Inspect(file, func(n ast.Node) bool {
		if not, ok := n.(*ast.UnaryExpr); ok && not.Op.String() == "!" {
			if call, ok := ast.Unparen(not.X).(*ast.CallExpr); ok {
				negated[callName(call)] = true
			}
		}
		return true
	})
	return negated
}

// returnsBool reports a function with the single result bool.
func returnsBool(fn *ast.FuncType) bool {
	return fn.Results != nil && len(fn.Results.List) == 1 && isBoolType(fn.Results.List[0].Type)
}

// prefixOnly reports a body whose calls are all len, prefix and suffix tests
// or error constructors, with at least one prefix test, and no loop.
func prefixOnly(body *ast.BlockStmt) bool {
	prefix, other := false, false
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.ForStmt, *ast.RangeStmt:
			other = true
		case *ast.CallExpr:
			name := callName(node)
			if !shapeOnlyCalls[name] {
				other = true
			}
			prefix = prefix || name == "HasPrefix"
		}
		return !other
	})
	return prefix && !other
}

// namesNonChainAddress reports a name with a word of a network or mail
// address: remoteAddr, emailAddress, isPrivateAddress.
func namesNonChainAddress(name string) bool {
	for _, word := range helpers.IdentifierWords(name) {
		if nonChainAddressWords[word] {
			return true
		}
	}
	return false
}
