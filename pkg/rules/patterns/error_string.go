package patterns

import (
	"go/ast"
	"regexp"
	"strings"
	"unicode"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewErrorStringRule())
}

// ErrorStringRule detects error strings that don't follow Go conventions
type ErrorStringRule struct {
	*rules.BaseRule
	// Common acronyms that are acceptable at the start
	acronyms map[string]bool
}

// NewErrorStringRule creates the rule
func NewErrorStringRule() *ErrorStringRule {
	return &ErrorStringRule{
		BaseRule: rules.NewBaseRule(
			"error-string",
			"patterns",
			"Error strings should not be capitalized or end with punctuation (Go convention)",
			core.SeverityLow,
		),
		acronyms: map[string]bool{
			// Standard tech acronyms
			"API": true, "URL": true, "HTTP": true, "HTTPS": true,
			"JSON": true, "XML": true, "SQL": true, "EOF": true,
			"ID": true, "UUID": true, "JWT": true, "JWKS": true,
			"TLS": true, "SSL": true, "DNS": true, "TCP": true,
			"UDP": true, "IP": true, "OS": true, "IO": true,
			"DI": true, "CSRF": true, "SSE": true, "MFA": true,
			"RPC": true, "gRPC": true, "REST": true, "SOAP": true,
			// Email/SMTP protocol
			"SMTP": true, "MAIL": true, "RCPT": true, "DATA": true,
			"POP3": true, "IMAP": true,
			// SQL keywords (often appear in database error messages)
			"SELECT": true, "INSERT": true, "UPDATE": true, "DELETE": true,
			"WHERE": true, "FROM": true, "JOIN": true, "CREATE": true,
			"DROP": true, "ALTER": true, "INDEX": true, "TABLE": true,
			// Crypto/blockchain
			"ETH": true, "BTC": true, "USDC": true, "USDT": true,
			"ERC": true, "NFT": true, "HD": true, "BIP": true,
			// Severity markers (intentionally capitalized)
			"CRITICAL": true, "SECURITY": true, "WARNING": true,
			"ERROR": true, "FATAL": true, "IMPORTANT": true,
			// Common English words that start errors (acceptable)
			"User": true, "No": true, "Not": true, "The": true,
			"This": true, "An": true, "A": true, "Invalid": true,
			"Missing": true, "Unknown": true, "Failed": true,
			"Cannot": true, "Could": true, "Unable": true,
			"List": true, "Search": true, "Get": true, "Set": true,
			"INTERFACE": true, "WRAPPER": true, "INTERNAL": true,
		},
	}
}

var errorFuncs = map[string]bool{
	"errors.New": true,
	"fmt.Errorf": true,
}

var errorStringPattern = regexp.MustCompile(`^["` + "`" + `]([^"` + "`" + `]+)["` + "`" + `]`)

// AnalyzeFile checks error string formatting
func (r *ErrorStringRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || !ctx.HasGoAST() {
		return nil
	}

	var violations []*core.Violation

	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		if vs := r.checkCall(ctx, n); len(vs) > 0 {
			violations = append(violations, vs...)
		}
		return true
	})

	return violations
}

func (r *ErrorStringRule) checkCall(ctx *core.FileContext, n ast.Node) []*core.Violation {
	call, ok := n.(*ast.CallExpr)
	if !ok || !r.isErrorCreation(call) || len(call.Args) == 0 {
		return nil
	}

	lit, ok := call.Args[0].(*ast.BasicLit)
	if !ok {
		return nil
	}

	val := strings.Trim(lit.Value, "`\"")
	if val == "" {
		return nil
	}

	return r.checkErrorString(ctx, lit, val)
}

func (r *ErrorStringRule) checkErrorString(ctx *core.FileContext, lit *ast.BasicLit, val string) []*core.Violation {
	var violations []*core.Violation
	pos := ctx.PositionFor(lit)

	if r.startsWithCapital(val) {
		v := r.CreateViolation(ctx.RelPath, pos.Line, "Error strings should not be capitalized")
		v.WithCode(ctx.GetLine(pos.Line))
		v.WithSuggestion("Use lowercase for error strings (Go convention)")
		violations = append(violations, v)
	}

	if r.endsWithPunctuation(val) {
		v := r.CreateViolation(ctx.RelPath, pos.Line, "Error strings should not end with punctuation")
		v.WithCode(ctx.GetLine(pos.Line))
		v.WithSuggestion("Remove trailing punctuation from error string")
		violations = append(violations, v)
	}

	return violations
}

func (r *ErrorStringRule) isErrorCreation(call *ast.CallExpr) bool {
	// Check for errors.New or fmt.Errorf
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}

	ident, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}

	funcName := ident.Name + "." + sel.Sel.Name
	return errorFuncs[funcName]
}

func (r *ErrorStringRule) startsWithCapital(s string) bool {
	if len(s) == 0 {
		return false
	}

	// Check for format verbs at start (like %s, %v)
	if s[0] == '%' {
		return false
	}

	// Get first rune properly (handles UTF-8 including Cyrillic)
	runes := []rune(s)
	firstRune := runes[0]

	// Only check Latin letters for capitalization
	// Non-Latin scripts (Cyrillic, etc.) have different conventions
	// and error messages in these languages are valid
	if !unicode.Is(unicode.Latin, firstRune) {
		return false
	}

	if !unicode.IsUpper(firstRune) {
		return false
	}

	// Check if it's a known acronym or allowed starter word
	firstWord := strings.Split(s, " ")[0]
	firstWord = strings.TrimRight(firstWord, ":")
	// Check both as-is (for common words like "User") and uppercase (for acronyms)
	if r.acronyms[firstWord] || r.acronyms[strings.ToUpper(firstWord)] {
		return false
	}

	// Check if it looks like a Go identifier (PascalCase function/type name)
	// e.g., "ValidationService", "GetAdminByEmail", "UnifiedConfig"
	if r.isPascalCaseIdentifier(firstWord) {
		return false
	}

	// Check if it looks like an error code (UPPER_SNAKE_CASE)
	// e.g., "CRYPTO2B_CONFIG_LOAD_FAILED:", "SECURITY_ERROR:"
	if r.isErrorCode(firstWord) {
		return false
	}

	return true
}

// isErrorCode checks if word looks like an error code (UPPER_SNAKE_CASE or UPPER-KEBAB-CASE)
func (r *ErrorStringRule) isErrorCode(word string) bool {
	if len(word) < 3 {
		return false
	}

	// Remove trailing colon if present
	word = strings.TrimSuffix(word, ":")

	// Must contain underscore or hyphen for error code patterns
	// Supports: SNAKE_CASE, KEBAB-CASE (like APPEND-ONLY)
	if !strings.Contains(word, "_") && !strings.Contains(word, "-") {
		return false
	}

	// All letters must be uppercase
	for _, ch := range word {
		if unicode.IsLetter(ch) && !unicode.IsUpper(ch) {
			return false
		}
	}

	return true
}

// isPascalCaseIdentifier checks if word looks like a Go identifier (PascalCase)
func (r *ErrorStringRule) isPascalCaseIdentifier(word string) bool {
	if len(word) < 2 {
		return false
	}

	runes := []rune(word)

	// Must start with uppercase
	if !unicode.IsUpper(runes[0]) {
		return false
	}

	// Check for PascalCase pattern: has lowercase after uppercase, or another uppercase
	hasLower := false
	hasMultipleCaps := false
	for i := 1; i < len(runes); i++ {
		if unicode.IsLower(runes[i]) {
			hasLower = true
		}
		if unicode.IsUpper(runes[i]) {
			hasMultipleCaps = true
		}
	}

	// PascalCase: either "ValidationService" (has both upper and lower)
	// or has multiple capitals like "GetURL" or ends with known suffix
	if hasLower && hasMultipleCaps {
		return true
	}

	// Check for common Go type/function suffixes
	suffixes := []string{"Service", "Config", "Manager", "Handler", "Repository", "Interface", "Error", "Exception", "Client", "Server", "Factory", "Builder", "Provider", "Validator", "Controller", "Module", "Dependencies"}
	for _, suffix := range suffixes {
		if strings.HasSuffix(word, suffix) {
			return true
		}
	}

	// Check for common Go function prefixes
	prefixes := []string{"Get", "Set", "New", "Create", "Delete", "Update", "Find", "Is", "Has", "Can", "Must", "Should", "Validate", "Parse", "Format", "Convert", "Build", "Make", "Init", "Load", "Save", "Read", "Write", "Open", "Close", "Start", "Stop", "Run", "Execute", "Process", "Handle", "Register", "Unregister", "Add", "Remove", "Assign"}
	for _, prefix := range prefixes {
		if strings.HasPrefix(word, prefix) && len(word) > len(prefix) {
			return true
		}
	}

	return false
}

func (r *ErrorStringRule) endsWithPunctuation(s string) bool {
	if len(s) == 0 {
		return false
	}

	// Check for format verbs at end
	if len(s) >= 2 && s[len(s)-2] == '%' {
		return false
	}

	lastRune := rune(s[len(s)-1])
	// . ! ? are problematic, but : is often used in structured errors
	return lastRune == '.' || lastRune == '!' || lastRune == '?'
}
