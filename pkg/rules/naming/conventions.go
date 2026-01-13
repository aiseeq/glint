package naming

import (
	"go/ast"
	"strings"
	"unicode"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewNamingConventionsRule())
}

// NamingConventionsRule detects Go naming convention violations
type NamingConventionsRule struct {
	*rules.BaseRule
	// Known acronyms that are correctly written in ALL_CAPS
	knownAcronyms map[string]bool
}

// NewNamingConventionsRule creates the rule
func NewNamingConventionsRule() *NamingConventionsRule {
	return &NamingConventionsRule{
		BaseRule: rules.NewBaseRule(
			"naming-convention",
			"naming",
			"Detects Go naming convention violations (stuttering, underscore, ALL_CAPS)",
			core.SeverityLow,
		),
		knownAcronyms: map[string]bool{
			// Standard Go acronyms (per Effective Go)
			"ID": true, "URL": true, "URI": true, "HTTP": true, "HTTPS": true,
			"API": true, "JSON": true, "XML": true, "HTML": true, "CSS": true,
			"SQL": true, "RPC": true, "TCP": true, "UDP": true, "IP": true,
			"TLS": true, "SSL": true, "SSH": true, "DNS": true,
			"EOF": true, "UUID": true, "UID": true, "GID": true,
			"CPU": true, "GPU": true, "RAM": true, "ROM": true,
			"OS": true, "IO": true, "UI": true, "CLI": true, "GUI": true,
			"OK": true, "ACL": true, "ASCII": true, "UTF8": true,
			// Auth/crypto
			"JWT": true, "JWK": true, "JWKS": true, "JWE": true,
			"RSA": true, "AES": true, "SHA": true, "MD5": true,
			"HMAC": true, "ECDSA": true, "PKCS": true,
			"MFA": true, "OTP": true, "TOTP": true, "HOTP": true,
			"CSRF": true, "XSS": true, "CORS": true,
			// Database
			"JSONB": true, "BSON": true, "BLOB": true, "CLOB": true,
			"DDL": true, "DML": true, "CRUD": true,
			// Blockchain
			"ETH": true, "BTC": true, "NFT": true, "ERC": true,
			"USDC": true, "USDT": true, "DAI": true,
			// Protocols
			"SMTP": true, "IMAP": true, "POP3": true,
			"FTP": true, "SFTP": true, "SCP": true,
			"GRPC": true, "REST": true, "SOAP": true,
			"SSE": true, "WS": true, "WSS": true,
			// Other common
			"YAML": true, "TOML": true, "CSV": true, "TSV": true,
			"PDF": true, "PNG": true, "JPG": true, "JPEG": true, "GIF": true,
			"SVG": true, "MP3": true, "MP4": true,
			"AWS": true, "GCP": true, "CDN": true,
			"SLA": true, "KPI": true, "ROI": true,
			"DI": true, "IOC": true, "ORM": true, "DTO": true, "DAO": true,
			"FIFO": true, "LIFO": true, "LRU": true,
		},
	}
}

// AnalyzeFile checks for naming convention violations
func (r *NamingConventionsRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || ctx.GoAST == nil {
		return nil
	}

	var violations []*core.Violation
	packageName := ctx.GoAST.Name.Name

	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.TypeSpec:
			violations = append(violations, r.checkTypeName(ctx, node, packageName)...)

		case *ast.FuncDecl:
			violations = append(violations, r.checkFuncName(ctx, node, packageName)...)

		case *ast.ValueSpec:
			violations = append(violations, r.checkValueNames(ctx, node)...)
		}

		return true
	})

	return violations
}

// checkTypeName checks type naming conventions
func (r *NamingConventionsRule) checkTypeName(ctx *core.FileContext, spec *ast.TypeSpec, pkgName string) []*core.Violation {
	var violations []*core.Violation
	name := spec.Name.Name

	// Check for stuttering (package name repeated in type name)
	// Only check exported types - unexported are internal and stuttering is acceptable
	if ast.IsExported(name) && r.stutters(name, pkgName) {
		pos := ctx.PositionFor(spec.Name)
		v := r.CreateViolation(ctx.RelPath, pos.Line,
			"Type name stutters with package name: "+pkgName+"."+name)
		v.WithCode(ctx.GetLine(pos.Line))
		v.WithSuggestion("Remove package name prefix from type name")
		v.WithContext("type", name)
		violations = append(violations, v)
	}

	// Check for ALL_CAPS (should be PascalCase)
	// Skip known acronyms which are correctly ALL_CAPS
	if r.isAllCaps(name) && len(name) > 2 && !r.knownAcronyms[name] {
		pos := ctx.PositionFor(spec.Name)
		v := r.CreateViolation(ctx.RelPath, pos.Line,
			"Type name uses ALL_CAPS instead of PascalCase: "+name)
		v.WithCode(ctx.GetLine(pos.Line))
		v.WithSuggestion("Use PascalCase for type names")
		v.WithContext("type", name)
		violations = append(violations, v)
	}

	// Check for underscore in exported name
	if ast.IsExported(name) && strings.Contains(name, "_") {
		pos := ctx.PositionFor(spec.Name)
		v := r.CreateViolation(ctx.RelPath, pos.Line,
			"Exported type name contains underscore: "+name)
		v.WithCode(ctx.GetLine(pos.Line))
		v.WithSuggestion("Use PascalCase without underscores for exported types")
		v.WithContext("type", name)
		violations = append(violations, v)
	}

	return violations
}

// checkFuncName checks function naming conventions
func (r *NamingConventionsRule) checkFuncName(ctx *core.FileContext, fn *ast.FuncDecl, pkgName string) []*core.Violation {
	var violations []*core.Violation
	name := fn.Name.Name

	// Skip main and init
	if name == "main" || name == "init" {
		return nil
	}

	// Check for stuttering
	if r.stutters(name, pkgName) && fn.Recv == nil {
		pos := ctx.PositionFor(fn.Name)
		v := r.CreateViolation(ctx.RelPath, pos.Line,
			"Function name stutters with package name: "+pkgName+"."+name)
		v.WithCode(ctx.GetLine(pos.Line))
		v.WithSuggestion("Remove package name prefix from function name")
		v.WithContext("function", name)
		violations = append(violations, v)
	}

	// Check for underscore in exported function
	if ast.IsExported(name) && strings.Contains(name, "_") && fn.Recv == nil {
		pos := ctx.PositionFor(fn.Name)
		v := r.CreateViolation(ctx.RelPath, pos.Line,
			"Exported function name contains underscore: "+name)
		v.WithCode(ctx.GetLine(pos.Line))
		v.WithSuggestion("Use PascalCase without underscores for exported functions")
		v.WithContext("function", name)
		violations = append(violations, v)
	}

	return violations
}

// checkValueNames checks const/var naming conventions
func (r *NamingConventionsRule) checkValueNames(ctx *core.FileContext, spec *ast.ValueSpec) []*core.Violation {
	var violations []*core.Violation

	for _, ident := range spec.Names {
		name := ident.Name

		// Skip blank identifier
		if name == "_" {
			continue
		}

		// ALL_CAPS is acceptable for constants but not for variables
		// Check for underscore in exported names
		if ast.IsExported(name) && strings.Contains(name, "_") && !r.isAllCaps(name) {
			pos := ctx.PositionFor(ident)
			v := r.CreateViolation(ctx.RelPath, pos.Line,
				"Exported name contains underscore: "+name)
			v.WithCode(ctx.GetLine(pos.Line))
			v.WithSuggestion("Use PascalCase for exported names, or ALL_CAPS for constants")
			v.WithContext("name", name)
			violations = append(violations, v)
		}
	}

	return violations
}

// stutters checks if name starts with package name (stuttering)
func (r *NamingConventionsRule) stutters(name, pkgName string) bool {
	// Convert to lowercase for comparison
	nameLower := strings.ToLower(name)
	pkgLower := strings.ToLower(pkgName)

	// Check if name starts with package name
	if !strings.HasPrefix(nameLower, pkgLower) {
		return false
	}

	// Check that there's something after the package name
	if len(nameLower) <= len(pkgLower) {
		return false
	}

	// The character after package name should be uppercase (new word)
	nextChar := rune(name[len(pkgName)])
	return unicode.IsUpper(nextChar)
}

// isAllCaps checks if name is ALL_CAPS
func (r *NamingConventionsRule) isAllCaps(name string) bool {
	hasLetter := false
	for _, c := range name {
		if unicode.IsLetter(c) {
			hasLetter = true
			if unicode.IsLower(c) {
				return false
			}
		}
	}
	return hasLetter
}
