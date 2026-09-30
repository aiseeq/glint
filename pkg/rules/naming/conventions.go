package naming

import (
	"go/ast"
	"strings"
	"unicode"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewConventionsRule())
}

// ConventionsRule detects Go naming convention violations in the names a
// package declares at top level - its API as other packages read it:
// stuttering (pkg.PkgThing; not in package main, which nobody imports),
// underscores in exported names, and ALL_CAPS type names that are not made of
// initialisms (JSONRPC is JSON + RPC). Names local to a function are never
// exported and are not checked: the underscore convention of Effective Go
// covers them too, but this rule keeps to the package API, as it does for
// unexported package-level names.
type ConventionsRule struct {
	*rules.BaseRule
	// Known acronyms that are correctly written in ALL_CAPS
	knownAcronyms map[string]bool
}

// NewConventionsRule creates the rule
func NewConventionsRule() *ConventionsRule {
	return &ConventionsRule{
		BaseRule: rules.NewBaseRule(
			"naming-convention",
			"naming",
			"Detects Go naming convention violations in top-level declarations: stuttering with the package name (except package main), underscores in exported names, ALL_CAPS type names not made of initialisms",
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
			"JWT": true, "JWK": true, "JWKS": true, "JWE": true, "RFI": true,
			"RSA": true, "AES": true, "SHA": true, "MD5": true,
			"HMAC": true, "ECDSA": true, "PKCS": true,
			"MFA": true, "OTP": true, "TOTP": true, "HOTP": true,
			"CSRF": true, "XSS": true, "CORS": true,
			// Database
			"DB": true, "JSONB": true, "BSON": true, "BLOB": true, "CLOB": true,
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
func (r *ConventionsRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || ctx.GoAST == nil || ctx.IsTestFile() {
		return nil
	}

	var violations []*core.Violation
	packageName := ctx.GoAST.Name.Name

	// Only top-level declarations: a name declared inside a function is local
	// and never part of the package API.
	for _, decl := range ctx.GoAST.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			violations = append(violations, r.checkFuncName(ctx, d, packageName)...)
		case *ast.GenDecl:
			for _, spec := range d.Specs {
				switch s := spec.(type) {
				case *ast.TypeSpec:
					violations = append(violations, r.checkTypeName(ctx, s, packageName)...)
				case *ast.ValueSpec:
					violations = append(violations, r.checkValueNames(ctx, s)...)
				}
			}
		}
	}

	return violations
}

// checkTypeName checks type naming conventions
func (r *ConventionsRule) checkTypeName(ctx *core.FileContext, spec *ast.TypeSpec, pkgName string) []*core.Violation {
	var violations []*core.Violation
	name := spec.Name.Name

	// Check for stuttering (package name repeated in type name)
	// Only check exported types - unexported are internal and stuttering is acceptable
	if ast.IsExported(name) && r.stutters(name, pkgName) && !r.isSemanticSuffix(name) {
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
	if r.isAllCaps(name) && len(name) > 2 && !r.isInitialismCompound(name) {
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

func (r *ConventionsRule) isSemanticSuffix(name string) bool {
	return strings.HasSuffix(name, "Error") || strings.HasSuffix(name, "Context")
}

// checkFuncName checks function naming conventions
func (r *ConventionsRule) checkFuncName(ctx *core.FileContext, fn *ast.FuncDecl, pkgName string) []*core.Violation {
	var violations []*core.Violation
	name := fn.Name.Name

	// Skip main and init
	if name == "main" || name == "init" {
		return nil
	}

	// Check for stuttering
	// Only check exported functions - unexported names are never qualified
	// as pkg.name by callers, so they cannot stutter
	if ast.IsExported(name) && r.stutters(name, pkgName) && fn.Recv == nil {
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
func (r *ConventionsRule) checkValueNames(ctx *core.FileContext, spec *ast.ValueSpec) []*core.Violation {
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

// stutters checks if name starts with package name (stuttering). Package
// main is never imported, so its names are never read as main.Name.
func (r *ConventionsRule) stutters(name, pkgName string) bool {
	if pkgName == "main" {
		return false
	}

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

// isInitialismCompound reports whether the name is a sequence of known
// initialisms - JSON, JSONRPC, HTTPAPI - which Go writes in capitals.
func (r *ConventionsRule) isInitialismCompound(name string) bool {
	// composed[i] reports whether name[:i] splits into known initialisms.
	composed := make([]bool, len(name)+1)
	composed[0] = true
	for end := 1; end <= len(name); end++ {
		for start := 0; start < end && !composed[end]; start++ {
			composed[end] = composed[start] && r.knownAcronyms[name[start:end]]
		}
	}
	return composed[len(name)]
}

// isAllCaps checks if name is ALL_CAPS
func (r *ConventionsRule) isAllCaps(name string) bool {
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
