package security

import (
	"go/ast"
	"go/token"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewJWTParseValidationRule())
}

// JWTParseValidationRule detects a JWT parsed without the checks the library
// leaves to its caller:
//
//	jwt.ParseWithClaims(s, claims, func(t *jwt.Token) (any, error) { return []byte(secret), nil })
//	jwt.ParseWithClaims(s, claims, func(t *jwt.Token) (any, error) { return keys[kid], nil })
//
// A key function that returns the key without looking at the algorithm lets
// the token choose how it is verified: jwt.WithValidMethods, or a check of
// token.Method in the key function, pins it. A key taken from a key set of an
// identity provider (a file naming a kid or a JWKS) verifies every token the provider signs,
// for any application: without jwt.WithIssuer and jwt.WithAudience, or a
// comparison of the claims in the file, a token issued for another audience
// passes. The library checks exp only when the token carries one: a key-set
// token without exp verifies forever unless jwt.WithExpirationRequired is
// passed or the file looks at the claims' expiry. A key function the file
// does not declare is not judged.
type JWTParseValidationRule struct {
	*rules.BaseRule
}

// NewJWTParseValidationRule creates the rule
func NewJWTParseValidationRule() *JWTParseValidationRule {
	return &JWTParseValidationRule{
		BaseRule: rules.NewBaseRule(
			"jwt-parse-validation",
			"security",
			"Detects JWT parsing without a pinned signing algorithm, or with a key-set key and no issuer or audience check",
			core.SeverityHigh,
		),
	}
}

// jwtImportPaths are the JWT libraries whose Parse leaves these checks to the caller.
var jwtImportPaths = map[string]bool{
	"github.com/golang-jwt/jwt": true, "github.com/golang-jwt/jwt/v4": true, "github.com/golang-jwt/jwt/v5": true,
	"github.com/dgrijalva/jwt-go": true, "github.com/form3tech-oss/jwt-go": true,
}

// keySetWord names a key picked from a set: a key id, a JWKS.
var keySetWord = regexp.MustCompile(`(?i)^kid$|jwks|keyset`)

// jwtParse is a call that verifies a token and what it is given.
type jwtParse struct {
	call    *ast.CallExpr
	keyfunc ast.Expr
	options []ast.Expr
}

// AnalyzeFile reports the JWT parses of a Go file that leave a check out.
func (r *JWTParseValidationRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.HasGoAST() || ctx.IsTestFile() {
		return nil
	}
	pkg := jwtPackageName(ctx.GoAST)
	if pkg == "" {
		return nil
	}
	funcs := make(map[string]*ast.FuncDecl)
	for _, decl := range ctx.GoAST.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil {
			funcs[fn.Name.Name] = fn
		}
	}
	claimsCompared := comparesIssuerOrAudience(ctx.GoAST)
	expiryChecked := checksExpiry(ctx.GoAST)
	keySet := usesKeySet(ctx.GoAST)
	lr := newLineReporter(ctx, r.BaseRule)
	report := lr.report
	for _, fn := range funcs {
		for _, parse := range jwtParses(fn.Body, pkg) {
			if !hasOption(parse.options, "WithValidMethods", "ValidMethods") && !keyfuncChecksMethod(parse.keyfunc, funcs) {
				report(parse.call, "The key function returns the key without checking the algorithm — the token chooses how it is verified",
					"Pass jwt.WithValidMethods([]string{...}) or check token.Method in the key function",
					"algorithm_unchecked")
			}
			if !claimsCompared && !hasOption(parse.options, "WithIssuer", "WithAudience") && keySet &&
				!keyfuncReturnsSecret(parse.keyfunc, funcs) {
				report(parse.call, "A key from an identity provider's key set verifies every token it signs — without the issuer and the audience a token issued for another application passes",
					"Pass jwt.WithIssuer and jwt.WithAudience, or compare the claims' issuer and audience after parsing",
					"issuer_audience_unchecked")
			}
			if !expiryChecked && !hasOption(parse.options, "WithExpirationRequired") && keySet &&
				!keyfuncReturnsSecret(parse.keyfunc, funcs) {
				report(parse.call, "The library checks exp only when the token has one — an identity provider's token without exp verifies forever",
					"Pass jwt.WithExpirationRequired() or reject claims whose ExpiresAt is nil after parsing",
					"expiry_not_required")
			}
		}
	}
	return lr.violations
}

// jwtPackageName returns the name a file imports a JWT library under.
func jwtPackageName(file *ast.File) string {
	for _, spec := range file.Imports {
		importPath := strings.Trim(spec.Path.Value, "`\"")
		if !jwtImportPaths[importPath] {
			continue
		}
		if spec.Name != nil {
			return spec.Name.Name
		}
		if base := path.Base(importPath); base != "v4" && base != "v5" && base != "jwt-go" {
			return base
		}
		return "jwt"
	}
	return ""
}

// jwtParses returns the Parse and ParseWithClaims calls of a body, of the
// package or of a parser the body builds, with the options they carry. A
// parser the body did not build carries options the rule cannot see.
func jwtParses(body *ast.BlockStmt, pkg string) []jwtParse {
	parsers := make(map[string][]ast.Expr)
	parserOptions := func(expr ast.Expr) ([]ast.Expr, bool) {
		switch e := ast.Unparen(expr).(type) {
		case *ast.CallExpr:
			switch helpers.ExprText(e.Fun) {
			case pkg + ".NewParser":
				return e.Args, true
			case "new":
				return nil, len(e.Args) == 1 && helpers.ExprText(e.Args[0]) == pkg+".Parser"
			}
		case *ast.UnaryExpr:
			if lit, ok := e.X.(*ast.CompositeLit); ok && e.Op == token.AND && helpers.ExprText(lit.Type) == pkg+".Parser" {
				return lit.Elts, true
			}
		case *ast.Ident:
			options, ok := parsers[e.Name]
			return options, ok
		}
		return nil, false
	}
	assignedValues(body, func(name *ast.Ident, value ast.Expr) {
		if options, ok := parserOptions(value); ok {
			parsers[name.Name] = options
		}
	})
	var parses []jwtParse
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		index := map[string]int{"Parse": 1, "ParseWithClaims": 2}[sel.Sel.Name]
		if index == 0 || len(call.Args) <= index {
			return true
		}
		options := call.Args[index+1:]
		if ident, ok := sel.X.(*ast.Ident); !ok || ident.Name != pkg {
			parserOpts, ok := parserOptions(sel.X)
			if !ok {
				return true
			}
			options = append(slices.Clone(parserOpts), options...)
		}
		parses = append(parses, jwtParse{call: call, keyfunc: call.Args[index], options: options})
		return true
	})
	return parses
}

// hasOption reports an option call (jwt.WithValidMethods(...)) or a parser
// field (ValidMethods: ...) among the options.
func hasOption(options []ast.Expr, names ...string) bool {
	for _, option := range options {
		var name string
		switch o := ast.Unparen(option).(type) {
		case *ast.CallExpr:
			name = callName(o)
		case *ast.KeyValueExpr:
			if key, ok := o.Key.(*ast.Ident); ok {
				name = key.Name
			}
		}
		for _, want := range names {
			if name == want {
				return true
			}
		}
	}
	return false
}

// keyfuncBodies returns the bodies a key function runs: its literal, or the
// function or method of the file it names, and the functions of the file
// those call. It returns false for a key function declared elsewhere.
func keyfuncBodies(keyfunc ast.Expr, funcs map[string]*ast.FuncDecl) ([]ast.Node, bool) {
	var root ast.Node
	switch k := ast.Unparen(keyfunc).(type) {
	case *ast.FuncLit:
		root = k.Body
	case *ast.Ident:
		fn, ok := funcs[k.Name]
		if !ok || fn.Recv != nil || fn.Body == nil {
			return nil, false
		}
		root = fn.Body
	case *ast.SelectorExpr:
		fn, ok := funcs[k.Sel.Name]
		if !ok || fn.Recv == nil || fn.Body == nil {
			return nil, false
		}
		root = fn.Body
	default:
		return nil, false
	}
	bodies := []ast.Node{root}
	ast.Inspect(root, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if fn, ok := funcs[callName(call)]; ok {
				bodies = append(bodies, fn.Body)
			}
		}
		return true
	})
	return bodies, true
}

// keyfuncChecksMethod reports a key function that looks at the algorithm:
// token.Method, token.Header["alg"]. One declared elsewhere is taken as
// checking.
func keyfuncChecksMethod(keyfunc ast.Expr, funcs map[string]*ast.FuncDecl) bool {
	bodies, ok := keyfuncBodies(keyfunc, funcs)
	if !ok {
		return true
	}
	for _, body := range bodies {
		found := false
		ast.Inspect(body, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.SelectorExpr:
				found = found || node.Sel.Name == "Method"
			case *ast.BasicLit:
				found = found || node.Value == `"alg"`
			}
			return !found
		})
		if found {
			return true
		}
	}
	return false
}

// keyfuncReturnsSecret reports a key function that verifies with a secret of
// the application: it pins an HMAC method, or every key it returns is a
// []byte conversion.
func keyfuncReturnsSecret(keyfunc ast.Expr, funcs map[string]*ast.FuncDecl) bool {
	bodies, ok := keyfuncBodies(keyfunc, funcs)
	if !ok {
		return false
	}
	hmac, returnsBytes, returnsOther := false, false, false
	ast.Inspect(bodies[0], func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.ReturnStmt:
			if len(node.Results) == 0 || isNilIdent(node.Results[0]) {
				return true
			}
			if conv, ok := node.Results[0].(*ast.CallExpr); ok && isByteSlice(conv.Fun) {
				returnsBytes = true
			} else {
				returnsOther = true
			}
		}
		return true
	})
	for _, body := range bodies {
		ast.Inspect(body, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok && strings.HasPrefix(sel.Sel.Name, "SigningMethodH") {
				hmac = true
			}
			return !hmac
		})
	}
	return hmac || returnsBytes && !returnsOther
}

// isByteSlice reports the type []byte.
func isByteSlice(expr ast.Expr) bool {
	arr, ok := expr.(*ast.ArrayType)
	if !ok || arr.Len != nil {
		return false
	}
	elt, ok := arr.Elt.(*ast.Ident)
	return ok && elt.Name == "byte"
}

func isNilIdent(expr ast.Expr) bool {
	ident, ok := ast.Unparen(expr).(*ast.Ident)
	return ok && ident.Name == "nil"
}

// usesKeySet reports a file that picks keys from a key set: it names a kid
// or a JWKS, wherever the key is then handed to the parse.
func usesKeySet(file *ast.File) bool {
	found := false
	ast.Inspect(file, func(n ast.Node) bool {
		switch e := n.(type) {
		case *ast.Ident:
			found = found || keySetWord.MatchString(e.Name)
		case *ast.BasicLit:
			found = found || e.Kind == token.STRING && e.Value == `"kid"`
		}
		return !found
	})
	return found
}

// checksExpiry reports a file that looks at the expiry of claims: ExpiresAt,
// a claims map's "exp", VerifyExpiresAt.
func checksExpiry(file *ast.File) bool {
	found := false
	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.SelectorExpr:
			found = found || node.Sel.Name == "ExpiresAt" || node.Sel.Name == "VerifyExpiresAt"
		case *ast.BasicLit:
			found = found || node.Kind == token.STRING && node.Value == `"exp"`
		}
		return !found
	})
	return found
}

// comparesIssuerOrAudience reports a file that checks the issuer or the
// audience of claims: a comparison of Issuer or Audience, a range over the
// audience, VerifyIssuer or VerifyAudience.
func comparesIssuerOrAudience(file *ast.File) bool {
	isClaim := func(expr ast.Expr) bool {
		sel, ok := ast.Unparen(expr).(*ast.SelectorExpr)
		if !ok {
			return false
		}
		switch sel.Sel.Name {
		case "Issuer", "Audience", "Iss", "Aud":
			return true
		}
		return false
	}
	found := false
	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.BinaryExpr:
			found = found || (node.Op == token.EQL || node.Op == token.NEQ) && (isClaim(node.X) || isClaim(node.Y))
		case *ast.RangeStmt:
			found = found || isClaim(node.X)
		case *ast.CallExpr:
			switch callName(node) {
			case "VerifyIssuer", "VerifyAudience":
				found = true
			case "Contains":
				for _, arg := range node.Args {
					found = found || isClaim(arg)
				}
			}
		}
		return !found
	})
	return found
}
