package security

import (
	"go/ast"
	"go/token"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewSecretExposureRule())
}

// SecretExposureRule detects a credential value written where it leaves the
// process:
//
//	logger.Info("migration config", "db_url", flags.dbURL)        // DSN with its password
//	return fmt.Errorf("known development password '%s'", c.Password)
//	if got != h.apiKey { return fmt.Errorf("expected %s", h.apiKey) }
//	ClientSecret string `env:"OAUTH_CLIENT_SECRET" json:"clientSecret"`
//
// A secret or a connection string handed to a log line or an error message
// is kept wherever logs and errors go. A failed comparison that prints the
// expected credential hands it to whoever sent the wrong one. A secret field
// of a configuration read from the environment, without json:"-", goes out
// whenever the configuration is encoded (a config endpoint, a debug dump).
//
// A value is judged by its name: Password, JWTSecret, PrivateKey, APIKey,
// AccessToken, a DSN or a database URL. Its length or a hash of it is not the
// value; building a connection string is not writing it out.
type SecretExposureRule struct {
	*rules.BaseRule
}

// NewSecretExposureRule creates the rule
func NewSecretExposureRule() *SecretExposureRule {
	return &SecretExposureRule{
		BaseRule: rules.NewBaseRule(
			"secret-exposure",
			"security",
			"Detects credentials and connection strings written to logs, error messages or serializable configuration",
			core.SeverityHigh,
		),
	}
}

// connectionStringName matches a value that carries the database password in
// it: dsn, dbURL, DatabaseURL, connStr, ConnectionString.
var connectionStringName = regexp.MustCompile(`(?i)(?:dsn|db[-_]?url|database[-_]?url|conn[-_]?str|connection[-_]?string)$`)

// credentialWord matches a compared value that is a credential: a key, a
// secret, a token, a signature, a password.
var credentialWord = regexp.MustCompile(`(?i)(?:key|secret|token|signature|password|hmac)$`)

// AnalyzeFile reports the credentials a Go file writes out.
func (r *SecretExposureRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.HasGoAST() || ctx.IsTestFile() {
		return nil
	}
	var violations []*core.Violation
	report := func(node ast.Node, message string) {
		line := ctx.LineFor(node)
		if ctx.IsSuppressed(line, r.Name()) {
			return
		}
		v := r.CreateViolation(ctx.RelPath, line, message)
		v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
		v.WithSuggestion("Write that the credential is set or which one failed, never its value; tag secret fields json:\"-\"")
		violations = append(violations, v)
	}
	reported := make(map[*ast.CallExpr]bool)
	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.IfStmt:
			if call := expectedCredentialCall(node); call != nil {
				reported[call] = true
				report(call, "The error of a failed credential check prints the stored credential")
			}
		case *ast.CallExpr:
			if reported[node] || !isWriteOut(node) {
				return true
			}
			if name := exposedSecret(node); name != "" {
				report(node, "Credential "+name+" is written to a log line or an error message")
			}
		case *ast.Field:
			if serializableSecret(node) {
				report(node, "Secret configuration field without json:\"-\" goes out whenever the configuration is encoded")
			}
		}
		return true
	})
	return violations
}

// isWriteOut reports a call whose arguments leave the process as text: a
// logger call or fmt.Errorf.
func isWriteOut(call *ast.CallExpr) bool {
	if helpers.IsLoggerCall(call) {
		return true
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "fmt" && sel.Sel.Name == "Errorf"
}

// exposedSecret returns the name of a credential among the call's arguments,
// looking into the fmt.Sprint* calls and concatenations that build them.
func exposedSecret(call *ast.CallExpr) string {
	for _, arg := range call.Args {
		if name := secretIn(arg); name != "" {
			return name
		}
	}
	return ""
}

func secretIn(expr ast.Expr) string {
	switch e := ast.Unparen(expr).(type) {
	case *ast.Ident, *ast.SelectorExpr:
		// ErrNoAPIKey is the error that says the key is missing.
		name := lastName(e)
		if !helpers.HasLeadingWord(name, "Err") && (secretFieldName.MatchString(name) || connectionStringName.MatchString(name)) {
			return name
		}
	case *ast.BinaryExpr:
		if e.Op == token.ADD {
			if name := secretIn(e.X); name != "" {
				return name
			}
			return secretIn(e.Y)
		}
	case *ast.CallExpr:
		if sel, ok := e.Fun.(*ast.SelectorExpr); ok {
			if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "fmt" && strings.HasPrefix(sel.Sel.Name, "Sprint") {
				return exposedSecret(e)
			}
		}
	}
	return ""
}

// lastName returns the identifier an expression ends with: c.Password is Password.
func lastName(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		return e.Sel.Name
	}
	return ""
}

// expectedCredentialCall returns the write-out call in the body of a failed
// credential comparison (a != b, both named like a credential) that prints
// one of the compared values.
func expectedCredentialCall(ifStmt *ast.IfStmt) *ast.CallExpr {
	bin, ok := ast.Unparen(ifStmt.Cond).(*ast.BinaryExpr)
	if !ok || bin.Op != token.NEQ {
		return nil
	}
	left, right := helpers.ExprText(bin.X), helpers.ExprText(bin.Y)
	if left == "" || right == "" || !credentialWord.MatchString(left) || !credentialWord.MatchString(right) {
		return nil
	}
	var found *ast.CallExpr
	ast.Inspect(ifStmt.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || found != nil || !isWriteOut(call) {
			return found == nil
		}
		for _, arg := range call.Args {
			if text := helpers.ExprText(arg); text == left || text == right {
				found = call
			}
		}
		return found == nil
	})
	return found
}

// serializableSecret reports a secret field of a configuration read from the
// environment (an env tag) that names itself for JSON (a json tag other than
// "-"): a struct without json tags is not written to be encoded.
func serializableSecret(field *ast.Field) bool {
	if field.Tag == nil || len(field.Names) != 1 || !secretFieldName.MatchString(field.Names[0].Name) {
		return false
	}
	tag := fieldTag(field)
	if _, fromEnv := tag.Lookup("env"); !fromEnv {
		return false
	}
	jsonTag, named := tag.Lookup("json")
	name, _, _ := strings.Cut(jsonTag, ",")
	return named && name != "-"
}

// fieldTag returns the parsed tag of a struct field; a tag the compiler
// would reject reads as empty.
func fieldTag(field *ast.Field) reflect.StructTag {
	raw, err := strconv.Unquote(field.Tag.Value)
	if err == nil {
		return reflect.StructTag(raw)
	}
	return ""
}
