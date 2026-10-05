package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// A prefix cut from a value of unknown length panics on a short one: a short
// e-mail turns the handler into a 500, a short secret fails the test helper.
func TestStringPrefixSliceUnguarded(t *testing.T) {
	found := projectRuleLines(t, NewStringPrefixSliceUnguardedRule(), map[string]string{
		"admin/label.go": `package admin

import (
	"fmt"

	"example.com/rulestest/uuid"
)

type Claims struct{ Email string }

type User struct {
	ID    string
	Email string
}

const prefix = "admin-"

func AdminID(claims Claims) string {
	return fmt.Sprintf("admin-%s", claims.Email[:8])
}

func Labels(users []User) []string {
	var out []string
	for i := range users {
		out = append(out, fmt.Sprintf("%s (ID: %s...)", users[i].Email, users[i].ID[:8]))
	}
	return out
}

func Guarded(claims Claims) string {
	email := claims.Email
	if len(email) > 8 {
		email = email[:8]
	}
	return email
}

func Fixed() string {
	short := uuid.NewString()[:8]
	id := uuid.New().String()
	return short + id[:8] + prefix[:3]
}

func Bytes(buf []byte) []byte {
	return buf[:4]
}

func Whole(claims Claims) string {
	return claims.Email[:]
}

type release struct{ head, name string }

func Capitalize(words []string, r release) string {
	for i, word := range words {
		words[i] = word[:2]
	}
	return r.head[:12] + r.name[:1]
}
`,
		"uuid/uuid.go": `package uuid

type UUID [16]byte

func (u UUID) String() string { return "00000000-0000-0000-0000-000000000000" }

func New() UUID { return UUID{} }

func NewString() string { return New().String() }
`,
		"admin/label_test.go": `package admin

import (
	"os"
	"testing"
)

type authConfig struct{ JWTSecret string }

type config struct{ Auth authConfig }

func restore(t *testing.T, cfg *config) {
	envSecret := os.Getenv("JWT_SECRET")
	t.Logf("restoring secret: '%s...' -> '%s...'", cfg.Auth.JWTSecret[:30], envSecret[:30])
	if len(envSecret) > 4 {
		t.Logf("prefix %s", envSecret[:4])
	}
	_ = cfg.Auth.JWTSecret[:2]
	data := []byte(envSecret)
	t.Logf("discriminator=%v", data[:8])
}
`,
	})
	assert.Equal(t, []string{"admin/label.go:19", "admin/label.go:25", "admin/label_test.go:14", "admin/label_test.go:14"}, found)
}

// encoding/json keeps the outer field of a name and drops the promoted one:
// a details type that adds a placeholder under the base type's JSON name
// sends the placeholder and loses the real value.
func TestJSONTagShadowsEmbeddedField(t *testing.T) {
	found := projectRuleLines(t, NewJSONTagShadowsEmbeddedFieldRule(), map[string]string{
		"models/investment.go": `package models

type Investment struct {
	ID           string ` + "`json:\"id\"`" + `
	StrategyName string ` + "`json:\"strategy\"`" + `
	Amount       string
}

type Audit struct {
	CreatedBy string ` + "`json:\"createdBy\"`" + `
}

type InvestmentDetails struct {
	Investment
	*Audit
	UserEmail string      ` + "`json:\"userEmail,omitempty\"`" + `
	Strategy  interface{} ` + "`json:\"strategy,omitempty\"`" + `
	Total     string      ` + "`json:\"Amount\"`" + `
	Author    string      ` + "`json:\"createdBy\"`" + `
	Ignored   string      ` + "`json:\"-\"`" + `
}

type Override struct {
	Investment
	ID string ` + "`json:\"id\"`" + `
}

type Named struct {
	Investment ` + "`json:\"investment\"`" + `
	Strategy string ` + "`json:\"strategy\"`" + `
}
`,
	})
	assert.Equal(t, []string{"models/investment.go:17", "models/investment.go:18", "models/investment.go:19"}, found)
}

// A state compared with a string that none of its constants holds: the value
// comes from another status set, and the compiler cannot see the drift.
func TestEnumComparedToForeignLiteral(t *testing.T) {
	found := projectRuleLines(t, NewEnumComparedToForeignLiteralRule(), map[string]string{
		"domain/state.go": `package domain

type State string

const (
	StateCreated  State = "created"
	StatePending  State = "pending_approval"
	StateRejected State = "rejected"
)

type Free string
`,
		"service/cancel.go": `package service

import (
	"errors"

	"example.com/rulestest/domain"
)

func Cancel(raw string, free domain.Free) error {
	state := domain.State(raw)
	if state != domain.StatePending && state != domain.StateCreated && string(state) != "pending" {
		return errors.New("cannot cancel")
	}
	if state == "canceled" {
		return errors.New("already")
	}
	if string(state) == "created" || free == "anything" || raw == "pending" {
		return nil
	}
	switch state {
	case domain.StateRejected, "refunded":
		return nil
	}
	if state == "" || state == "*" {
		return nil
	}
	return nil
}
`,
	})
	assert.Equal(t, []string{"service/cancel.go:11", "service/cancel.go:14", "service/cancel.go:21"}, found)
}

// A host matched by suffix without the dot: evilexample.com passes a check
// for example.com.
func TestHostSuffixWithoutDot(t *testing.T) {
	found := projectRuleLines(t, NewHostSuffixWithoutDotRule(), map[string]string{
		"middleware/https.go": `package middleware

import "strings"

func Allowed(host, baseDomain string) bool {
	if baseDomain != "" && !strings.HasSuffix(strings.Split(host, ":")[0], baseDomain) {
		return false
	}
	return strings.HasSuffix(host, "example.com")
}

func Strict(host, baseDomain string) bool {
	return host == baseDomain || strings.HasSuffix(host, "."+baseDomain) || strings.HasSuffix(host, ".example.com")
}

func Other(name, ext string) bool {
	return strings.HasSuffix(name, ext) || strings.HasSuffix(name, ".go")
}

var testEmailDomains = []string{"@local.test", "@" + localDomain}

const localDomain = "app.test"

func IsTestEmail(email string) bool {
	for _, domain := range testEmailDomains {
		if strings.HasSuffix(email, domain) {
			return true
		}
	}
	return false
}

func IsTestDomain(domainPart string) bool {
	for _, testDomain := range []string{"local.test", "example.com"} {
		if strings.HasSuffix(domainPart, testDomain) {
			return true
		}
	}
	return strings.HasSuffix(domainPart, "@"+localDomain)
}
`,
	})
	assert.Equal(t, []string{"middleware/https.go:35", "middleware/https.go:6", "middleware/https.go:9"}, found)
}

// JSON written with a format verb inside quotes: a quote or a newline in the
// value breaks the frame or adds fields.
func TestJSONBuiltByFormat(t *testing.T) {
	found := projectRuleLines(t, NewJSONBuiltByFormatRule(), map[string]string{
		"sse/handler.go": `package sse

import (
	"fmt"
	"net/http"
)

func Connected(w http.ResponseWriter, userID string, count int) {
	fmt.Fprintf(w, "data: {\"status\":\"connected\",\"userId\":\"%s\"}\n\n", userID)
	body := fmt.Sprintf(` + "`{\"error\": \"%v\"}`" + `, userID)
	_ = body
	fmt.Fprintf(w, "data: {\"count\":%d}\n\n", count)
	fmt.Fprintf(w, "user %q connected", userID)
}
`,
		"sse/handler_test.go": `package sse

import "fmt"

func body(email string) string {
	return fmt.Sprintf(` + "`{\"email\":\"%s\"}`" + `, email)
}
`,
	})
	assert.Equal(t, []string{"sse/handler.go:10", "sse/handler.go:9"}, found)
}

// Quotes doubled by hand in place of bind parameters: other metacharacters
// pass, and the SQL built around the value escapes the injection checks.
func TestSQLQuoteEscapedByHand(t *testing.T) {
	found := projectRuleLines(t, NewSQLQuoteEscapedByHandRule(), map[string]string{
		"helpers/where.go": `package helpers

import "strings"

func escapeSQLLiteral(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}

var quoter = strings.NewReplacer("'", "''", "\\", "\\\\")

func legacy(s string) string {
	return strings.Replace(s, "'", "''", -1)
}

func other(s string) string {
	return strings.ReplaceAll(s, "\"", "'")
}
`,
		"helpers/db.go": `package helpers

import "database/sql"

var DB *sql.DB
`,
	})
	assert.Equal(t, []string{"helpers/where.go:12", "helpers/where.go:6", "helpers/where.go:9"}, found)

	// A tool that hands SQL text to the psql command has no bind parameters.
	cli := projectRuleLines(t, NewSQLQuoteEscapedByHandRule(), map[string]string{
		"flags/sql.go": `package flags

import "strings"

func literal(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
`,
	})
	assert.Empty(t, cli)
}

// A metric answered by a literal zero: the API reports no return instead of
// failing or leaving the field out.
func TestSQLMetricLiteralZero(t *testing.T) {
	found := projectRuleLines(t, NewSQLMetricLiteralZeroRule(), map[string]string{
		"repo/portfolio.go": `package repo

const summaryQuery = ` + "`" + `
	SELECT
		COUNT(*) as total_investments,
		COALESCE(SUM(amount), 0) as total_value,
		0 as total_return,
		0::numeric AS realized_profit
	FROM investments WHERE user_id = $1` + "`" + `

const unionQuery = ` + "`" + `
	SELECT amount, 0 AS fee FROM deposits
	UNION ALL
	SELECT amount, fee FROM withdrawals` + "`" + `

const flagQuery = ` + "`SELECT id, 0 AS retry_count FROM jobs`" + `

func Query() string { return summaryQuery + unionQuery + flagQuery }
`,
	})
	assert.Equal(t, []string{"repo/portfolio.go:7", "repo/portfolio.go:8"}, found)
}

// A template passes a permission name to a FuncMap helper that converts it
// to the permission type: a name no constant holds (a permission of an
// older set) hides the button for everyone, and nothing compiles it.
func TestEnumComparedToForeignLiteralInTemplate(t *testing.T) {
	found := projectRuleLines(t, NewEnumComparedToForeignLiteralRule(), map[string]string{
		"domain/perm.go": `package domain

type Permission string

const (
	PermOperations Permission = "operations"
	PermExport     Permission = "export"
)

type Role string

func HasPermission(role Role, perm Permission) bool { return role == "admin" || perm == PermExport }
`,
		"admin/funcs.go": `package admin

import (
	"html/template"

	"example.com/rulestest/domain"
)

var funcs = template.FuncMap{
	"hasPerm": func(role, perm string) bool {
		return domain.HasPermission(domain.Role(role), domain.Permission(perm))
	},
	"upper": func(s string) string { return s },
}
`,
		"admin/templates/layout.html": `<nav>
{{if hasPerm .Role "execute_transaction"}}<a href="/run">Run</a>{{end}}
{{if hasPerm .Role "operations"}}<a href="/ops">Ops</a>{{end}}
{{upper "anything"}}
</nav>
`,
	})
	assert.Equal(t, []string{"admin/funcs.go:10"}, found)
}
