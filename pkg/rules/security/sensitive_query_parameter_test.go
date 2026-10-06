package security

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

func TestSensitiveQueryParameterRuleIsRegistered(t *testing.T) {
	_, ok := rules.Get("sensitive-query-param")
	assert.True(t, ok, "sensitive-query-param must run through the CLI registry")
}

func TestSensitiveQueryParameterRule(t *testing.T) {
	tests := []struct {
		name           string
		path           string
		code           string
		wantViolations int
	}{
		{
			name:           "Go reads token from query",
			path:           "/src/auth.go",
			code:           `package auth; func token(r *http.Request) string { return r.URL.Query().Get("token") }`,
			wantViolations: 1,
		},
		{
			name:           "TypeScript reads token from search params",
			path:           "/src/callback.ts",
			code:           `const token = searchParams.get('access_token')`,
			wantViolations: 1,
		},
		{
			name:           "sensitive URL literal",
			path:           "/src/email.go",
			code:           `package email; const actionURL = "/verify?token=" + token`,
			wantViolations: 1,
		},
		{
			name:           "fragment token is not sent to server",
			path:           "/src/email.go",
			code:           `package email; const actionURL = "/verify#token=" + token`,
			wantViolations: 0,
		},
		{
			name:           "ordinary query parameter",
			path:           "/src/list.ts",
			code:           `const page = searchParams.get('page')`,
			wantViolations: 0,
		},
		{
			name:           "JSON body token",
			path:           "/src/client.ts",
			code:           `await fetch('/verify', { method: 'POST', body: JSON.stringify({ token }) })`,
			wantViolations: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewSensitiveQueryParameterRule()
			ctx := core.NewFileContext(tt.path, "/src", []byte(tt.code), core.DefaultConfig())
			assert.Len(t, rule.AnalyzeFile(ctx), tt.wantViolations)
		})
	}
}

// A generated password handed to a redirect helper ends up in the query of
// the redirect URL whatever the parameter is called: browser history, proxy
// and access logs keep it.
func TestSensitiveQueryParameterSecretInRedirect(t *testing.T) {
	code := `package admin

func (a *Admin) create(w http.ResponseWriter, r *http.Request) {
	password, _ := generatePassword()
	a.redirectUsers(w, r, "success",
		fmt.Sprintf("created %s with password %s", name, password))
	http.Redirect(w, r, "/done?msg="+url.QueryEscape(newToken), http.StatusSeeOther)
	a.redirectUsers(w, r, "error", a.t(r, "msg.password_mismatch"))
	a.redirectUsers(w, r, "success", "password changed for "+user.Name)
	a.render(w, "created.html", password)
}

func (a *Admin) redirectUsers(w http.ResponseWriter, r *http.Request, key, msg string) {
	http.Redirect(w, r, "/users?"+key+"="+url.QueryEscape(msg), http.StatusSeeOther)
}
`
	ctx := rulestest.GoFile(t, "admin/users.go", code)
	var lines []int
	for _, v := range NewSensitiveQueryParameterRule().AnalyzeFile(ctx) {
		lines = append(lines, v.Line)
	}
	assert.Equal(t, []int{5, 7}, lines)
}

func TestSensitiveQueryParameterSuppression(t *testing.T) {
	rule := NewSensitiveQueryParameterRule()
	code := `package auth
func token(r *http.Request) string {
	//nolint:sensitive-query-param // protocol-mandated callback
	return r.URL.Query().Get("token")
}`
	ctx := core.NewFileContext("/src/auth.go", "/src", []byte(code), core.DefaultConfig())
	assert.Empty(t, rule.AnalyzeFile(ctx))
}

// A token put into url.Values that end up in the query of a redirect is in
// the access log of the page it lands on and in its Referer; the same values
// posted as a form body to a token endpoint, or encoded after '#', do not
// travel to a server.
func TestSensitiveQueryParameterValuesIntoRedirect(t *testing.T) {
	code := `package auth

func (a *Auth) callback(w http.ResponseWriter, r *http.Request, result Result, gift string) {
	frontendURL := frontendCallbackURL(a.domain, url.Values{"id_token": {result.IDToken}}, gift)
	http.Redirect(w, r, frontendURL, http.StatusTemporaryRedirect)
}

func (a *Auth) fragment(w http.ResponseWriter, r *http.Request, result Result) {
	target := "https://app/cb#" + url.Values{"id_token": {result.IDToken}}.Encode()
	http.Redirect(w, r, target, http.StatusTemporaryRedirect)
}

func (a *Auth) exchange(code string) (*http.Response, error) {
	return http.PostForm(a.tokenURL, url.Values{"client_secret": {a.secret}, "code": {code}})
}

func (a *Auth) plain(w http.ResponseWriter, r *http.Request, gift string) {
	http.Redirect(w, r, "/done?"+url.Values{"gift_code": {gift}}.Encode(), http.StatusSeeOther)
}
`
	ctx := rulestest.GoFile(t, "auth/callback.go", code)
	var lines []int
	for _, v := range NewSensitiveQueryParameterRule().AnalyzeFile(ctx) {
		lines = append(lines, v.Line)
	}
	assert.Equal(t, []int{4}, lines)
}

// The search params of the page read through a variable are the query all
// the same: the token came in the URL the server and its logs saw.
func TestSensitiveQueryParameterSearchParamsVariable(t *testing.T) {
	code := `export function Callback() {
  const params = new URLSearchParams(window.location.search)
  const gift = params.get('gift_code')
  const idToken = params.get('id_token')
  const fromHash = new URLSearchParams(window.location.hash.slice(1)).get('id_token')
  return { gift, idToken, fromHash }
}
`
	ctx := core.NewFileContext("/src/app/callback/page.tsx", "/src", []byte(code), core.DefaultConfig())
	var lines []int
	for _, v := range NewSensitiveQueryParameterRule().AnalyzeFile(ctx) {
		lines = append(lines, v.Line)
	}
	assert.Equal(t, []int{4}, lines)
}
