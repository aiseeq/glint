package deadcode

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

func responseFieldNeverSetLines(t *testing.T, files map[string]string) []string {
	t.Helper()
	violations, err := NewResponseFieldNeverSetRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	var found []string
	for _, v := range violations {
		found = append(found, v.File+":"+v.Message[:20])
	}
	return found
}

// The dashboard field nobody assigns: the response carries zero every time,
// and the screen shows zero withdrawals.
func TestResponseFieldNeverSet(t *testing.T) {
	violations, err := NewResponseFieldNeverSetRule().AnalyzeGoProject(rulestest.Project(t, map[string]string{
		"stats/stats.go": `package stats

import "encoding/json"

type Dashboard struct {
	TotalDeposits    int64 ` + "`json:\"totalDeposits\"`" + `
	TotalWithdrawals int64 ` + "`json:\"totalWithdrawals\"`" + `
	Internal         int64
}

func Build(deposits int64) ([]byte, error) {
	return json.Marshal(Dashboard{TotalDeposits: deposits, Internal: 1})
}

type Withdrawal struct {
	ID           string ` + "`json:\"id\" db:\"id\"`" + `
	Amount       string ` + "`json:\"amount\" db:\"amount\"`" + `
	ClientNumber string ` + "`json:\"clientNumber\" db:\"client_number\"`" + `
}

type DB interface {
	Select(dest any, query string, args ...any) error
}

func List(db DB) ([]Withdrawal, error) {
	var out []Withdrawal
	err := db.Select(&out, "SELECT id, amount FROM withdrawals")
	return out, err
}

func Feed(db DB) ([]Withdrawal, error) {
	var out []Withdrawal
	err := db.Select(&out, "SELECT * FROM (SELECT id, amount FROM withdrawals) t")
	return out, err
}

type Audit struct {
	ID   string ` + "`json:\"id\" db:\"id\"`" + `
	Note string ` + "`json:\"note\" db:\"note\"`" + `
}

func Audits(db DB) ([]Audit, error) {
	var out []Audit
	err := db.Select(&out, "SELECT * FROM audits")
	return out, err
}
`,
	}))
	require.NoError(t, err)
	var lines []int
	for _, v := range violations {
		lines = append(lines, v.Line)
	}
	assert.Equal(t, []int{7, 18}, lines)
}

// Decoded types, fields some code writes, columns a query names, values
// converted from another struct, and types nothing builds are left alone.
func TestResponseFieldNeverSetAllowed(t *testing.T) {
	assert.Empty(t, responseFieldNeverSetLines(t, map[string]string{
		"api/api.go": `package api

import "encoding/json"

type Request struct {
	Name  string ` + "`json:\"name\"`" + `
	Email string ` + "`json:\"email\"`" + `
}

func Parse(data []byte) (Request, error) {
	var r Request
	err := json.Unmarshal(data, &r)
	return r, err
}

type Profile struct {
	Name  string ` + "`json:\"name\"`" + `
	Phone string ` + "`json:\"phone\"`" + `
}

func NewProfile(name string) *Profile {
	p := &Profile{Name: name}
	p.Phone = "+1"
	return p
}

type Row struct {
	ID     string ` + "`json:\"id\" db:\"id\"`" + `
	Client string ` + "`json:\"client\" db:\"client_number\"`" + `
}

type DB interface {
	Get(dest any, query string, args ...any) error
}

func Load(db DB) (Row, error) {
	var r Row
	err := db.Get(&r, "SELECT r.id, u.number AS client_number FROM rows r JOIN users u ON u.id = r.user_id")
	return r, err
}

type source struct {
	Name  string
	Phone string
}

type View struct {
	Name  string ` + "`json:\"name\"`" + `
	Phone string ` + "`json:\"phone\"`" + `
}

func Convert(s source) View { return View(s) }

func Use() source { return source{Name: "a", Phone: "b"} }

type Claims interface{ Valid() error }

type TokenClaims struct {
	Subject string ` + "`json:\"sub\"`" + `
	Issuer  string ` + "`json:\"iss\"`" + `
}

func (c *TokenClaims) Valid() error { return nil }

func ParseWithClaims(token string, claims Claims) error { return nil }

func Verify(token string) (*TokenClaims, error) {
	claims := &TokenClaims{Subject: "x"}
	err := ParseWithClaims(token, claims)
	return claims, err
}

type Page struct {
	Total int ` + "`json:\"total\"`" + `
	Items int ` + "`json:\"items\"`" + `
}

func decode[T any](data []byte, out *T) error { return json.Unmarshal(data, out) }

func LoadPage(data []byte) (Page, error) {
	p := Page{Items: 1}
	err := decode(data, &p)
	return p, err
}

type Range struct {
	Start string ` + "`json:\"start\"`" + `
	End   string ` + "`json:\"end\"`" + `
}

type Stats struct {
	Count int   ` + "`json:\"count\"`" + `
	Dates Range ` + "`json:\"dates\"`" + `
	From  struct {
		Account string ` + "`json:\"account\"`" + `
	} ` + "`json:\"from\"`" + `
	Window Range ` + "`json:\"window\"`" + `
}

func (r *Range) Fill(start string) { r.Start = start }

func Collect(first, last, account string) Stats {
	s := Stats{Count: 2}
	s.Dates.Start = first
	s.Dates.End = last
	s.From.Account = account
	s.Window.Fill(first)
	return s
}

type Account struct {
	ID    string ` + "`json:\"id\" db:\"id\"`" + `
	Owner string ` + "`json:\"owner\" db:\"owner_name\"`" + `
}

func LoadAccount(db DB, id string) (Account, error) {
	var a Account
	query := "SELECT * FROM accounts WHERE id = $1"
	err := db.Get(&a, query, id)
	return a, err
}

type Unused struct {
	A string ` + "`json:\"a\"`" + `
	B string ` + "`json:\"b\"`" + `
}
`,
	}))
}
