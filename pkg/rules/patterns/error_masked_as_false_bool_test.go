package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/core"
)

func TestErrorMaskedAsFalseBoolRule(t *testing.T) {
	rule := NewErrorMaskedAsFalseBoolRule()

	tests := []struct {
		name          string
		path          string
		code          string
		expectedCount int
	}{
		{
			name: "ValidateUserPermission masks error as false",
			path: "/src/backend/auth.go",
			code: `package auth
type C struct{}
func (c *C) GetRolePermissions(role string) ([]string, error) { return nil, nil }
func (c *C) ValidateUserPermission(userRole, perm string) bool {
	permissions, err := c.GetRolePermissions(userRole)
	if err != nil {
		return false
	}
	_ = permissions
	return true
}`,
			expectedCount: 1,
		},
		{
			name: "error logged by the receiver's own log method NOT flagged",
			path: "/src/backend/plan.go",
			code: `package plan
type Ctx struct{}
func (c *Ctx) log(format string, args ...any) {}
func (c *Ctx) Load(id string) (int, error) { return 0, nil }
func (c *Ctx) PlaceBuilding(id string) bool {
	n, err := c.Load(id)
	if err != nil {
		c.log("place %s: %v", id, err)
		return false
	}
	return n > 0
}`,
			expectedCount: 0,
		},
		{
			name: "error logged by the receiver's Log<Word> method NOT flagged",
			path: "/src/backend/plan.go",
			code: `package plan
type Ctx struct{ Log func(string) }
func (c *Ctx) LogLine(msg string, kv ...any) {}
func (c *Ctx) Load(id string) (int, error) { return 0, nil }
func (c *Ctx) PlaceBuilding(id string) bool {
	n, err := c.Load(id)
	if err != nil {
		c.LogLine("place", "id", id, "error", err)
		return false
	}
	return n > 0
}`,
			expectedCount: 0,
		},
		{
			name: "Login is not a logging verb — masked error still flagged",
			path: "/src/backend/session.go",
			code: `package session
type S struct{}
func (s *S) Login(user string) {}
func (s *S) Load(id string) (int, error) { return 0, nil }
func (s *S) Ready(id string) bool {
	n, err := s.Load(id)
	if err != nil {
		s.Login(id)
		return false
	}
	return n > 0
}`,
			expectedCount: 1,
		},
		{
			name: "error written to stderr by a CLI NOT flagged",
			path: "/src/cmd/tool/cache.go",
			code: `package main
import (
	"fmt"
	"os"
)
func load(dir string) (string, error) { return "", nil }
func cached(dir string) bool {
	key, err := load(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: cache off for %s: %v\n", dir, err)
		return false
	}
	return key != ""
}`,
			expectedCount: 0,
		},
		{
			name: "error written to stdout or a buffer — flagged",
			path: "/src/cmd/tool/cache.go",
			code: `package main
import (
	"fmt"
	"os"
)
func load(dir string) (string, error) { return "", nil }
func cached(dir string) bool {
	key, err := load(dir)
	if err != nil {
		fmt.Fprintf(os.Stdout, "cache off: %v\n", err)
		return false
	}
	return key != ""
}`,
			expectedCount: 1,
		},
		{
			name: "math.Log is not logging — flagged",
			path: "/src/backend/plan.go",
			code: `package plan
import "math"
type Ctx struct{}
func (c *Ctx) Load(id string) (float64, error) { return 0, nil }
func (c *Ctx) Worth(id string) bool {
	v, err := c.Load(id)
	if err != nil {
		_ = math.Log(v)
		return false
	}
	return v > 0
}`,
			expectedCount: 1,
		},
		{
			name: "HasRole pure predicate NOT flagged",
			path: "/src/backend/auth.go",
			code: `package auth
type C struct{}
func (c *C) Lookup(r string) (bool, error) { return false, nil }
func (c *C) HasRole(r string) bool {
	ok, err := c.Lookup(r)
	if err != nil {
		return false
	}
	return ok
}`,
			expectedCount: 0,
		},
		{
			name: "IsEnabled pure predicate NOT flagged",
			path: "/src/backend/auth.go",
			code: `package auth
type C struct{}
func (c *C) Load() (bool, error) { return false, nil }
func (c *C) IsEnabled() bool {
	ok, err := c.Load()
	if err != nil {
		return false
	}
	return ok
}`,
			expectedCount: 0,
		},
		{
			name: "CanWrite pure predicate NOT flagged",
			path: "/src/backend/auth.go",
			code: `package auth
type C struct{}
func (c *C) Load() (bool, error) { return false, nil }
func (c *C) CanWrite() bool {
	ok, err := c.Load()
	if err != nil {
		return false
	}
	return ok
}`,
			expectedCount: 0,
		},
		{
			name: "Validate with logging before return false NOT flagged",
			path: "/src/backend/auth.go",
			code: `package auth
import "log"
type C struct{}
func (c *C) Load() (bool, error) { return false, nil }
func (c *C) ValidateAccess() bool {
	ok, err := c.Load()
	if err != nil {
		log.Printf("load failed: %v", err)
		return false
	}
	return ok
}`,
			expectedCount: 0,
		},
		{
			name: "non-bool return NOT flagged",
			path: "/src/backend/auth.go",
			code: `package auth
type C struct{}
func (c *C) Load() (int, error) { return 0, nil }
func (c *C) GetValue() int {
	v, err := c.Load()
	if err != nil {
		return 0
	}
	return v
}`,
			expectedCount: 0,
		},
		{
			name: "Issue prefix NOT treated as predicate (Is+lowercase NOT matched)",
			path: "/src/backend/auth.go",
			code: `package auth
type C struct{}
func (c *C) Load() (bool, error) { return false, nil }
func (c *C) IssueCredential() bool {
	ok, err := c.Load()
	if err != nil {
		return false
	}
	return ok
}`,
			expectedCount: 1, // "Issue" is NOT predicate, should be flagged
		},
		{
			name: "test file skipped",
			path: "/src/backend/auth_test.go",
			code: `package auth
type C struct{}
func (c *C) Load() (bool, error) { return false, nil }
func (c *C) ValidateFoo() bool {
	_, err := c.Load()
	if err != nil { return false }
	return true
}`,
			expectedCount: 0,
		},
		{
			name: "nolint honored",
			path: "/src/backend/auth.go",
			code: `package auth
type C struct{}
func (c *C) Load() (bool, error) { return false, nil }
func (c *C) ValidateFoo() bool {
	_, err := c.Load()
	if err != nil {
		return false //nolint:error-masked-as-false-bool // intentional
	}
	return true
}`,
			expectedCount: 0,
		},
		{
			name: "returning the error alongside false is propagation, not masking",
			path: "/src/backend/store.go",
			code: `package store
type C struct{}
func (c *C) lookup(k string) (bool, error) { return false, nil }
func (c *C) Record(k string) (bool, error) {
	ok, err := c.lookup(k)
	if err != nil {
		return false, err
	}
	return ok, nil
}`,
			expectedCount: 0,
		},
		{
			name: "returning a wrapped error alongside false is propagation",
			path: "/src/backend/store.go",
			code: `package store
import "fmt"
type C struct{}
func (c *C) lookup(k string) (bool, error) { return false, nil }
func (c *C) Record(k string) (bool, error) {
	ok, err := c.lookup(k)
	if err != nil {
		return false, fmt.Errorf("record %s: %w", k, err)
	}
	return ok, nil
}`,
			expectedCount: 0,
		},
		{
			name: "returning false with an explicit nil error is still masking",
			path: "/src/backend/store.go",
			code: `package store
type C struct{}
func (c *C) lookup(k string) (bool, error) { return false, nil }
func (c *C) Record(k string) (bool, error) {
	ok, err := c.lookup(k)
	if err != nil {
		return false, nil
	}
	return ok, nil
}`,
			expectedCount: 1,
		},
		{
			// Ветка отказа отдаёт ошибку клиенту через общего помощника: и вызывающий
			// узнал о сбое ответом, и в журнале он есть. Имя помощника ничего не значит.
			name: "error branch answers the client through the response writer",
			path: "/src/backend/web.go",
			code: `package web
import "net/http"
type A struct{}
func (a *A) fail(w http.ResponseWriter, r *http.Request, msg string, err error) {}
func (a *A) load(ctx interface{}) ([]string, error) { return nil, nil }
func (a *A) allItemsOr500(w http.ResponseWriter, r *http.Request) ([]string, bool) {
	items, err := a.load(r.Context())
	if err != nil {
		a.fail(w, r, "failed to load items", err)
		return nil, false
	}
	return items, true
}`,
			expectedCount: 0,
		},
		{
			// Тот же writer в параметрах, но ветка им не пользуется: ошибка потеряна.
			name: "response writer in scope but the branch answers nobody",
			path: "/src/backend/web.go",
			code: `package web
import "net/http"
type A struct{}
func (a *A) load(ctx interface{}) ([]string, error) { return nil, nil }
func (a *A) allItemsOr500(w http.ResponseWriter, r *http.Request) ([]string, bool) {
	items, err := a.load(r.Context())
	if err != nil {
		return nil, false
	}
	return items, true
}`,
			expectedCount: 1,
		},
		{
			// Лукап (value, found, error): ErrNoRows, опознанный через errors.Is,
			// и есть «не найдено»; прочие ошибки уходят вызывающему.
			name: "classified not-found answers false, the rest is returned",
			path: "/src/backend/store.go",
			code: `package store
import (
	"database/sql"
	"errors"
	"fmt"
)
type Repo struct{ db *sql.DB }
func (r *Repo) FindOwner(id string) (string, bool, error) {
	var owner string
	err := r.db.QueryRow("SELECT owner FROM wallets WHERE id = $1", id).Scan(&owner)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("find owner: %w", err)
	}
	return owner, true, nil
}
func (r *Repo) FindOwnerSwitch(id string) (string, bool, error) {
	var owner string
	err := r.db.QueryRow("SELECT owner FROM wallets WHERE id = $1", id).Scan(&owner)
	if err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return "", false, nil
		default:
			return "", false, fmt.Errorf("find owner: %w", err)
		}
	}
	return owner, true, nil
}`,
			expectedCount: 0,
		},
		{
			name: "classified not-found beside an unclassified false still reported",
			path: "/src/backend/store.go",
			code: `package store
import (
	"database/sql"
	"errors"
)
type Repo struct{ db *sql.DB }
func (r *Repo) FindOwner(id string) (string, bool, error) {
	var owner string
	err := r.db.QueryRow("SELECT owner FROM wallets WHERE id = $1", id).Scan(&owner)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", false, nil
		}
		return "", false, nil
	}
	return owner, true, nil
}`,
			expectedCount: 1,
		},
		{
			// Итератор в духе sql.Rows: Next кладёт ошибку в поле получателя,
			// а Err() её отдаёт — вызывающий узнаёт о сбое после цикла.
			name: "iterator stores the error for its Err method NOT flagged",
			path: "/src/backend/sheet.go",
			code: `package sheet
import (
	"database/sql"
	"fmt"
)
type reader struct {
	rows  *sql.Rows
	cells []string
	err   error
}
func (r *reader) Next() bool {
	if !r.rows.Next() {
		return false
	}
	cells, err := r.rows.Columns()
	if err != nil {
		r.err = fmt.Errorf("read: %w", err)
		return false
	}
	r.cells = cells
	return true
}
func (r *reader) Err() error { return r.err }`,
			expectedCount: 0,
		},
		{
			// Err() читает поля под условием и склеивает накопленные тексты ошибок:
			// и обёртка в поле-ошибку, и текст в поле-срез доходят до вызывающего.
			name: "iterator Err reads the fields under ifs and joins collected texts NOT flagged",
			path: "/src/backend/sheet.go",
			code: `package sheet
import (
	"errors"
	"fmt"
	"strings"
)
type source interface {
	Next() bool
	Columns() ([]string, error)
}
type reader struct {
	rows source
	err  error
	errs []string
}
func parse(c []string) (string, error) {
	if len(c) == 0 {
		return "", errors.New("empty")
	}
	return c[0], nil
}
func (r *reader) Next() bool {
	for r.rows.Next() {
		cells, err := r.rows.Columns()
		if err != nil {
			r.err = fmt.Errorf("read row: %w", err)
			return false
		}
		if _, err := parse(cells); err != nil {
			r.errs = append(r.errs, err.Error())
			return false
		}
		return true
	}
	return false
}
func (r *reader) Err() error {
	if r.err != nil {
		return r.err
	}
	if len(r.errs) > 0 {
		return fmt.Errorf("%s", strings.Join(r.errs, "; "))
	}
	return nil
}`,
			expectedCount: 0,
		},
		{
			// Ошибка в поле, но Err() отдаёт другое поле (или его нет): сбой потерян.
			name: "error stored in a field no Err method returns still flagged",
			path: "/src/backend/sheet.go",
			code: `package sheet
import "database/sql"
type reader struct {
	rows    *sql.Rows
	cells   []string
	lastErr error
	err     error
}
func (r *reader) Next() bool {
	cells, err := r.rows.Columns()
	if err != nil {
		r.lastErr = err
		return false
	}
	r.cells = cells
	return true
}
func (r *reader) Err() error { return r.err }
type other struct{ err error }
func (o *other) Next(rows *sql.Rows) bool {
	_, err := rows.Columns()
	if err != nil {
		o.err = err
		return false
	}
	return true
}`,
			expectedCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := core.NewFileContext(tt.path, "/src", []byte(tt.code), core.DefaultConfig())
			parser := core.NewParser()
			fset, astFile, err := parser.ParseGoFile(tt.path, []byte(tt.code))
			if err == nil {
				ctx.SetGoAST(fset, astFile)
			}
			violations := rule.AnalyzeFile(ctx)
			assert.Len(t, violations, tt.expectedCount, "Code: %s", tt.code)
		})
	}
}
