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
