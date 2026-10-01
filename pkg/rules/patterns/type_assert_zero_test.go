package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// A factory asserts a constructed service to its interface through a generic
// helper; the service lacks one method, the assertion fails, the helper
// returns nil and the first login panics far from the cause.
func TestTypeAssertMismatchReturnsZero(t *testing.T) {
	violations, err := NewTypeAssertMismatchReturnsZeroRule().AnalyzeGoProject(rulestest.Project(t, map[string]string{
		"registry/registry.go": `package registry

import (
	"errors"
	"fmt"
)

type AuthService interface {
	Login(user string) error
	Logout(user string) error
}

func safeCast[T any](value any) T {
	if value == nil {
		var zero T
		return zero
	}
	if result, ok := value.(T); ok {
		return result
	}
	var zero T
	return zero
}

func asAuth(value any) AuthService {
	auth, ok := value.(AuthService)
	if !ok {
		return nil
	}
	return auth
}

func asString(value any) string {
	if s, ok := value.(string); ok {
		return s
	}
	return ""
}

func castOrError[T any](value any) (T, error) {
	if result, ok := value.(T); ok {
		return result, nil
	}
	var zero T
	return zero, errors.New("unexpected type")
}

func castOK[T any](value any) (T, bool) {
	result, ok := value.(T)
	return result, ok
}

func mustCast[T any](value any) T {
	if result, ok := value.(T); ok {
		return result
	}
	panic(fmt.Sprintf("unexpected type %T", value))
}

func describe(value any) string {
	if s, ok := value.(fmt.Stringer); ok {
		return s.String()
	}
	return ""
}

func extractAuth(value any) AuthService {
	var auth AuthService
	if a, ok := value.(AuthService); ok {
		auth = a
	}
	return auth
}

func authOrDefault(value any, fallback func() AuthService) AuthService {
	var auth AuthService
	auth = fallback()
	if a, ok := value.(AuthService); ok {
		return a
	}
	return auth
}
`,
	}))
	require.NoError(t, err)
	assert.Equal(t, []string{"registry/registry.go:22", "registry/registry.go:28", "registry/registry.go:72"}, foundLines(violations))
}
