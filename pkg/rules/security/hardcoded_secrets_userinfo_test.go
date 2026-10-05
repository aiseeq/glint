package security

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/core"
)

// A real password inside the userinfo of a DSN is a hardcoded secret whatever
// the variable is called, in a test helper and in a committed env template
// as well.
func TestHardcodedSecretsPasswordInURLUserinfo(t *testing.T) {
	cases := []struct {
		name, path, code string
		want             []int
	}{
		{
			name: "DSN constants of a test helper",
			path: "/src/internal/testdb/testdb_test.go",
			code: `package testdb

const (
	adminDSN = "postgres://app:k7Qm2vX9pL4w@127.0.0.1:5432/postgres?sslmode=disable"
	baseDSN  = "postgres://app:k7Qm2vX9pL4w@127.0.0.1:5432/%s?sslmode=disable"
	localDSN = "postgres://postgres:postgres@localhost:5432/app"
	hintDSN  = "postgres://user:password@localhost:5432/app"
	envDSN   = "postgres://app:${DB_PASSWORD}@db:5432/app"
	fmtDSN   = "postgres://%s:%s@%s/%s"
)
`,
			want: []int{4, 5},
		},
		{
			name: "env template values",
			path: "/src/.env.example",
			code: `# database
DB_DSN=postgres://app:k7Qm2vX9pL4w@127.0.0.1:5432/app?sslmode=disable
CACHE_URL=redis://:changeme@localhost:6379/0
API_TOKEN=Zx81kq0Pw3nB7tYv
SESSION_SECRET=replace-me
UPSTREAM_SECRET_FILE=/run/secrets/upstream
# OLD_DSN=postgres://app:k7Qm2vX9pL4w@127.0.0.1:5432/app
`,
			want: []int{2, 4},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := core.NewFileContext(tc.path, "/src", []byte(tc.code), core.DefaultConfig())
			var lines []int
			for _, v := range NewHardcodedSecretsRule().AnalyzeFile(ctx) {
				lines = append(lines, v.Line)
				assert.NotContains(t, v.Code, "k7Qm2vX9pL4w", "the reported code masks the password")
			}
			assert.Equal(t, tc.want, lines)
		})
	}
}
