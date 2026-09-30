package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

func TestDeterministicUUIDRule_Metadata(t *testing.T) {
	rule := NewDeterministicUUIDRule()
	assert.Equal(t, "deterministic-uuid", rule.Name())
	assert.Equal(t, "patterns", rule.Category())
	assert.Equal(t, core.SeverityHigh, rule.DefaultSeverity())
}

// uuidModuleFiles stands in for the UUID libraries: a module that requires
// them from local copies, so the cases type-check offline.
var uuidModuleFiles = map[string]string{
	"go.mod": `module example.com/rulestest

go 1.24

require (
	github.com/gofrs/uuid/v5 v5.0.0
	github.com/google/uuid v1.6.0
)

replace github.com/google/uuid => ./third_party/googleuuid

replace github.com/gofrs/uuid/v5 => ./third_party/gofrsuuid
`,
	"third_party/googleuuid/go.mod": "module github.com/google/uuid\n\ngo 1.24\n",
	"third_party/googleuuid/uuid.go": `package uuid

type UUID [16]byte

var NameSpaceDNS UUID

func New() UUID                                  { return UUID{} }
func NewSHA1(space UUID, data []byte) UUID       { return UUID{} }
func NewMD5(space UUID, data []byte) UUID        { return UUID{} }
func FromBytes(b []byte) (UUID, error)           { return UUID{}, nil }
func Parse(s string) (UUID, error)               { return UUID{}, nil }
func (u UUID) String() string                    { return "" }
`,
	"third_party/gofrsuuid/go.mod": "module github.com/gofrs/uuid/v5\n\ngo 1.24\n",
	"third_party/gofrsuuid/uuid.go": `package uuid

type UUID [16]byte

var NamespaceURL UUID

func NewV4() (UUID, error)            { return UUID{}, nil }
func NewV5(ns UUID, name string) UUID { return UUID{} }
`,
}

func TestDeterministicUUIDRule(t *testing.T) {
	rule := NewDeterministicUUIDRule()

	tests := []struct {
		name          string
		code          string
		expectedCount int
	}{
		{
			name: "name-based UUID from an email",
			code: `package ids

import "github.com/google/uuid"

func accountID(email string) string {
	return uuid.NewSHA1(uuid.NameSpaceDNS, []byte(email)).String()
}`,
			expectedCount: 1,
		},
		{
			name: "MD5 name-based UUID under an alias",
			code: `package ids

import guuid "github.com/google/uuid"

func accountID(email string) guuid.UUID {
	return guuid.NewMD5(guuid.NameSpaceDNS, []byte(email))
}`,
			expectedCount: 1,
		},
		{
			name: "UUID assembled from hash bytes",
			code: `package ids

import (
	"crypto/sha256"

	"github.com/google/uuid"
)

func accountID(email string) (string, error) {
	sum := sha256.Sum256([]byte(email))
	id, err := uuid.FromBytes(sum[:16])
	if err != nil {
		return "", err
	}
	return id.String(), nil
}`,
			expectedCount: 1,
		},
		{
			name: "gofrs NewV5",
			code: `package ids

import "github.com/gofrs/uuid/v5"

func accountID(email string) uuid.UUID {
	return uuid.NewV5(uuid.NamespaceURL, email)
}`,
			expectedCount: 1,
		},
		{
			name: "UUID read back from stored bytes is OK",
			code: `package ids

import "github.com/google/uuid"

func decode(stored []byte) (uuid.UUID, error) {
	return uuid.FromBytes(stored)
}`,
			expectedCount: 0,
		},
		{
			name: "uuid.New is OK",
			code: `package ids

import "github.com/google/uuid"

func createID() string {
	return uuid.New().String()
}`,
			expectedCount: 0,
		},
		{
			// Repro: a cache key and an ETag were reported as synthetic IDs —
			// a string prefix and a sha256 near the word "userID" matched the
			// line patterns.
			name: "cache key and ETag are not IDs",
			code: `package ids

import (
	"crypto/sha256"
	"encoding/hex"
)

func CacheKey(userID string) string {
	return "user-" + userID
}

func ETag(userID string, body []byte) string {
	sum := sha256.Sum256([]byte(string(body)))
	return hex.EncodeToString(sum[:])
}`,
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := map[string]string{"ids/ids.go": tt.code}
			for name, source := range uuidModuleFiles {
				files[name] = source
			}
			violations := runRuleOnFiles(t, rule, files)
			var own int
			for _, v := range violations {
				if v.File == "ids/ids.go" {
					own++
				}
			}
			assert.Equal(t, tt.expectedCount, own, "Test: %s\nCode: %s", tt.name, tt.code)
		})
	}
}

// Without type information the library calls are still known through the
// file's imports; test files are fixtures and are not looked at.
func TestDeterministicUUIDRule_UntypedAndTestFiles(t *testing.T) {
	rule := NewDeterministicUUIDRule()
	code := `package ids

import "github.com/google/uuid"

func accountID(email string) uuid.UUID {
	return uuid.NewSHA1(uuid.NameSpaceDNS, []byte(email))
}`
	assert.Len(t, rule.AnalyzeFile(rulestest.GoFile(t, "ids/ids.go", code)), 1)
	assert.Empty(t, rule.AnalyzeFile(rulestest.GoFile(t, "ids/ids_test.go", code)))
}

func TestDeterministicUUIDRule_NonGoFile(t *testing.T) {
	rule := NewDeterministicUUIDRule()
	ctx := core.NewFileContext("/test/file.ts", "/test", []byte("const id = 'user-' + email"), core.DefaultConfig())
	violations := rule.AnalyzeFile(ctx)
	assert.Empty(t, violations)
}
