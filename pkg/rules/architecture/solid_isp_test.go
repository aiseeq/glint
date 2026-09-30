package architecture

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

func TestSolidISPRule_Metadata(t *testing.T) {
	rule := NewSolidISPRule()

	assert.Equal(t, "solid-isp", rule.Name())
	assert.Equal(t, "architecture", rule.Category())
	assert.Equal(t, core.SeverityHigh, rule.DefaultSeverity())
}

func TestSolidISPRule_LargeInterfaceFlagged(t *testing.T) {
	rule := NewSolidISPRule()
	require.NoError(t, rule.Configure(map[string]any{
		"max_methods": 3,
	}))

	goCode := `package api

type UserAPI interface {
	Create() error
	Fetch() error
	Modify() error
	Remove() error
}
`
	ctx := createTestContext(t, "backend/api/user_api.go", goCode)
	violations := rule.AnalyzeFile(ctx)

	require.Len(t, violations, 1)
	assert.Contains(t, violations[0].Message, "UserAPI interface has 4 methods (max 3)")
}

func TestSolidISPRule_SmallInterfaceOK(t *testing.T) {
	rule := NewSolidISPRule()
	require.NoError(t, rule.Configure(map[string]any{
		"max_methods": 3,
	}))

	goCode := `package api

type Reader interface {
	Fetch() error
	Stream() error
}
`
	ctx := createTestContext(t, "backend/api/reader.go", goCode)
	violations := rule.AnalyzeFile(ctx)

	assert.Empty(t, violations)
}

func TestSolidISPRule_ConfigInterfaceSkipped(t *testing.T) {
	rule := NewSolidISPRule()
	require.NoError(t, rule.Configure(map[string]any{
		"max_methods": 3,
	}))

	goCode := `package api

type ServerConfig interface {
	Host() string
	Port() int
	Timeout() int
	Retries() int
}
`
	ctx := createTestContext(t, "backend/api/server.go", goCode)
	violations := rule.AnalyzeFile(ctx)

	assert.Empty(t, violations, "config interfaces are legitimately large and must be skipped")
}

func TestSolidISPRule_TestFilesExcluded(t *testing.T) {
	rule := NewSolidISPRule()
	require.NoError(t, rule.Configure(map[string]any{
		"max_methods": 3,
	}))

	goCode := `package api

type FakeUserAPI interface {
	Create() error
	Fetch() error
	Modify() error
	Remove() error
}
`
	ctx := createTestContext(t, "backend/api/user_api_test.go", goCode)
	violations := rule.AnalyzeFile(ctx)

	assert.Empty(t, violations, "Test files should be excluded")
}

// An embedded interface brings its whole method set, not one method: the
// interface a client has to implement is the full set.
func TestSolidISPRule_CountsMethodsOfEmbeddedInterfaces(t *testing.T) {
	rule := NewSolidISPRule()
	require.NoError(t, rule.Configure(map[string]any{"max_methods": 3}))

	project := rulestest.Project(t, map[string]string{"backend/api/api.go": `package api

import "io"

type Small interface {
	A()
	B()
}

type Wide interface {
	Small
	C()
	D()
}

type Stream interface {
	io.ReadWriteCloser
	Flush() error
}

type Tiny interface{ A() }
`})
	violations, err := rule.AnalyzeGoProject(project)
	require.NoError(t, err)
	require.Len(t, violations, 2)
	assert.Contains(t, violations[0].Message, "Wide interface has 4 methods (max 3)")
	assert.Contains(t, violations[1].Message, "Stream interface has 4 methods (max 3)")
}
