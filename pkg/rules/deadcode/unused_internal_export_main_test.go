package deadcode

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// Nothing imports a main package: an access check it exports that only its
// tests call is a guard production never applies.
func TestUnusedInternalExportRule_MainPackageExportOnlyTestsCall(t *testing.T) {
	project := rulestest.Project(t, map[string]string{
		"cmd/server/access.go": `package main

import "errors"

// CheckAccountAccess is the guard the handlers were meant to call.
func CheckAccountAccess(allowed []string, id string) error {
	for _, a := range allowed {
		if a == id {
			return nil
		}
	}
	return errors.New("denied")
}

// Version is printed at start.
const Version = "1"

func main() { println(Version) }
`,
		"cmd/server/access_test.go": `package main

import "testing"

func TestCheckAccountAccess(t *testing.T) {
	if CheckAccountAccess([]string{"a"}, "b") == nil {
		t.Fatal("allowed")
	}
}
`,
	})
	violations, err := NewUnusedInternalExportRule().AnalyzeGoProject(project)
	require.NoError(t, err)
	require.Len(t, violations, 1)
	assert.Contains(t, violations[0].Message, "CheckAccountAccess")
	assert.Contains(t, violations[0].Message, "used only by tests")
	assert.Contains(t, violations[0].Message, "main package")
	assert.Equal(t, 6, violations[0].Line)
}
