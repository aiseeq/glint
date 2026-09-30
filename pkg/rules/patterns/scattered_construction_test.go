package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules"
)

func scatteredServerFile(name string) string {
	return `package projecta

import (
	"net/http"
	"time"
)

func ` + name + `(h http.Handler) *http.Server {
	return &http.Server{Addr: ":80", Handler: h, ReadTimeout: time.Second}
}
`
}

// Every site of a scattered type is reported, whatever the order the files
// are seen in, with the project-relative path.
func TestScatteredConstructionReportsEverySite(t *testing.T) {
	rule := NewScatteredConstructionRule()
	_, isProjectRule := any(rule).(rules.GoProjectRule)
	require.True(t, isProjectRule, "sites are collected over the whole project before reporting")

	violations := runRuleOnFiles(t, rule, map[string]string{
		"srv/a.go": scatteredServerFile("serverA"),
		"srv/b.go": scatteredServerFile("serverB"),
		"srv/c.go": scatteredServerFile("serverC"),
	})

	require.Len(t, violations, 3)
	var files []string
	for _, v := range violations {
		files = append(files, v.File)
		assert.Equal(t, 9, v.Line)
		assert.Contains(t, v.Message, "http.Server constructed in 3 places")
	}
	assert.Equal(t, []string{"srv/a.go", "srv/b.go", "srv/c.go"}, files)
}

func TestScatteredConstructionBelowThreshold(t *testing.T) {
	violations := runRuleOnFiles(t, NewScatteredConstructionRule(), map[string]string{
		"srv/a.go": scatteredServerFile("serverA"),
		"srv/b.go": scatteredServerFile("serverB"),
	})
	assert.Empty(t, violations)
}

// Two runs of the same rule instance do not share sites.
func TestScatteredConstructionRunsAreIndependent(t *testing.T) {
	rule := NewScatteredConstructionRule()
	files := map[string]string{
		"srv/a.go": scatteredServerFile("serverA"),
		"srv/b.go": scatteredServerFile("serverB"),
	}
	assert.Empty(t, runRuleOnFiles(t, rule, files))
	assert.Empty(t, runRuleOnFiles(t, rule, files))
}
