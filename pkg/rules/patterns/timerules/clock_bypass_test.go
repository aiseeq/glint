package timerules

import (
	"testing"

	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patterntest"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClockBypass(t *testing.T) {
	files := map[string]string{
		"go.mod": "module example.test/project\n\ngo 1.24\n",
		"shared/clock/clock.go": `package clock

import "time"

func Now() time.Time { return time.Now() }
`,
		"service/a.go": `package service

import "example.test/project/shared/clock"

func readA() { _ = clock.Now() }
`,
		"service/b.go": `package service

import "example.test/project/shared/clock"

func readB() { _ = clock.Now() }
`,
		"service/c.go": `package service

import "time"

func readC() { _ = time.Now() }
func elapsed() {
	start := time.Now()
	_ = time.Since(start)
}
`,
	}
	violations, err := NewClockBypassRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	assert.Equal(t, []string{"service/c.go:5"}, patterntest.FoundLines(violations))
	assert.Contains(t, violations[0].Message, "2 times")
	assert.Contains(t, violations[0].Message, "service/a.go (1), service/b.go (1)")
}

func TestClockBypassNegatives(t *testing.T) {
	files := map[string]string{
		"go.mod": "module example.test/project\n\ngo 1.24\n",
		"shared/clock/clock.go": `package clock

import "time"

func Now() time.Time { return time.Now() }
`,
		"service/one.go": `package service

import (
	"time"
	"example.test/project/shared/clock"
)

func one() { _ = clock.Now(); _ = time.Since(time.Now()) }
`,
		"service/two.go": `package service

import "time"

func two() { _ = time.Now() }
`,
		"command/main.go": `package main

import (
	"time"
	"example.test/project/shared/clock"
)

func main() { _ = clock.Now(); _ = clock.Now(); _ = time.Now() }
`,
		"shared/clock/clock_test.go": `package clock

import "testing"

func TestNow(t *testing.T) { _ = Now() }
`,
	}
	violations, err := NewClockBypassRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	assert.Empty(t, violations)
}

func TestClockBypassModuleClockPackage(t *testing.T) {
	files := map[string]string{
		"go.mod": "module example.com/app\n\ngo 1.24\n",
		"clock/clock.go": `package clock
import "time"
type Clock interface { Now() time.Time }
func Now() time.Time { return time.Now() }
`,
		"report/report.go": `package report
import "time"
var moduleStart = time.Now()
func Since() time.Time { return time.Now().Add(-time.Hour) }
func Took() time.Duration { start := time.Now(); work(); return time.Since(start) }
func work() {}
`,
		"command/main.go": `package main
import "time"
func main() { _ = time.Now() }
`,
	}
	rule := NewClockBypassRule()
	require.NoError(t, rule.Configure(map[string]any{"clock_package": "example.com/app/clock"}))
	violations, err := rule.AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	assert.Equal(t, []string{"report/report.go:3", "report/report.go:4"}, patterntest.FoundLines(violations))
	for _, violation := range violations {
		assert.Equal(t, "This module takes time from example.com/app/clock; this standard clock read can disagree with it", violation.Message)
	}
}

func TestClockBypassModuleClockSQL(t *testing.T) {
	files := map[string]string{
		"go.mod": "module example.com/app\n\ngo 1.24\n",
		"clock/clock.go": `package clock
import "time"
func Now() time.Time { return time.Now() }
`,
		"store/store.go":     "package store\nconst q = `UPDATE jobs SET processed_at = NOW() WHERE id = $1`\nconst r = `SELECT id FROM jobs WHERE created_at >= now() - interval '1 day'`\nconst t = `SELECT CURRENT_TIMESTAMP, LOCALTIMESTAMP, CURRENT_DATE`\nconst s = \"now is the time\"\nconst n = \"SELECT id FROM t WHERE label = 'now'\"\nconst m = \"SELECT now_at FROM t\"\n",
		"store/multiline.go": "package store\nconst query = `SELECT id\nFROM jobs\nWHERE created_at > NOW()`\n",
		"migrations/001.sql": "CREATE TABLE jobs (created_at timestamp DEFAULT now());\n",
	}
	rule := NewClockBypassRule()
	require.NoError(t, rule.Configure(map[string]any{"clock_package": "example.com/app/clock"}))
	violations, err := rule.AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	assert.Equal(t, []string{"store/multiline.go:4", "store/store.go:2", "store/store.go:3", "store/store.go:4", "store/store.go:4", "store/store.go:4"}, patterntest.FoundLines(violations))
	for _, violation := range violations {
		assert.Contains(t, violation.Message, "database clock")
		assert.Contains(t, violation.Message, "parameter")
		assert.Contains(t, violation.Suggestion, "$N::timestamptz")
	}
}

func TestClockBypassModuleClockUnset(t *testing.T) {
	files := map[string]string{
		"go.mod": "module example.com/app\n\ngo 1.24\n",
		"clock/clock.go": `package clock
import "time"
func Now() time.Time { return time.Now() }
`,
		"report/report.go": `package report
import "time"
func Since() time.Time { return time.Now().Add(-time.Hour) }
`,
	}
	violations, err := NewClockBypassRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	assert.Empty(t, violations)
}

func TestClockBypassProjectClockMethodAndTimeUntil(t *testing.T) {
	files := map[string]string{
		"go.mod": "module example.test/project\n\ngo 1.24\n",
		"service/clock.go": `package service

import "time"

type Clock interface { Now() time.Time }
type Service struct { clock Clock }

func (s *Service) readA() { _ = s.clock.Now() }
`,
		"service/other.go": `package service

import (
	"time"
	"example.test/project/shared"
)

func readB() { _ = shared.Now() }
func readC() {
	deadline := time.Now()
	_ = time.Until(deadline)
}
func readStruct(c shared.Clock) { _ = c.Now() }
`,
		"shared/clock.go": `package shared

import "time"

type Clock struct{}
func (Clock) Now() time.Time { return time.Now() }
func Now() time.Time { return time.Now() }
`,
	}
	violations, err := NewClockBypassRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	assert.Equal(t, []string{"service/other.go:10", "service/other.go:11"}, patterntest.FoundLines(violations))
}
