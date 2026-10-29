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
