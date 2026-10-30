package timerules

import (
	"path/filepath"
	"testing"

	"github.com/aiseeq/glint/pkg/core"
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
	assert.Equal(t, []string{"command/main.go:3", "report/report.go:3", "report/report.go:4"}, patterntest.FoundLines(violations))
	for _, violation := range violations {
		assert.Equal(t, "This module takes time from example.com/app/clock; this standard clock read can disagree with it", violation.Message)
	}
}

func TestClockBypassModuleMainPackage(t *testing.T) {
	files := map[string]string{
		"go.mod": "module example.com/app\n\ngo 1.24\n",
		"clock/clock.go": `package clock
import "time"
func Now() time.Time { return time.Now() }
`,
		"service/service.go": `package service
import "time"
func Run(time.Time) {}
`,
		"command/main.go": `package main
import (
	"time"
	"example.com/app/service"
)
var startedAt = time.Now()
var now time.Time
func main() {
	now = time.Now()
	service.Run(time.Now().UTC())
}
const query = ` + "`SELECT NOW(), NOW()`" + `
`,
	}
	rule := NewClockBypassRule()
	require.NoError(t, rule.Configure(map[string]any{"clock_package": "example.com/app/clock"}))
	violations, err := rule.AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	assert.Equal(t, []string{"command/main.go:10", "command/main.go:12", "command/main.go:12", "command/main.go:6", "command/main.go:9"}, patterntest.FoundLines(violations))
}

func TestClockBypassModuleMainClockSetup(t *testing.T) {
	files := map[string]string{
		"go.mod": "module example.com/app\n\ngo 1.24\n",
		"clock/clock.go": `package clock
import "time"
type Func func() time.Time
var Default Func
var Started time.Time
func Set(Func) {}
func New(location *time.Location) *time.Location { return location }
func Now() time.Time { return time.Now() }
`,
		"command/main.go": `package main
import (
	"time"
	"example.com/app/clock"
)
var appClock = clock.New(time.Now().Location())
func main() {
	clock.Set(func() time.Time { return time.Now() })
	clock.Default = clock.Func(time.Now)
	clock.New(time.Now().Location())
	clock.Default = clock.Func(func() time.Time { return time.Now() })
	clock.Started = time.Now()
}
`,
	}
	rule := NewClockBypassRule()
	require.NoError(t, rule.Configure(map[string]any{"clock_package": "example.com/app/clock"}))
	violations, err := rule.AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	assert.Empty(t, violations)
}

func TestClockBypassModuleOtherModule(t *testing.T) {
	root, contexts := rulestest.Module(t, map[string]string{
		"go.mod": "module example.com/app\n\ngo 1.24\n",
		"clock/clock.go": `package clock
import "time"
func Now() time.Time { return time.Now() }
`,
	})
	outer, err := core.LoadGoProject(root, contexts, core.GoProjectOptions{ListPackages: rulestest.ListPackages})
	require.NoError(t, err)
	otherRoot := filepath.Join(root, "tools")
	otherFiles := rulestest.ModuleIn(t, otherRoot, map[string]string{
		"go.mod": "module example.com/tools\n\ngo 1.24\n",
		"cmd/main.go": `package main
import "time"
func main() { _ = time.Now() }
`,
		"clock/clock.go": `package clock
import "time"
func Read() time.Time { return time.Now() }
`,
	})
	other, err := core.LoadGoProject(otherRoot, otherFiles, core.GoProjectOptions{ListPackages: rulestest.ListPackages})
	require.NoError(t, err)
	project := &core.GoProjectContext{Packages: append(outer.Packages, other.Packages...)}
	rule := NewClockBypassRule()
	require.NoError(t, rule.Configure(map[string]any{"clock_package": "example.com/app/clock"}))
	violations, err := rule.AnalyzeGoProject(project)
	require.NoError(t, err)
	assert.Empty(t, violations)
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

func TestClockBypassSQLFragments(t *testing.T) {
	files := map[string]string{
		"go.mod": "module example.com/app\n\ngo 1.24\n",
		"clock/clock.go": `package clock
import "time"
func Now() time.Time { return time.Now() }
`,
		"store/query.go": `package store
import (
	"fmt"
	"strings"
)
func membershipSQL(table, condition string) string { return table + ".id AND " + condition }
func query() string {
	base := fmt.Sprintf(` + "`g.effective_from <= NOW() AND %[1]s`" + `, "g.active")
	part := membershipSQL("g", "NOW()")
	updates := append([]string{}, "updated_at = NOW()")
	joined := "created_at < " + "CURRENT_TIMESTAMP"
	_ = []string{"expires_at = LOCALTIMESTAMP"}
	return base + part + strings.Join(updates, ",") + joined
}
`,
	}
	rule := NewClockBypassRule()
	require.NoError(t, rule.Configure(map[string]any{"clock_package": "example.com/app/clock"}))
	violations, err := rule.AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	assert.Equal(t, []string{"store/query.go:10", "store/query.go:11", "store/query.go:12", "store/query.go:8", "store/query.go:9"}, patterntest.FoundLines(violations))
	for _, violation := range violations {
		assert.Contains(t, violation.Message, "database clock")
		assert.Contains(t, violation.Suggestion, "$N::timestamptz")
	}
}

func TestClockBypassSQLFragmentsNegatives(t *testing.T) {
	files := map[string]string{
		"go.mod": "module example.com/app\n\ngo 1.24\n",
		"clock/clock.go": `package clock
import "time"
func Now() time.Time { return time.Now() }
`,
		"store/query.go": `package store
import (
	"errors"
	"fmt"
	"log"
)
func report() error {
	log.Printf("database returned NOW()")
	return fmt.Errorf("query failed at NOW(): %w", errors.New("NOW()"))
}
const query = ` + "`SELECT id FROM users WHERE created_at < NOW()`" + `
`,
	}
	rule := NewClockBypassRule()
	require.NoError(t, rule.Configure(map[string]any{"clock_package": "example.com/app/clock"}))
	violations, err := rule.AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	assert.Equal(t, []string{"store/query.go:11"}, patterntest.FoundLines(violations))

	withoutSetting, err := NewClockBypassRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	assert.Empty(t, withoutSetting)
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
