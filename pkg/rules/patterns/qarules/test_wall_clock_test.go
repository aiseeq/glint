package qarules

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patterntest"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testWallClockFindings(t *testing.T, files map[string]string) []string {
	t.Helper()
	root, _ := rulestest.Module(t, files)
	contexts, errs := core.NewWalker(root, core.DefaultConfig()).WalkSync()
	require.Empty(t, errs)
	rule := NewTestDependsOnWallClockRule()
	rule.UseProjectFiles(contexts)
	var violations []*core.Violation
	for _, ctx := range contexts {
		violations = append(violations, rule.AnalyzeFile(ctx)...)
	}
	return patterntest.FoundLines(violations)
}

const wallClockService = `package bot

import "time"

type Config struct {
	Start, End int
	TZ         string
	Day, Night string
}

type Service struct{ cfg Config }

// replyText picks the reply by the business hours of the current moment.
func (s *Service) replyText() (string, error) {
	loc, err := time.LoadLocation(s.cfg.TZ)
	if err != nil {
		return "", err
	}
	now := time.Now().In(loc)
	hour := now.Hour()
	weekday := now.Weekday()
	open := hour >= s.cfg.Start && hour < s.cfg.End &&
		weekday != time.Saturday && weekday != time.Sunday
	if open {
		return s.cfg.Day, nil
	}
	return s.cfg.Night, nil
}

// Handle answers a message with the reply of the moment.
func (s *Service) Handle(msg string) (string, error) {
	return s.replyText()
}

// Route answers only some messages with the reply of the moment.
func (s *Service) Route(msg string) (string, error) {
	if msg == "" {
		return "", nil
	}
	return s.replyText()
}

func greeting() string {
	switch time.Now().Weekday() {
	case time.Saturday, time.Sunday:
		return "weekend"
	}
	return "weekday"
}

// replyAt is the testable form: the moment comes from the caller.
func (s *Service) replyAt(now time.Time) string {
	if now.Hour() < s.cfg.Start {
		return s.cfg.Night
	}
	return s.cfg.Day
}

// stamp reads the clock but takes no decision on the calendar.
func stamp() string {
	return time.Now().Format(time.RFC3339)
}

func elapsed(start time.Time) bool {
	return time.Since(start) > time.Second
}
`

// The tests call code that decides by the hour and the weekday of
// time.Now(): they pass on a weekday at noon and fail at night or on a
// weekend, and nothing in the test can move the clock.
func TestTestDependsOnWallClock(t *testing.T) {
	assert.Equal(t, []string{"bot/bot_test.go:20", "bot/bot_test.go:26", "bot/bot_test.go:9"}, testWallClockFindings(t, map[string]string{
		"bot/bot.go": wallClockService,
		"bot/bot_test.go": `package bot

import "testing"

func testConfig() Config { return Config{Start: 0, End: 24, TZ: "UTC", Day: "day", Night: "night"} }

func TestReplyBusinessHours(t *testing.T) {
	svc := &Service{cfg: testConfig()}
	text, err := svc.replyText()
	if err != nil {
		t.Fatal(err)
	}
	if text != "day" {
		t.Errorf("got %s", text)
	}
}

func TestHandle(t *testing.T) {
	svc := &Service{cfg: testConfig()}
	if got, _ := svc.Handle("hi"); got != "day" {
		t.Errorf("got %s", got)
	}
}

func TestGreeting(t *testing.T) {
	if greeting() != "weekday" {
		t.Error("weekday expected")
	}
}
`,
	}))
}

// Code that takes the moment as an argument, reads the clock without a
// calendar decision, or a test whose clock is faked or whose expectation is
// computed from the same clock is left alone.
func TestTestDependsOnWallClockNegatives(t *testing.T) {
	assert.Empty(t, testWallClockFindings(t, map[string]string{
		"bot/bot.go": wallClockService,
		"bot/bot_test.go": `package bot

import (
	"testing"
	"testing/synctest"
	"time"
)

func TestReplyAt(t *testing.T) {
	svc := &Service{cfg: Config{Start: 9}}
	if svc.replyAt(time.Date(2026, 1, 5, 8, 0, 0, 0, time.UTC)) != "" {
		t.Error("night expected")
	}
}

func TestReplyBadZone(t *testing.T) {
	svc := &Service{cfg: Config{TZ: "Bad/Zone"}}
	if _, err := svc.replyText(); err == nil {
		t.Error("a bad zone fails")
	}
	greeting()
}

func TestRouteEmpty(t *testing.T) {
	svc := &Service{}
	if got, _ := svc.Route(""); got != "" {
		t.Error(got)
	}
}

func TestStamp(t *testing.T) {
	if stamp() == "" || elapsed(time.Now()) {
		t.Error("stamp")
	}
}

func TestGreetingFakeClock(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		if greeting() != "weekend" {
			t.Error("the bubble starts on a Saturday")
		}
	})
}

func TestGreetingMirrorsClock(t *testing.T) {
	want := "weekday"
	if wd := time.Now().Weekday(); wd == time.Saturday || wd == time.Sunday {
		want = "weekend"
	}
	if greeting() != want {
		t.Error(want)
	}
}
`,
		// A program, not a test, calls the clock-dependent code.
		"cmd/run/main.go": `package main

import "time"

func main() {
	if time.Now().Hour() > 22 {
		return
	}
}
`,
	}))
}

// An external test package calls the exported clock-dependent code through
// the package name.
func TestTestDependsOnWallClockExternalPackage(t *testing.T) {
	assert.Equal(t, []string{"bot/bot_ext_test.go:10"}, testWallClockFindings(t, map[string]string{
		"bot/bot.go": wallClockService + `
func Greeting() string { return greeting() }
`,
		"bot/bot_ext_test.go": `package bot_test

import (
	"testing"

	"example.com/rulestest/bot"
)

func TestGreetingExported(t *testing.T) {
	if bot.Greeting() != "weekday" {
		t.Error("weekday expected")
	}
}
`,
	}))
}
