package httprules

import (
	"testing"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
)

// A duration of the config with UnmarshalText alone lands in the state the
// program saves as JSON and loads back: JSON writes it as a number and reads
// it as text, so the saved state no longer loads.
func TestJSONTextCodecOneSided(t *testing.T) {
	tag := func(s string) string { return "`" + s + "`" }
	assert.Equal(t, []string{"state/state.go:12", "state/state.go:13", "state/state.go:14", "state/state.go:15"},
		rulestest.ProjectRulePlaces(t, NewJSONTextCodecOneSidedRule(), map[string]string{
			"policy/policy.go": `package policy

import (
	"strconv"
	"strings"
	"time"
)

// Duration is read from the config as text.
type Duration time.Duration

func (d *Duration) UnmarshalText(b []byte) error {
	v, err := time.ParseDuration(string(b))
	*d = Duration(v)
	return err
}

// Level is written as its name.
type Level int

func (l Level) MarshalText() ([]byte, error) { return []byte(strconv.Itoa(int(l))), nil }

// Name is a string read through a check: JSON writes and reads a string.
type Name string

func (n *Name) UnmarshalText(b []byte) error {
	*n = Name(strings.ToLower(string(b)))
	return nil
}

// Window has both text methods.
type Window time.Duration

func (w Window) MarshalText() ([]byte, error) { return []byte(time.Duration(w).String()), nil }

func (w *Window) UnmarshalText(b []byte) error {
	v, err := time.ParseDuration(string(b))
	*w = Window(v)
	return err
}

// Span has its own JSON form, which JSON prefers to the text one.
type Span int64

func (s Span) MarshalJSON() ([]byte, error) { return []byte(strconv.FormatInt(int64(s), 10)), nil }

func (s *Span) UnmarshalJSON(b []byte) error {
	v, err := strconv.ParseInt(string(b), 10, 64)
	*s = Span(v)
	return err
}

func (s *Span) UnmarshalText(b []byte) error { return s.UnmarshalJSON(b) }

// Config is read from TOML only.
type Config struct {
	Interval Duration ` + tag(`toml:"interval"`) + `
}
`,
			"state/state.go": `package state

import (
	"encoding/json"
	"os"

	"example.com/rulestest/policy"
)

type Trace struct {
	Path     string            ` + tag(`json:"path"`) + `
	Lifetime policy.Duration   ` + tag(`json:"lifetime,omitempty"`) + `
	Prio     policy.Level      ` + tag(`json:"prio"`) + `
	Grace    *policy.Duration  ` + tag(`json:"grace,omitempty"`) + `
	Steps    []policy.Duration ` + tag(`json:"steps"`) + `
	Owner    policy.Name       ` + tag(`json:"owner"`) + `
	Window   policy.Window     ` + tag(`json:"window"`) + `
	Span     policy.Span       ` + tag(`json:"span"`) + `
	Memo     policy.Duration   ` + tag(`json:"-"`) + `
	local    policy.Duration
}

type State struct {
	Traces map[string]Trace ` + tag(`json:"traces"`) + `
}

func Load(path string) (*State, error) {
	s := &State{}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return s, json.Unmarshal(b, s)
}

func (s *State) Save(path string) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}
`,
			"api/request.go": `package api

import (
	"encoding/json"
	"io"

	"example.com/rulestest/policy"
)

// Request comes from a client as text and is never written back.
type Request struct {
	Timeout policy.Duration ` + tag(`json:"timeout"`) + `
}

func Decode(r io.Reader) (Request, error) {
	var req Request
	return req, json.NewDecoder(r).Decode(&req)
}
`,
		}))
}
