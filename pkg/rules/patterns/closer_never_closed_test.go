package patterns

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

func closerNeverClosedFindings(t *testing.T, files map[string]string) []string {
	t.Helper()
	violations, err := NewCloserNeverClosedRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	var out []string
	for _, v := range violations {
		out = append(out, fmt.Sprintf("%s:%d", v.File, v.Line))
	}
	sort.Strings(out)
	return out
}

const closerStoreSource = `package store

import "errors"

type Conn struct{}

func (c *Conn) Close() error { return nil }
func (c *Conn) Ping() error  { return nil }

type Pool struct{ conn *Conn }

type Ticker struct{}

func (Ticker) Close(force bool) {}

func Dial(addr string) (*Conn, error) {
	if addr == "" {
		return nil, errors.New("empty address")
	}
	return &Conn{}, nil
}

func NewTicker() Ticker { return Ticker{} }

func Leak(addr string) error {
	conn, err := Dial(addr)
	if err != nil {
		return err
	}
	return conn.Ping()
}

func Closed(addr string) error {
	conn, err := Dial(addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	return conn.Ping()
}

func Returned(addr string) (*Conn, error) {
	conn, err := Dial(addr)
	return conn, err
}

func Stored(addr string) (*Pool, error) {
	conn, err := Dial(addr)
	if err != nil {
		return nil, err
	}
	return &Pool{conn: conn}, nil
}

func Captured(addr string, run func(func())) {
	conn, _ := Dial(addr)
	run(func() { _ = conn.Ping() })
}

func PassedOn(addr string) {
	conn, _ := Dial(addr)
	keep(conn)
}

func keep(c *Conn) { _ = c }

func Printed(addr string) {
	conn, _ := Dial(addr)
	show(conn)
}

func show(v any) { _ = v }

func NilChecked(addr string) bool {
	conn, _ := Dial(addr)
	return conn != nil
}

func CloseTakesArgs() {
	ticker := NewTicker()
	_ = ticker
}
`

// The value is not the caller's to close: a shared instance, one the
// constructor already hands to the test's cleanup, one a later Wait closes,
// a reflect.Value whose Close closes a channel, or a field of it closed
// through another variable.
func TestCloserNeverClosedNotTheCallersToClose(t *testing.T) {
	found := closerNeverClosedFindings(t, map[string]string{
		"store/store.go": `package store

import (
	"os/exec"
	"reflect"
	"sync"
	"testing"
)

type Conn struct{}

func (c *Conn) Close() error { return nil }
func (c *Conn) Ping() error  { return nil }

type Wrapper struct{ Conn *Conn }

func (w *Wrapper) Close() error { return nil }

var (
	shared     *Conn
	sharedOnce sync.Once
)

func Shared() *Conn {
	sharedOnce.Do(func() { shared = &Conn{} })
	return shared
}

type Manager struct{ conn *Conn }

func (m *Manager) conn0() *Conn {
	if m.conn != nil {
		return m.conn
	}
	conn := &Conn{}
	m.conn = conn
	return conn
}

func Connect(t testing.TB) *Conn {
	conn := &Conn{}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func OpenWrapper() *Wrapper { return &Wrapper{Conn: &Conn{}} }

func UseShared() error { return Shared().Ping() }

func UseShared2() error {
	conn := Shared()
	return conn.Ping()
}

func (m *Manager) Use() error {
	conn := m.conn0()
	return conn.Ping()
}

func Pipe(cmd *exec.Cmd) error {
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if stdout == nil {
		return nil
	}
	return cmd.Wait()
}

func Reflect(v any) bool {
	value := reflect.ValueOf(v)
	return value.IsValid()
}

func Field() error {
	wrapper := OpenWrapper()
	conn := wrapper.Conn
	defer conn.Close()
	return conn.Ping()
}
`,
		"store/store_test.go": `package store

import "testing"

func TestConnect(t *testing.T) {
	conn := Connect(t)
	_ = conn.Ping()
}
`,
		"cmd/tool/main.go": `package main

import "example.com/rulestest/store"

func main() {
	wrapper := store.OpenWrapper()
	_ = wrapper.Conn.Ping()
}
`,
	})
	assert.Empty(t, found)
}

// The body of a function outside the project is not visible: its result is
// taken as a fresh resource only when the name says it creates one
// (os.Open, net.Dial); a getter such as io.NopCloser may hand out a value the
// caller must not close. A project function is judged by its body, whatever
// its name.
func TestCloserNeverClosedExternalCallee(t *testing.T) {
	found := closerNeverClosedFindings(t, map[string]string{
		"store/store.go": `package store

import (
	"io"
	"net"
	"os"
	"strings"
)

type Conn struct{}

func (c *Conn) Close() error { return nil }
func (c *Conn) Ping() error  { return nil }

func fresh() *Conn { return &Conn{} }

func OpenFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	_, err = file.Stat()
	return err
}

func DialPeer(addr string) error {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}
	return conn.SetDeadline(zeroTime)
}

var zeroTime = time0()

func Wrap(text string) bool {
	body := io.NopCloser(strings.NewReader(text))
	return body != nil
}

func Project() error {
	conn := fresh()
	return conn.Ping()
}
`,
		"store/time.go": `package store

import "time"

func time0() time.Time { return time.Time{} }
`,
	})
	assert.Equal(t, []string{"store/store.go:18", "store/store.go:27", "store/store.go:42"}, found)
}

// A client built from a constructor and dropped at the end of the function
// keeps its connections open: nothing closes it, and nothing it was handed
// to can.
func TestCloserNeverClosed(t *testing.T) {
	found := closerNeverClosedFindings(t, map[string]string{
		"store/store.go": closerStoreSource,
		"store/store_test.go": `package store

import "testing"

func TestDial(t *testing.T) {
	conn, err := Dial("db")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Ping()
}
`,
		"store/external_test.go": `package store_test

import (
	"testing"

	"example.com/rulestest/store"
)

func TestLeak(t *testing.T) {
	conn, err := store.Dial("db")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Ping()
}

func TestClosed(t *testing.T) {
	conn, _ := store.Dial("db")
	t.Cleanup(func() { conn.Close() })
}

func TestReturnedFromHelper(t *testing.T) {
	ticker := store.NewTicker()
	_ = ticker
}
`,
	})
	assert.Equal(t, []string{
		"store/external_test.go:10",
		"store/store.go:26",
		"store/store.go:68",
		"store/store.go:75",
		"store/store_test.go:6",
	}, found)
}

// A run over some packages of a module types the package of a shared getter
// without analyzing its files: the getter is still judged by its body, so a
// shared instance is not taken for a fresh one the caller has to close.
func TestCloserNeverClosedGetterBodyNotLoaded(t *testing.T) {
	root, contexts := rulestest.Module(t, map[string]string{
		"analytics/analytics.go": `package analytics

type Service struct{}

func (s *Service) Close() {}

func (s *Service) Track(event string) {}

var global *Service

func Get() *Service { return global }

func OpenShared() *Service { return global }

func NewService() *Service { return &Service{} }
`,
		"deposits/deposits.go": `package deposits

import "example.com/rulestest/analytics"

func Record() {
	amp := analytics.Get()
	amp.Track("deposit")
}

func Leak() {
	svc := analytics.NewService()
	svc.Track("deposit")
}

func Shared() {
	svc := analytics.OpenShared()
	svc.Track("deposit")
}
`,
	})
	var analyzed []*core.FileContext
	for _, file := range contexts {
		if strings.HasSuffix(file.Path, "deposits.go") {
			analyzed = append(analyzed, file)
		}
	}
	project, err := core.LoadGoProject(root, analyzed, core.GoProjectOptions{})
	require.NoError(t, err)
	violations, err := NewCloserNeverClosedRule().AnalyzeGoProject(project)
	require.NoError(t, err)
	assert.Equal(t, []string{"deposits/deposits.go:11"}, foundLines(violations))
}
