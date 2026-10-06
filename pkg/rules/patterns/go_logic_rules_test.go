package patterns

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// fileRuleLines runs a file rule on one file and returns the reported lines.
func fileRuleLines(t *testing.T, rule fileRule, path, source string) []int {
	t.Helper()
	var got []int
	for _, v := range rule.AnalyzeFile(rulestest.GoFile(t, path, source)) {
		got = append(got, v.Line)
	}
	return got
}

func analyzeFileRule(t *testing.T, rule fileRule, source string) []int {
	t.Helper()
	return fileRuleLines(t, rule, "app.go", source)
}

// wantLines returns the lines of the source marked with a // want comment.
func wantLines(source string) []int {
	var lines []int
	for i, line := range strings.Split(source, "\n") {
		if strings.Contains(line, "// want") {
			lines = append(lines, i+1)
		}
	}
	return lines
}

func assertWanted(t *testing.T, rule any, source string) {
	t.Helper()
	switch r := rule.(type) {
	case goProjectRule:
		assert.Equal(t, wantLines(source), appRuleLines(t, r, source))
	case fileRule:
		assert.Equal(t, wantLines(source), analyzeFileRule(t, r, source))
	default:
		t.Fatalf("%T is neither a project nor a file rule", rule)
	}
}

// Repro from a real project: a cached path point keyed by the unit was served
// for any destination and radius, and a cached route keyed by the number of
// bases was served for any target point.
func TestMemoIgnoresParameter(t *testing.T) {
	assertWanted(t, NewMemoIgnoresParameterRule(), `package app

type Point struct{ X, Y float64 }

type Unit struct {
	Tag uint64
	Pos Point
}

type Ctx struct {
	points map[uint64]Point
	ways   []Point
	waysAt int
	halls  int
}

func next(u *Unit, to Point, r float64) (Point, bool) { return to, r > 0 }

func (c *Ctx) PathWithin(u *Unit, to Point, r float64) (Point, bool) {
	if p, ok := c.points[u.Tag]; ok { // want
		return p, true
	}
	p, ok := next(u, to, r)
	if ok {
		c.points[u.Tag] = p
	}
	return p, ok
}

func (c *Ctx) Ways(to Point) []Point {
	if c.ways != nil && c.halls == c.waysAt { // want
		return c.ways
	}
	c.waysAt = c.halls
	from := Point{}
	if to.X > 0 {
		from = to
	}
	c.ways = []Point{from, to}
	return c.ways
}
`)
}

// The key or the guard carries every input the value is computed from.
func TestMemoIgnoresParameterAccepts(t *testing.T) {
	assertWanted(t, NewMemoIgnoresParameterRule(), `package app

type Point struct{ X, Y float64 }

type key struct {
	tag uint64
	to  Point
}

type Ctx struct {
	points map[key]Point
	air    map[uint64][2]Point
}

func next(tag uint64, to Point) Point { return to }

func (c *Ctx) Path(tag uint64, to Point) Point {
	if p, ok := c.points[key{tag, to}]; ok {
		return p
	}
	p := next(tag, to)
	c.points[key{tag, to}] = p
	return p
}

func (c *Ctx) Air(tag uint64, to Point) Point {
	if s, ok := c.air[tag]; ok && s[0] == to {
		return s[1]
	}
	p := next(tag, to)
	c.air[tag] = [2]Point{to, p}
	return p
}

type Game struct {
	Start Point
	Mem   *Memory
}

type Memory struct {
	ways   []Point
	waysAt int
	report []Point
}

// A loader and a value every caller reads from the same field do not vary
// the way a key does.
func (m *Memory) Ways(start Point, halls int) []Point {
	if m.ways != nil && halls == m.waysAt {
		return m.ways
	}
	m.waysAt = halls
	m.ways = []Point{start}
	return m.ways
}

func (m *Memory) Report(load func() []Point) []Point {
	if m.report != nil {
		return m.report
	}
	m.report = load()
	return m.report
}

func (g *Game) Step(halls int) []Point {
	return append(g.Mem.Ways(g.Start, halls), g.Mem.Report(func() []Point { return nil })...)
}

func Again(g *Game) []Point { return g.Mem.Ways(g.Start, 2) }

type walker struct{ memo map[int]int }

// A recursion budget bounds the walk, and a cache the caller passes in is
// scoped by the caller.
func (w *walker) size(v, depth int) int {
	if n, ok := w.memo[v]; ok {
		return n
	}
	if depth > 8 {
		return 0
	}
	n := w.size(v/2, depth+1) + 1
	w.memo[v] = n
	return n
}

func known(src string, name string, cache map[string]bool) bool {
	if k, ok := cache[name]; ok {
		return k
	}
	found := len(src) > len(name)
	cache[name] = found
	return found
}
`)
}

// Repro from a real project: a test checked every flag the source creates,
// but its pattern no longer matched how flags were created - zero matches,
// zero checks, a green test.
func TestAssertionsOnlyInScanLoop(t *testing.T) {
	violations := fileRuleLines(t, NewAssertionsOnlyInScanLoopRule(), "app_test.go", `package app

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestFlagsKnown(t *testing.T) {
	if len(known) == 0 {
		t.Fatal("empty table")
	}
	re := regexp.MustCompile(`+"`newFlag\\(\"([^\"]+)\"`"+`)
	for _, file := range []string{"a.go", "b.go"} {
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range re.FindAllStringSubmatch(string(src), -1) {
			if !known[m[1]] {
				t.Errorf("%s: flag %q unknown", file, m[1])
			}
		}
	}
}

func TestFlagsBothWays(t *testing.T) {
	re := regexp.MustCompile(`+"`newFlag\\(\"([^\"]+)\"`"+`)
	src, err := os.ReadFile("a.go")
	if err != nil {
		t.Fatal(err)
	}
	made := map[string]bool{}
	for _, m := range re.FindAllStringSubmatch(string(src), -1) {
		made[m[1]] = true
		if !known[m[1]] {
			t.Errorf("flag %q unknown", m[1])
		}
	}
	for name := range known {
		if !made[name] {
			t.Errorf("flag %q never made", name)
		}
	}
}

func TestFlagsCounted(t *testing.T) {
	re := regexp.MustCompile("x")
	matches := re.FindAllString("xx", -1)
	if len(matches) == 0 {
		t.Fatal("pattern found nothing")
	}
	for _, m := range matches {
		if m != "x" {
			t.Errorf("odd %q", m)
		}
	}
}

func TestNoBadLines(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(src), "\n") {
			if strings.Contains(line, "panic(") {
				t.Errorf("%s:%d: panic", f, i+1)
			}
		}
	}
}
`)
	assert.Equal(t, []int{21}, violations)
}

// Repro from a real project: the opponent's slot defaulted to 2 and was
// replaced only when the name was found, so an unknown name analysed the
// wrong player.
func TestNotFoundIndexDefaultedPreassigned(t *testing.T) {
	violations := analyzeFileRule(t, NewNotFoundIndexDefaultedRule(), `package app

import "slices"

func Slot(names []string, opp string) int64 {
	p := int64(2) // want
	if i := slices.Index(names, opp); i >= 0 {
		p = int64(i + 1)
	}
	return p
}

func Cut(s string, sep byte) string {
	end := len(s)
	for i := range s {
		if s[i] == sep {
			end = i
			break
		}
	}
	return s[:end]
}

func Section(lines []string, title string) int {
	line := 1
	if i := slices.Index(lines, title); i >= 0 {
		line = i + 1
	}
	return line
}
`)
	assert.Equal(t, []int{6}, violations)
}

// Repro from a real project: the game returned our player id, the code only
// logged it and went on to scan players 1 and 2 by literal - wrong when the
// game seated us second.
func TestReturnedIDReplacedByLiteral(t *testing.T) {
	assertWanted(t, NewReturnedIDReplacedByLiteralRule(), `package app

import (
	"errors"
	"log/slog"
)

func join() (uint32, error) { return 1, nil }

func scan(out string, player int32, title string) error { return errors.New(title) }

func Run(out string) error {
	playerID, err := join()
	if err != nil {
		return err
	}
	slog.Info("joined", "player_id", playerID)
	if err := scan(out, 2, "them"); err != nil { // want
		return err
	}
	return scan(out, 1, "us") // want
}

func Use(out string) error {
	playerID, err := join()
	if err != nil {
		return err
	}
	return scan(out, int32(playerID), "us")
}
`)
}

// Repro from a real project: a 6x6 template shifted a building one cell left
// with pos-1, which in the first column wrote into the previous row.
func TestFlatGridNeighborCrossesRow(t *testing.T) {
	assertWanted(t, NewFlatGridNeighborCrossesRowRule(), `package app

const side = 6

func Fix(dst []int) {
	for pos, cell := range dst {
		if cell == 3 {
			dst[pos-1] = cell // want
			dst[pos] = 9
		}
	}
}

func Point(pos int) (int, int) { return pos % side, pos / side }

func Safe(dst []int) {
	for pos, cell := range dst {
		if cell != 3 || pos%side == 0 {
			continue
		}
		dst[pos-1] = cell
	}
}

func Bites(hp []int) []int {
	var out []int
	for pos, h := range hp {
		if pos > 0 {
			out = append(out, hp[pos-1]-h)
		}
	}
	return out
}
`)
}

// Repro from a real project: images of a series were named by the second of
// their first frame, and two images within one second overwrote each other.
func TestFileNameUniqueOnlyByRoundedTime(t *testing.T) {
	assertWanted(t, NewFileNameUniqueOnlyByRoundedTimeRule(), `package app

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func Write(dir, name string, loops []uint32, data [][]byte) error {
	for i, l := range loops {
		out := filepath.Join(dir, fmt.Sprintf("%s-%03.0fs.png", name, float64(l)/24)) // want
		if err := os.WriteFile(out, data[i], 0o644); err != nil {
			return err
		}
	}
	return nil
}

func Stamp(dir string, data [][]byte) error {
	for _, d := range data {
		out := filepath.Join(dir, time.Now().Format("20060102-150405")+".json") // want
		if err := os.WriteFile(out, d, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func Exact(dir, name string, loops []uint32, data [][]byte) error {
	for i, l := range loops {
		out := filepath.Join(dir, fmt.Sprintf("%s-%03.0fs-loop%010d.png", name, float64(l)/24, l))
		if err := os.WriteFile(out, data[i], 0o644); err != nil {
			return err
		}
	}
	return nil
}
`)
}

// Repro from a real project: the main path filled an empty -profile from the
// binary name, the -info path passed the raw flag and failed on "".
func TestDefaultAppliedOnOnePathOnly(t *testing.T) {
	assertWanted(t, NewDefaultAppliedOnOnePathOnlyRule(), `package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

func newProfile(name string) (string, error) {
	if name == "" {
		return "", errors.New("no profile")
	}
	return name, nil
}

func main() {
	profileName := flag.String("profile", "", "")
	info := flag.Bool("info", false, "")
	flag.Parse()
	if *info {
		if _, err := newProfile(*profileName); err != nil { // want
			os.Exit(1)
		}
		return
	}
	name := *profileName
	if name == "" {
		name = filepath.Base(os.Args[0])
	}
	if _, err := newProfile(name); err != nil {
		os.Exit(1)
	}
}

func show(title string) {
	if *verbose {
		fmt.Println(title)
		return
	}
	t := title
	if t == "" {
		t = "-"
	}
	fmt.Println(t)
}

var verbose = flag.Bool("v", false, "")
`)
}

// Repro from a real project: two order rules carried the same id "B4", and
// the per-rule summary added unrelated rules together.
func TestConstFamilyDuplicateValue(t *testing.T) {
	assertWanted(t, NewConstFamilyDuplicateValueRule(), `package app

const (
	RuleScoutHome  = "B4"
	RuleArmyGather  = "A3"
	RuleFlyer       = "C2"
	RuleWatcher     = "C7"
	RuleRushStage = "B4" // want
)

const (
	DefaultHost   = "localhost"
	DefaultDBHost = "localhost"
)

const (
	StatusActive  = "active"
	StateActive   = "active"
	StatusDeleted = "deleted"
)

type OrderStatus string

type OrderLineStatus string

// Two enums of one prefix share values on purpose.
const (
	OrderStatusPending   OrderStatus   = "pending"
	OrderStatusFailed    OrderStatus   = "failed"
	OrderStatusDone      OrderStatus   = "done"
	OrderLineStatusPending OrderLineStatus = "pending"
	OrderLineStatusFailed  OrderLineStatus = "failed"
)

// Rule numbers named by what they do share no prefix: the block is the
// family.
const (
	Gather  = "A1"
	Attack  = "A2"
	Retreat = "A3"
	Defend  = "A4"
	Probe   = "A2" // want
)
`)
}

// Repro from a real project: three diagnostics shared one throttle map, and
// the first line about money silenced the placement diagnostic for a window.
func TestThrottleStateSharedByMessages(t *testing.T) {
	assertWanted(t, NewThrottleStateSharedByMessagesRule(), `package app

import "log/slog"

const every = 22

type Ctx struct {
	loop   uint32
	last   map[uint32]uint32
	denied map[uint32]uint32
}

func (c *Ctx) noSupplier(id uint32) {
	if c.loop-c.last[id] < every { // want
		return
	}
	c.last[id] = c.loop
	slog.Info("no supplier", "id", id)
}

func (c *Ctx) orderRejected(id uint32) {
	if c.loop-c.last[id] < every { // want
		return
	}
	c.last[id] = c.loop
	slog.Info("order rejected", "id", id)
}

func (c *Ctx) own(id uint32) {
	if c.loop-c.denied[id] < every {
		return
	}
	c.denied[id] = c.loop
	slog.Info("own throttle", "id", id)
}
`)
}

// Repro from a real project: comparing two digests over a fixed list of
// fields took a field missing from the old digest for an empty value and
// reported a difference.
func TestMapCompareMissingKeyAsZero(t *testing.T) {
	assertWanted(t, NewMapCompareMissingKeyAsZeroRule(), `package app

import "fmt"

type digest struct{ Fields map[string]string }

var fields = []string{"result", "time"}

func Compare(want, got digest) []string {
	var out []string
	keys := append(append([]string{}, fields...), "flags")
	for _, k := range keys {
		if want.Fields[k] != got.Fields[k] { // want
			out = append(out, fmt.Sprintf("%s: %q -> %q", k, want.Fields[k], got.Fields[k]))
		}
	}
	return out
}

func Checked(want, got digest) []string {
	var out []string
	for _, k := range fields {
		if _, known := want.Fields[k]; !known {
			continue
		}
		if want.Fields[k] != got.Fields[k] {
			out = append(out, k)
		}
	}
	return out
}

func OwnKeys(want, got digest) []string {
	var out []string
	for k := range want.Fields {
		if want.Fields[k] != got.Fields[k] {
			out = append(out, k)
		}
	}
	return out
}
`)
}

// Repro from a real project: a second client was started with options
// built in place, while the main one used a constructor that also set the
// visibility options - the two clients saw different data.
func TestLiteralBypassesConstructor(t *testing.T) {
	assertWanted(t, NewLiteralBypassesConstructorRule(), `package app

type Options struct {
	Raw     bool
	Score   bool
	Cloaked bool
	Burrow  bool
}

func DefaultOptions() *Options {
	return &Options{Raw: true, Score: true, Cloaked: true, Burrow: true}
}

type Request struct{ Opts *Options }

func Second() Request {
	return Request{Opts: &Options{Raw: true, Score: true}} // want
}

func Custom() Request {
	return Request{Opts: &Options{Raw: true, Score: false, Cloaked: true, Burrow: false}}
}

type Schedule struct{ Hour, Minute int }

// Two constructors of one type are two configurations.
func NightlySchedule() Schedule { return Schedule{Hour: 2, Minute: 0} }

func MorningSchedule() Schedule { return Schedule{Hour: 7, Minute: 30} }

func Hourly() Schedule { return Schedule{Minute: 40} }

type Unit struct {
	Name    string
	Count   int
	Pending int
}

// A function returning a literal is a build step, not the type's constructor.
func workerStep() Unit { return Unit{Name: "worker", Count: 30, Pending: 2} }

func Steps() []Unit { return []Unit{workerStep(), {Name: "depot", Count: 1}} }
`)
}
