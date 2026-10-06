package patterns

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// appRuleLines runs a project rule on one file app.go and returns the lines
// it reports, in order.
func appRuleLines(t *testing.T, rule goProjectRule, source string) []int {
	t.Helper()
	violations, err := rule.AnalyzeGoProject(rulestest.Project(t, map[string]string{"app.go": source}))
	require.NoError(t, err)
	var got []int
	for _, v := range violations {
		got = append(got, v.Line)
	}
	return got
}

func appRuleMessages(t *testing.T, rule goProjectRule, source string) []string {
	t.Helper()
	violations, err := rule.AnalyzeGoProject(rulestest.Project(t, map[string]string{"app.go": source}))
	require.NoError(t, err)
	var got []string
	for _, v := range violations {
		got = append(got, fmt.Sprintf("%d: %s", v.Line, v.Message))
	}
	return got
}

// Repro from a real project: a PNG was encoded into a created file closed by
// defer; the error of the final flush on Close was lost and the function
// reported success for a truncated image.
func TestDeferredCloseOfWrittenFile(t *testing.T) {
	assert.Equal(t, []int{15, 24}, appRuleLines(t, NewDeferredCloseOfWrittenFileRule(), `package app

import (
	"fmt"
	"image"
	"image/png"
	"os"
)

func Save(out string, img image.Image) error {
	f, err := os.Create(out)
	if err != nil {
		return fmt.Errorf("create: %w", err)
	}
	defer f.Close()
	if err := png.Encode(f, img); err != nil {
		return fmt.Errorf("png: %w", err)
	}
	return nil
}

func Append(path string, line []byte) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644)
	defer f.Close()
	if err != nil {
		return err
	}
	_, err = f.Write(line)
	return err
}
`))
}

// A file opened for reading has nothing to flush; a written file whose Close
// result is returned, or that is closed and checked at the end besides the
// deferred close, reports the failure.
func TestDeferredCloseOfWrittenFileAccepts(t *testing.T) {
	assert.Empty(t, appRuleLines(t, NewDeferredCloseOfWrittenFileRule(), `package app

import (
	"io"
	"os"
)

func Read(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

func Write(path string, data []byte) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return err
	}
	return f.Close()
}

func WriteChecked(path string, data []byte) (err error) {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()
	_, err = f.Write(data)
	return err
}

func Sync(path string, data []byte) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return err
	}
	return f.Sync()
}
`))
}

// Repro from a real project: the candidates left after a filter could be
// none, and rand.Intn(0) panicked at the start of a game.
func TestRandIndexOfFilteredSlice(t *testing.T) {
	assert.Equal(t, []int{16}, appRuleLines(t, NewRandIndexOfFilteredSliceRule(), `package app

import "math/rand"

func Pick(pool []string, banned string, rnd *rand.Rand) string {
	var best []string
	for _, t := range pool {
		if t == banned {
			continue
		}
		best = append(best, t)
	}
	if rnd.Intn(2) == 0 {
		return pool[0]
	}
	return best[rnd.Intn(len(best))]
}
`))
}

// A length check before the draw, or a slice that is never filtered, leaves
// nothing to report.
func TestRandIndexOfFilteredSliceAccepts(t *testing.T) {
	assert.Empty(t, appRuleLines(t, NewRandIndexOfFilteredSliceRule(), `package app

import "math/rand/v2"

func Pick(pool []string, banned string) string {
	var best []string
	for _, t := range pool {
		if t != banned {
			best = append(best, t)
		}
	}
	if len(best) == 0 {
		return ""
	}
	return best[rand.IntN(len(best))]
}

func All(pool []string) string {
	var all []string
	for _, t := range pool {
		all = append(all, t)
	}
	all = append(all, "default")
	return all[rand.IntN(len(all))]
}
`))
}

// Repro from a real project: a seal file was written read-only, and the next
// run could not write it again.
func TestWriteFileWithoutOwnerWrite(t *testing.T) {
	assert.Equal(t, []int{6, 10}, appRuleLines(t, NewWriteFileWithoutOwnerWriteRule(), `package app

import "os"

func Seal(path string, data []byte) error {
	return os.WriteFile(path, data, 0o444)
}

func Lock(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0400)
}
`))
}

// Removing the old copy first lets the write create a fresh file; a
// writable mode needs nothing.
func TestWriteFileWithoutOwnerWriteAccepts(t *testing.T) {
	assert.Empty(t, appRuleLines(t, NewWriteFileWithoutOwnerWriteRule(), `package app

import (
	"errors"
	"io/fs"
	"os"
)

func Seal(path string, data []byte) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return os.WriteFile(path, data, 0o444)
}

func Plain(path string, data []byte) error {
	return os.WriteFile(path, data, 0o644)
}
`))
}

// Repro from a real project: a session id read from decoded JSON with
// fmt.Sprint became the text "<nil>" when the key was missing, and that text
// was passed on as the id of a session.
func TestSprintOfAnyMapEntry(t *testing.T) {
	assert.Equal(t, []int{14, 15}, appRuleLines(t, NewSprintOfAnyMapEntryRule(), `package app

import (
	"encoding/json"
	"fmt"
	"os"
)

func queue(session string) error { return nil }

func Hook() error {
	var ev map[string]any
	_ = json.NewDecoder(os.Stdin).Decode(&ev)
	err := queue(fmt.Sprint(ev["session_id"]))
	path := fmt.Sprintf("%v", ev["transcript_path"])
	if fmt.Sprint(ev["stop_hook_active"]) != "true" {
		return err
	}
	_ = path
	return err
}
`))
}

// A comma-ok check first, or a typed map, keeps "<nil>" out.
func TestSprintOfAnyMapEntryAccepts(t *testing.T) {
	assert.Empty(t, appRuleLines(t, NewSprintOfAnyMapEntryRule(), `package app

import "fmt"

func use(string) {}

func Hook(ev map[string]any, names map[string]string) {
	if v, ok := ev["session_id"]; ok {
		use(fmt.Sprint(v))
	}
	use(fmt.Sprint(names["x"]))
}
`))
}

// Repro from a real project: the main work of a measurement failed and the
// error went to an Info line, while the function went on to report the run
// as a success.
func TestErrorLoggedAtInfo(t *testing.T) {
	assert.Equal(t, []int{14}, appRuleLines(t, NewErrorLoggedAtInfoRule(), `package app

import (
	"errors"
	"log/slog"
)

func scan(side int) error { return errors.New("broken") }

func Run(ok bool) error {
	if !ok {
		return errors.New("not ready")
	}
	if err := scan(2); err != nil {
		slog.Info("enemy side", "err", err)
	}
	slog.Info("match done")
	return nil
}
`))
}

// A warning or an error level is visible; a debug line marks an optional step
// on purpose; a function without an error result has no one to tell.
func TestErrorLoggedAtInfoAccepts(t *testing.T) {
	assert.Empty(t, appRuleLines(t, NewErrorLoggedAtInfoRule(), `package app

import (
	"errors"
	"log/slog"
)

func scan(side int) error { return errors.New("broken") }

func Run() error {
	if err := scan(2); err != nil {
		slog.Warn("enemy side", "err", err)
	}
	if err := scan(1); err != nil {
		slog.Debug("optional", "err", err)
	}
	return nil
}

func Loop() {
	if err := scan(2); err != nil {
		slog.Info("enemy side", "err", err)
	}
}
`))
}

// Repro from a real project: -parallel 0 started no worker, the jobs waited in
// the buffer and the run reported an empty successful sample; -progress 0
// panicked in time.NewTicker; -cols 0 sliced with a negative bound.
func TestCLINumberFlagUnchecked(t *testing.T) {
	assert.Equal(t, []string{
		`23: Flag -parallel reaches a worker loop bound with no check that it is positive — a zero or negative value from the command line makes the program fail or quietly do nothing`,
		`26: Flag -progress reaches time.NewTicker with no check that it is positive — a zero or negative value from the command line makes the program fail or quietly do nothing`,
		`32: Flag -cols reaches a slice bound with no check that it is positive — a zero or negative value from the command line makes the program fail or quietly do nothing`,
	}, appRuleMessages(t, NewCLINumberFlagUncheckedRule(), `package main

import (
	"flag"
	"time"
)

type config struct {
	parallel int
	repeat   int
}

type opts struct{ cols int }

func main() {
	var cfg config
	flag.IntVar(&cfg.parallel, "parallel", 1, "workers")
	flag.IntVar(&cfg.repeat, "repeat", 1, "runs")
	progress := flag.Duration("progress", time.Second, "report every")
	cols := flag.Int("cols", 4, "columns")
	flag.Parse()
	jobs := make(chan int, 16)
	for i := 0; i < cfg.parallel; i++ {
		go func() { <-jobs }()
	}
	tick := time.NewTicker(*progress)
	defer tick.Stop()
	film(opts{cols: *cols - 1}, []int{1, 2, 3})
}

func film(o opts, frames []int) []int {
	return frames[:o.cols]
}
`))
}

// A flag compared with a constant after parsing is checked; a flag used only
// for text needs no check.
func TestCLINumberFlagUncheckedAccepts(t *testing.T) {
	assert.Empty(t, appRuleLines(t, NewCLINumberFlagUncheckedRule(), `package main

import (
	"flag"
	"fmt"
	"os"
	"time"
)

type config struct{ parallel int }

func main() {
	var cfg config
	flag.IntVar(&cfg.parallel, "parallel", 1, "workers")
	every := flag.Duration("every", time.Second, "")
	label := flag.Int("label", 1, "")
	flag.Parse()
	if cfg.parallel <= 0 {
		fmt.Println("-parallel must be > 0")
		os.Exit(2)
	}
	if *every < time.Millisecond {
		os.Exit(2)
	}
	for i := 0; i < cfg.parallel; i++ {
		go func() {}()
	}
	t := time.NewTicker(*every)
	t.Stop()
	fmt.Println(*label)
}
`))
}

// Repro from a real project: a difficulty typed wrong on the command line was
// looked up in a map without ok, and the zero value silently turned the
// computer opponent into a second bot slot.
func TestCLIFlagMapLookupWithoutOK(t *testing.T) {
	assert.Equal(t, []int{15}, appRuleLines(t, NewCLIFlagMapLookupWithoutOKRule(), `package main

import (
	"flag"
	"fmt"
)

type Difficulty int

var Difficulties = map[string]Difficulty{"easy": 1, "hard": 2}

func main() {
	diff := flag.String("diff", "hard", "")
	flag.Parse()
	fmt.Println(Difficulties[*diff])
}
`))
}

func TestCLIFlagMapLookupWithoutOKAccepts(t *testing.T) {
	assert.Empty(t, appRuleLines(t, NewCLIFlagMapLookupWithoutOKRule(), `package main

import (
	"flag"
	"fmt"
	"os"
)

var Difficulties = map[string]int{"easy": 1, "hard": 2}
var known = map[string]bool{"a": true}

func main() {
	diff := flag.String("diff", "hard", "")
	name := flag.String("name", "a", "")
	flag.Parse()
	d, ok := Difficulties[*diff]
	if !ok {
		os.Exit(2)
	}
	if known[*name] {
		fmt.Println(d)
	}
}
`))
}

// Repro from a real project: a batch of orders was sent and the per-order
// results were dropped; orders the server refused were taken as given.
func TestBatchStatusResultsDropped(t *testing.T) {
	assert.Equal(t, []int{21}, appRuleLines(t, NewBatchStatusResultsDroppedRule(), `package app

import "context"

type ActionResult int32

const (
	ActionResult_Success     ActionResult = 1
	ActionResult_NotSupported ActionResult = 2
	ActionResult_Error       ActionResult = 3
)

type Action struct{}

type Client struct{}

func (c *Client) Act(ctx context.Context, acts []*Action) ([]ActionResult, error) { return nil, nil }

func Send(ctx context.Context, c *Client, acts []*Action) error {
	_ = ctx
	if _, err := c.Act(ctx, acts); err != nil {
		return err
	}
	return nil
}
`))
}

// Statuses that are read, or a dropped slice of plain values, are fine.
func TestBatchStatusResultsDroppedAccepts(t *testing.T) {
	assert.Empty(t, appRuleLines(t, NewBatchStatusResultsDroppedRule(), `package app

type Status int

const (
	StatusOK Status = iota
	StatusFailed
)

func act(ids []int) ([]Status, error) { return nil, nil }
func ids() ([]int, error)             { return nil, nil }

func Send(list []int) (int, error) {
	res, err := act(list)
	if err != nil {
		return 0, err
	}
	failed := 0
	for _, s := range res {
		if s != StatusOK {
			failed++
		}
	}
	_, err = ids()
	return failed, err
}
`))
}

// False positives from a real project: the flag was validated by a comma-ok
// lookup of the same map elsewhere, or the looked-up value is tested for nil
// right away.
func TestCLIFlagMapLookupValidatedElsewhere(t *testing.T) {
	assert.Empty(t, appRuleLines(t, NewCLIFlagMapLookupWithoutOKRule(), `package main

import (
	"flag"
	"fmt"
	"os"
)

type ctl struct{ name string }

var ctls = map[string]*ctl{"a": {"a"}}
var scenes = map[string]*ctl{"x": {"x"}}

type config struct{ ctl, scene string }

func parse() config {
	var cfg config
	flag.StringVar(&cfg.ctl, "ctl", "a", "")
	flag.StringVar(&cfg.scene, "scene", "x", "")
	flag.Parse()
	if _, ok := ctls[cfg.ctl]; !ok {
		os.Exit(2)
	}
	return cfg
}

func main() {
	cfg := parse()
	fmt.Println(ctls[cfg.ctl].name)
	if layout := scenes[cfg.scene]; layout == nil {
		os.Exit(2)
	}
}
`))
}

// A failed teardown after the work is done - leaving a game, closing a
// connection - is logged at Info on purpose.
func TestErrorLoggedAtInfoAcceptsTeardown(t *testing.T) {
	assert.Empty(t, appRuleLines(t, NewErrorLoggedAtInfoRule(), `package app

import (
	"errors"
	"log/slog"
)

type client struct{}

func (c *client) LeaveGame() error { return nil }
func (c *client) Play() error      { return errors.New("lost") }

func Run(c *client) error {
	err := c.Play()
	if lerr := c.LeaveGame(); lerr != nil {
		slog.Info("leave after the end", "err", lerr)
	}
	return err
}
`))
}

// Repro from a real project: a download wrote dst+".part" and renamed it onto
// dst, and a history store wrote path+".tmp" the same way. Two processes
// writing one destination truncated each other's temp file, and one of them
// renamed a half-written file into place.
func TestFixedTempNameRenamed(t *testing.T) {
	assertWanted(t, NewFixedTempNameRenamedRule(), `package app

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

func Download(dst string, body io.Reader) error {
	tmp := dst + ".part" // want
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, body); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

func SaveTable(dir, name string, data []byte) error {
	tmp := filepath.Join(dir, name+".tmp") // want
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, name))
}

func SaveInline(path string, data []byte) error {
	if err := os.WriteFile(path+".tmp", data, 0o600); err != nil { // want
		return err
	}
	return os.Rename(path+".tmp", path)
}

func SaveUnique(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

func SavePid(path string, data []byte) error {
	tmp := fmt.Sprintf("%s.%d.tmp", path, os.Getpid())
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

var mu sync.Mutex

func SaveLocked(path string, data []byte) error {
	mu.Lock()
	defer mu.Unlock()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func Backup(path string) error {
	return os.Rename(path, path+".bak")
}
`)
}

// Repro from a real project: a program loaded its result log when a run
// started and wrote the loaded list plus its own record back when it ended;
// two runs at once kept only the later writer's record.
func TestSnapshotAppendedAndRewritten(t *testing.T) {
	assertWanted(t, NewSnapshotAppendedAndRewrittenRule(), `package app

import (
	"encoding/json"
	"os"
	"syscall"
)

type Record struct{ Build, Result string }

type Picker struct {
	path string
	past []Record
}

func (s *Picker) load() ([]Record, error) {
	raw, err := os.ReadFile(s.path)
	if err != nil {
		return nil, err
	}
	var past []Record
	if err := json.Unmarshal(raw, &past); err != nil {
		return nil, err
	}
	return past, nil
}

func (s *Picker) save(past []Record) error {
	raw, err := json.Marshal(past)
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, raw, 0o644)
}

func (s *Picker) Begin() error {
	past, err := s.load()
	if err != nil {
		return err
	}
	s.past = past
	return nil
}

func (s *Picker) End(rec Record) error {
	return s.save(append(s.past, rec)) // want
}

type ResultLog struct {
	Results []Record
}

func ReadLog(path string) (*ResultLog, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var h ResultLog
	if err := json.Unmarshal(raw, &h); err != nil {
		return nil, err
	}
	return &h, nil
}

func (h *ResultLog) Save(path string) error {
	raw, err := json.Marshal(h)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path+".tmp", raw, 0o644); err != nil {
		return err
	}
	return os.Rename(path+".tmp", path)
}

func AddResult(past *ResultLog, path string, rec Record) error {
	past.Results = append(past.Results, rec)
	return past.Save(path) // want
}

// AppendResult re-reads the file under a lock: the record of another process
// written since the start is kept.
func AppendResult(path string, rec Record) error {
	f, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	h, err := ReadLog(path)
	if err != nil {
		return err
	}
	h.Results = append(h.Results, rec)
	return h.Save(path)
}

func appendLine(path string, line []byte) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(line); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func (s *Picker) Log(line []byte) error {
	return appendLine(s.path+".log", append(line, '\n'))
}
`)
}
