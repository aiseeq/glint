package gorules

import (
	"testing"

	"github.com/aiseeq/glint/pkg/rules/patterns/shellrules"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
)

// Number flags copied into an options value and checked by a method of that
// value (value or pointer receiver) are checked: the receiver is the value.
func TestCLINumberFlagCheckedByMethodOfOptions(t *testing.T) {
	assert.Empty(t, rulestest.GoProjectRuleLines(t, shellrules.NewCLINumberFlagUncheckedRule(), "app.go", `package main

import (
	"errors"
	"flag"
	"time"
)

type opts struct {
	cols  int
	every time.Duration
}

func (o opts) validate() error {
	if o.cols <= 0 {
		return errors.New("cols")
	}
	if o.every <= 0 {
		return errors.New("every")
	}
	return nil
}

type sheet struct{ cols int }

func (s *sheet) check() error {
	if s.cols <= 0 {
		return errors.New("cols")
	}
	return nil
}

func draw(o opts) error {
	if err := o.validate(); err != nil {
		return err
	}
	_ = make([]int, 0)[:o.cols]
	t := time.NewTicker(o.every)
	t.Stop()
	return nil
}

func main() {
	cols := flag.Int("cols", 4, "")
	every := flag.Duration("every", time.Second, "")
	n := flag.Int("n", 2, "")
	flag.Parse()
	o := opts{cols: *cols, every: *every}
	if err := draw(o); err != nil {
		return
	}
	s := &sheet{cols: *n}
	if err := s.check(); err != nil {
		return
	}
	_ = make([]int, 0)[:s.cols]
}
`))
}

// Without the method's check the same flow keeps its findings.
func TestCLINumberFlagOptionsWithoutCheckKeepFinding(t *testing.T) {
	assert.Equal(t, []int{17, 18}, rulestest.GoProjectRuleLines(t, shellrules.NewCLINumberFlagUncheckedRule(), "app.go", `package main

import (
	"flag"
	"time"
)

type opts struct {
	cols  int
	every time.Duration
}

func (o opts) describe() string { return "opts" }

func draw(o opts) {
	_ = o.describe()
	_ = make([]int, 0)[:o.cols]
	t := time.NewTicker(o.every)
	t.Stop()
}

func main() {
	cols := flag.Int("cols", 4, "")
	every := flag.Duration("every", time.Second, "")
	flag.Parse()
	draw(opts{cols: *cols, every: *every})
}
`))
}
