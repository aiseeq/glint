package duplication

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestDuplicateFuncOfLibraryInlineShape: the same set of library fields is not
// enough — the fragment must also take the method's shape: its condition and
// its arithmetic. Two fields summed with += next to a method that picks one of
// them under a condition is an idiom, not a copy.
func TestDuplicateFuncOfLibraryInlineShape(t *testing.T) {
	ctx := duplicateLibraryTestProject(t, "github.com/projectq/kit", "github.com/projectq/app", inlineShapeApp, map[string]string{"conf/conf.go": inlineShapeLibrary}, true, "")
	violations, err := NewDuplicateFuncOfLibraryRule().AnalyzeGoProject(ctx)
	require.NoError(t, err)
	found := map[int]string{}
	for _, v := range violations {
		found[v.Line] = v.Message
	}
	require.Len(t, found, 3, "%v", found)
	require.Contains(t, found[59], "EffectiveTimeout", "N7 copies the method's flow into a")
	require.Contains(t, found[72], "EffectiveTimeout", "Run: the fragment starts at its var declaration")
	require.Contains(t, found[87], "Span", "Layout copies Window.Span")
}

const inlineShapeLibrary = `// Package conf holds client settings.
package conf

// Client is a client configuration.
type Client struct {
	Timeout  int
	Fallback int
	Retries  int
	Name     string
}

// Window is a range with a minimal step.
type Window struct {
	Min  int
	Max  int
	Step int
}

// EffectiveTimeout is the configured timeout or the fallback when none is set.
func (c Client) EffectiveTimeout() int {
	t := c.Timeout
	if t <= 0 {
		t = c.Fallback
	}
	return t
}

// Span is the width of the window, at least one step.
func (w Window) Span() int {
	s := w.Max - w.Min
	if s < w.Step {
		s = w.Step
	}
	return s
}
`

const inlineShapeApp = `// Package app uses the client settings.
package app

import (
	"fmt"

	"github.com/projectq/kit/conf"
)

// Settings is the app's own copy of the knobs.
type Settings struct {
	Timeout  int
	Fallback int
}

// N1 copies two fields into the app's struct: plain field assignments.
func N1(c conf.Client) Settings {
	var s Settings
	s.Timeout = c.Timeout
	s.Fallback = c.Fallback
	return s
}

// N2 sums two fields into one variable without the method's condition.
func N2(c conf.Client) int {
	total := c.Timeout
	total += c.Fallback
	return total
}

// N3 takes the larger of the two fields in one line.
func N3(c conf.Client) int {
	return max(c.Timeout, c.Fallback)
}

// N4 defaults a single field.
func N4(c conf.Client) int {
	t := c.Timeout
	if t <= 0 {
		t = 30
	}
	return t
}

// N5 calls the method and prints the fields next to it.
func N5(c conf.Client) string {
	t := c.EffectiveTimeout()
	return fmt.Sprintf("%d (%d/%d)", t, c.Timeout, c.Fallback)
}

// N6 prints the window bounds and computes a plain width.
func N6(w conf.Window) string {
	width := w.Max - w.Min
	return fmt.Sprintf("%d..%d step %d width %d", w.Min, w.Max, w.Step, width)
}

// N7 checks the fields with an if but keeps them in separate variables.
func N7(c conf.Client) (int, int) {
	a := c.Timeout
	b := c.Fallback
	if a <= 0 {
		a = b
	}
	return a, b
}

// Run dials with a timeout. P1: inline copy of Client.EffectiveTimeout, other names, if/else.
func Run(cfg conf.Client, attempts int) error {
	if attempts <= 0 {
		return fmt.Errorf("no attempts")
	}
	var limit int
	if cfg.Timeout > 0 {
		limit = cfg.Timeout
	} else {
		limit = cfg.Fallback
	}
	for i := 0; i < attempts; i++ {
		fmt.Println("dial", cfg.Name, limit, i)
	}
	return nil
}

// Layout places columns. P2: inline copy of Window.Span with other names.
func Layout(win conf.Window, cols []string) []int {
	out := make([]int, 0, len(cols))
	width := win.Max - win.Min
	if width < win.Step {
		width = win.Step
	}
	for i := range cols {
		out = append(out, i*width)
	}
	return out
}

// N8 has the method's condition but adds the fallback instead of taking it.
func N8(c conf.Client) int {
	total := c.Timeout
	if total <= 0 {
		total += c.Fallback
	}
	return total
}
`
