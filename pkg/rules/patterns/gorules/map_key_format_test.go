package gorules

import (
	"strings"
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patterntest"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mapKeyFormatSource keys maps by strings formatted from comparable fields:
// every lookup formats, allocates and hashes a long string, while a struct
// of the same fields is a key as it is. A map whose string keys also come
// from elsewhere, or that leaves the function whole (serialized, returned),
// needs the strings; a rounding format merges keys a struct would keep
// apart.
const mapKeyFormatSource = `package plan

import (
	"encoding/json"
	"fmt"
)

type Target struct {
	Kind, Name string
	N          int
}

func (t Target) Key() string { return fmt.Sprintf("%s:%s:%d", t.Kind, t.Name, t.N) }

type Tracker struct {
	counts  map[string]int
	labels map[string]string
	prices map[string]int
	sent   map[string]bool
}

func (c *Tracker) Mark(kind, name string, n int) {
	c.counts[Target{kind, name, n}.Key()]++ // want map-key-built-by-format
	if c.counts[fmt.Sprintf("%s:%s:%d", kind, name, n)] > 3 { // want map-key-built-by-format
		return
	}
	c.labels[fmt.Sprint(kind, n)] = name
	c.labels[name] = kind
	c.prices[fmt.Sprintf("%s:%.2f", kind, float64(n))]++
	c.sent[fmt.Sprintf("%s:%d", kind, n)] = true
}

func (c *Tracker) Dump() ([]byte, error) { return json.Marshal(c.sent) }

func NewTracker() *Tracker { return &Tracker{counts: map[string]int{}, labels: make(map[string]string)} }

//glint:hot
func Count(seen map[string]int, kind string, n int) {
	seen[fmt.Sprintf("%s/%d", kind, n)]++ // want map-key-built-by-format
}
`

func TestMapKeyBuiltByFormat(t *testing.T) {
	files := map[string]string{"plan/plan.go": mapKeyFormatSource}
	violations, err := NewMapKeyBuiltByFormatRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	assert.Equal(t, patterntest.WantedLines(files, "map-key-built-by-format"), patterntest.FoundLines(violations))
	severities := map[string]core.Severity{}
	for _, v := range violations {
		name, _, _ := strings.Cut(v.Message, " is keyed")
		severities[name] = max(severities[name], v.Severity)
	}
	assert.Equal(t, map[string]core.Severity{"The map counts": core.SeverityLow, "The map seen": core.SeverityMedium}, severities, "a hot function makes it medium")
}
