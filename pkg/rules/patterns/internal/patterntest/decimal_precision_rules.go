package patterntest

import (
	"fmt"
	"testing"

	"github.com/aiseeq/glint/pkg/rules"
	"github.com/stretchr/testify/assert"
)

// DecimalWanted runs a typed rule on one file of a module that can import
// the decimal package and compares the findings with the // want lines.
func DecimalWanted(t *testing.T, rule rules.GoProjectRule, source string) {
	t.Helper()
	var want []string
	for _, line := range wantLines(source) {
		want = append(want, fmt.Sprintf("ledger/ledger.go:%d", line))
	}
	assert.Equal(t, want, TypedFuncFindings(t, rule, map[string]string{"ledger/ledger.go": source}))
}
