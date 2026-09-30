package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Only test files are skipped: latest_rates.go contains "test_" and a
// testimonials directory starts with "/test", yet both are production code.
func TestIgnoredError_ProductionFilesWithTestLikeNames(t *testing.T) {
	const source = `package rates

import "strconv"

func Latest(s string) int {
	v, _ := strconv.Atoi(s)
	return v
}
`
	for _, path := range []string{"rates/latest_rates.go", "web/testimonials/rates.go", "rates/testing.go"} {
		t.Run(path, func(t *testing.T) {
			found := ignoredErrorMessages(t, map[string]string{path: source})
			assert.Len(t, found, 1, "%v", found)
		})
	}
}
