package patterns

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/stretchr/testify/assert"
)

func TestPaginationBoundaryTruncationRule_Metadata(t *testing.T) {
	rule := NewPaginationBoundaryTruncationRule()
	assert.Equal(t, "pagination-boundary-truncation", rule.Name())
	assert.Equal(t, "patterns", rule.Category())
	assert.Equal(t, core.SeverityMedium, rule.DefaultSeverity())
}

func TestPaginationBoundaryTruncationRule_Detection(t *testing.T) {
	tests := []struct {
		name string
		code string
		want int
	}{
		{
			name: "silent cap before time boundary",
			code: `package sync
func fetch(maxPages int, minTime *time.Time) error {
	pages := 0
	for {
		items := getPage()
		pages++
		if len(items) == 0 || (minTime != nil && items[len(items)-1].Time.Before(*minTime)) { break }
		if maxPages > 0 && pages >= maxPages { break }
	}
	return nil
}`,
			want: 1,
		},
		{
			name: "local cutoff and cap in for condition",
			code: `package sync
func fetch(period time.Duration, maxPages int) error {
	cutoff := time.Now().Add(-period)
	for page := 0; page < maxPages; page++ {
		items := getPage()
		if items[0].Time.Before(cutoff) { break }
	}
	return nil
}`,
			want: 1,
		},
		{
			name: "nested switch break does not exit pagination",
			code: `package sync
func fetch(maxPages int, since time.Time) error {
	for {
		if item.Time.Before(since) { break }
		if pages >= maxPages { switch status { case done: break } }
	}
	return nil
}`,
			want: 0,
		},
		{
			name: "conditional error still has silent break path",
			code: `package sync
func fetch(maxPages int, since time.Time, strict bool) error {
	for {
		if item.Time.Before(since) { break }
		if pages >= maxPages {
			if strict { return errors.New("truncated") }
			break
		}
	}
	return nil
}`,
			want: 1,
		},
		{
			name: "cap is allowed only without boundary contract",
			code: `package sync
func fetch(maxPages int, minTime *time.Time) error {
	for pages := 0; ; pages++ {
		if minTime != nil && item.Time.Before(*minTime) { break }
		if pages >= maxPages {
			if minTime == nil { break }
			return errors.New("truncated")
		}
	}
	return nil
}`,
			want: 0,
		},
		{
			name: "cap returns explicit truncation error",
			code: `package sync
func fetch(maxPages int, since *time.Time) error {
	for pages := 0; ; pages++ {
		items := getPage()
		if since != nil && items[0].Time.Before(*since) { break }
		if maxPages > 0 && pages >= maxPages { return errors.New("history truncated before since") }
	}
	return nil
}`,
			want: 0,
		},
		{
			name: "bounded retry loop has no time boundary",
			code: `package sync
func fetch(maxAttempts int) error {
	for attempts := 0; attempts < maxAttempts; attempts++ {
		if request() == nil { break }
	}
	return nil
}`,
			want: 0,
		},
		{
			name: "time walk without page cap",
			code: `package sync
func fetch(minMinedAt *time.Time) error {
	for {
		items := getPage()
		if minMinedAt != nil && items[0].Time.Before(*minMinedAt) { break }
	}
	return nil
}`,
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := createQueryContext(t, "sync.go", tt.code)
			assert.Len(t, NewPaginationBoundaryTruncationRule().AnalyzeFile(ctx), tt.want)
		})
	}
}
