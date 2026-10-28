package timerules

import (
	"strings"
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/stretchr/testify/assert"
)

func TestCalendarDayDiffInLocalTimeRule(t *testing.T) {
	tests := []struct {
		name string
		code string
		want int
	}{
		{
			name: "local date strings compared with a week in milliseconds",
			code: "const dayMs = 24 * 60 * 60 * 1000\nexpect(new Date(`${date}T12:00:00`).getTime() - new Date(`${periodStart}T12:00:00`).getTime()).toBe(7 * dayMs)",
			want: 1,
		},
		{
			name: "UTC date strings",
			code: "Date.parse(`${date}T00:00:00Z`) - Date.parse(`${periodStart}T00:00:00Z`) === 7 * 86400000",
		},
		{
			name: "local date difference compared as calendar days",
			code: "differenceInCalendarDays(new Date(a), new Date(b)) === 7",
		},
		{
			name: "elapsed duration compared with hours",
			code: "new Date(a).getTime() - new Date(b).getTime() > 12 * 60 * 60 * 1000",
		},
		{
			name: "timestamps with explicit offsets",
			code: "new Date(`${date}T12:00:00+02:00`).getTime() - new Date(`${start}T12:00:00+02:00`).getTime() === 7 * 86400000",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &core.FileContext{Path: "/page.test.tsx", RelPath: "page.test.tsx", Content: []byte(tt.code), Lines: strings.Split(tt.code, "\n")}
			assert.Len(t, NewCalendarDayDiffInLocalTimeRule().AnalyzeFile(ctx), tt.want)
		})
	}
}
