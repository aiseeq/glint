package timerules

import (
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewCalendarDayDiffInLocalTimeRule())
}

var (
	localDateTimeValue = regexp.MustCompile(`new\s+Date\s*\(\s*([\x60'"])([^\x60'"]*)[\x60'"]\s*\)\s*\.\s*(?:getTime|valueOf)\s*\(\s*\)`)
	dayMilliseconds    = regexp.MustCompile(`(?:24\s*\*\s*60\s*\*\s*60\s*\*\s*1000|86400000)`)
	dayConstant        = regexp.MustCompile(`(?m)\b(?:const|let|var)\s+(\w+)\s*=\s*(?:24\s*\*\s*60\s*\*\s*60\s*\*\s*1000|86400000)\b`)
	dateTimeZone       = regexp.MustCompile(`(?:Z|[+-]\d{2}:?\d{2})$`)
	explicitZoneOnLine = regexp.MustCompile(`(?:Z|\+\d{2}:?\d{2})`)
)

// CalendarDayDiffInLocalTimeRule detects calendar-day comparisons made with
// elapsed local timestamp milliseconds.
type CalendarDayDiffInLocalTimeRule struct {
	*rules.BaseRule
}

// NewCalendarDayDiffInLocalTimeRule creates the rule.
func NewCalendarDayDiffInLocalTimeRule() *CalendarDayDiffInLocalTimeRule {
	return &CalendarDayDiffInLocalTimeRule{BaseRule: rules.NewBaseRule(
		"calendar-day-diff-in-local-time",
		"patterns",
		"Detects differences of local date-time timestamps compared with a whole number of days — daylight-saving changes make a calendar week longer or shorter than 24-hour multiples",
		core.SeverityMedium,
	)}
}

// AnalyzeFile reports local date-time timestamp differences compared with days.
func (r *CalendarDayDiffInLocalTimeRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if (!ctx.IsTypeScriptFile() && !ctx.IsJavaScriptFile()) || ctx.IsGenerated() {
		return nil
	}
	code := strings.Join(helpers.FileJSCode(ctx), "\n")
	dayNames := map[string]bool{}
	for _, match := range dayConstant.FindAllStringSubmatch(code, -1) {
		dayNames[match[1]] = true
	}
	var violations []*core.Violation
	for i, line := range strings.Split(code, "\n") {
		values := localDateTimeValue.FindAllStringSubmatchIndex(line, -1)
		if len(values) < 2 || !strings.Contains(line, "-") {
			continue
		}
		if explicitZoneOnLine.MatchString(ctx.GetLine(i + 1)) {
			continue
		}
		localCount := 0
		for _, match := range values {
			dateText := line[match[4]:match[5]]
			if !dateTimeZone.MatchString(dateText) {
				localCount++
			}
		}
		if localCount < 2 || !calendarDayScale(line, dayNames) || ctx.IsSuppressed(i+1, r.Name()) {
			continue
		}
		v := r.CreateViolation(ctx.RelPath, i+1, "The difference between local date-time timestamps is elapsed time, so a daylight-saving change makes calendar days differ from multiples of 24 hours")
		v.WithCode(strings.TrimSpace(ctx.GetLine(i + 1)))
		v.WithSuggestion("Compare date-only values in UTC, or compare calendar-day counts instead of timestamp milliseconds")
		violations = append(violations, v)
	}
	return violations
}

func calendarDayScale(line string, dayNames map[string]bool) bool {
	if dayMilliseconds.MatchString(line) {
		return true
	}
	for name := range dayNames {
		if regexp.MustCompile(`\b` + regexp.QuoteMeta(name) + `\b`).MatchString(line) {
			return true
		}
	}
	return false
}
