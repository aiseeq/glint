package frontendrules

import (
	"fmt"
	"maps"
	"regexp"
	"strconv"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
)

func init() { rules.Register(NewTSPeriodBoundaryByHandRule()) }

// TSPeriodBoundaryByHandRule finds calendar boundaries calculated outside
// configured shared period modules.
type TSPeriodBoundaryByHandRule struct {
	*rules.BaseRule
	periodModules []string
	dayConstants  map[string]string
}

// NewTSPeriodBoundaryByHandRule creates the rule.
func NewTSPeriodBoundaryByHandRule() *TSPeriodBoundaryByHandRule {
	return &TSPeriodBoundaryByHandRule{BaseRule: rules.NewBaseRule(
		"ts-period-boundary-by-hand", "patterns",
		"Detects frontend calendar period boundaries calculated outside configured shared period modules",
		core.SeverityMedium,
	).DeclareSettings(rules.NewSettingSpec("period_modules", "string list", "", "Paths of shared period modules excluded from this check.", []string{"src/lib/period.ts"}))}
}

// Configure sets the glob paths of shared period modules.
func (r *TSPeriodBoundaryByHandRule) Configure(settings map[string]any) error {
	if err := r.BaseRule.Configure(settings); err != nil {
		return err
	}
	modules, exists, err := r.GetStringListSetting("period_modules")
	if err != nil {
		return err
	}
	r.periodModules = nil
	if exists {
		r.periodModules = modules
	}
	for i := range r.periodModules {
		r.periodModules[i] = strings.ReplaceAll(r.periodModules[i], "\\", "/")
	}
	return nil
}

var (
	periodSetter  = regexp.MustCompile(`\b([A-Za-z_$][\w$]*)\s*\.\s*set(UTC)?(Date|Month|FullYear)\s*\(\s*([A-Za-z_$][\w$]*)\s*\.\s*get(UTC)?(Date|Month|FullYear)\s*\(\s*\)\s*([+-])\s*[^,)]+\)`)
	periodParts   = regexp.MustCompile(`\bnew\s+Date\s*\(\s*([A-Za-z_$][\w$]*)\s*\.\s*getFullYear\s*\(\s*\)\s*,\s*([A-Za-z_$][\w$]*)\s*\.\s*getMonth\s*\(\s*\)\s*,`)
	periodDay     = regexp.MustCompile(`\b([A-Za-z_$][\w$]*)\s*\.\s*setHours\s*\(\s*0\s*,\s*0\s*,\s*0\s*,\s*0\s*\)`)
	periodWrapper = regexp.MustCompile(`\bMath\.(?:round|floor|ceil|trunc)\s*\(`)
	periodConst   = regexp.MustCompile(`\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([^;\n]+)`)
	periodNumber  = regexp.MustCompile(`^(?:\d[\d_]*(?:\.\d[\d_]*)?|\.\d[\d_]*)(?:[eE][+-]?\d[\d_]*)?$`)
)

// UseProjectFiles indexes constants that may be imported by another frontend file.
func (r *TSPeriodBoundaryByHandRule) UseProjectFiles(files []*core.FileContext) {
	r.dayConstants = make(map[string]string)
	for _, file := range files {
		if !productionFrontendFile(file) || file.IsGenerated() {
			continue
		}
		for _, match := range periodConst.FindAllStringSubmatch(patternkit.NewJSFlat(file).Code, -1) {
			r.dayConstants[match[1]] = strings.TrimSpace(match[2])
		}
	}
}

// ResetState clears indexed project constants.
func (r *TSPeriodBoundaryByHandRule) ResetState() { r.dayConstants = nil }

// AnalyzeFile reports manual calendar boundaries outside shared period modules.
func (r *TSPeriodBoundaryByHandRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if len(r.periodModules) == 0 || !productionFrontendFile(ctx) || ctx.IsGenerated() || r.isPeriodModule(ctx.RelPath) {
		return nil
	}
	f := patternkit.NewJSFlat(ctx)
	positions := make([]int, 0)
	for _, match := range periodSetter.FindAllStringSubmatchIndex(f.Code, -1) {
		if f.Code[match[2]:match[3]] != f.Code[match[8]:match[9]] ||
			(match[4] >= 0) != (match[10] >= 0) ||
			f.Code[match[6]:match[7]] != f.Code[match[12]:match[13]] {
			continue
		}
		positions = append(positions, match[0])
	}
	for _, match := range periodParts.FindAllStringSubmatchIndex(f.Code, -1) {
		if f.Code[match[2]:match[3]] == f.Code[match[4]:match[5]] {
			positions = append(positions, match[0])
		}
	}
	for _, match := range periodDay.FindAllStringIndex(f.Code, -1) {
		positions = append(positions, match[0])
	}
	constants := make(map[string]string, len(r.dayConstants))
	maps.Copy(constants, r.dayConstants)
	for _, match := range periodConst.FindAllStringSubmatch(f.Code, -1) {
		constants[match[1]] = strings.TrimSpace(match[2])
	}
	for _, match := range periodWrapper.FindAllStringIndex(f.Code, -1) {
		open := match[1] - 1
		close, ok := f.Closing(open)
		if !ok {
			continue
		}
		if isDayDifference(f.Code[open+1:close], constants) {
			positions = append(positions, match[0])
		}
	}
	if len(positions) == 0 {
		return nil
	}
	module := r.periodModules[0]
	message := fmt.Sprintf("Period boundary computed by hand — take it from the shared period module (%s)", module)
	out := make([]*core.Violation, 0, len(positions))
	seen := map[int]bool{}
	for _, pos := range positions {
		line := f.Line(pos)
		if seen[line] {
			continue
		}
		seen[line] = true
		v := r.CreateViolation(ctx.RelPath, line, message)
		v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
		out = append(out, v)
	}
	return out
}

func (r *TSPeriodBoundaryByHandRule) isPeriodModule(file string) bool {
	file = strings.ReplaceAll(file, "\\", "/")
	for _, pattern := range r.periodModules {
		if core.MatchGlob(pattern, file) {
			return true
		}
	}
	return false
}

func isDayDifference(expression string, constants map[string]string) bool {
	division := splitTopLevel(expression, '/')
	if len(division) != 2 || !hasTopLevelOperator(stripOuterParens(division[0]), '-') {
		return false
	}
	value, ok := evalDayMillis(division[1], constants, make(map[string]bool))
	return ok && value == 86_400_000
}

func evalDayMillis(expression string, constants map[string]string, visiting map[string]bool) (float64, bool) {
	expression = stripOuterParens(strings.TrimSpace(expression))
	if parts := splitTopLevel(expression, '*'); len(parts) > 1 {
		product := 1.0
		for _, part := range parts {
			value, ok := evalDayMillis(part, constants, visiting)
			if !ok {
				return 0, false
			}
			product *= value
		}
		return product, true
	}
	if periodNumber.MatchString(expression) {
		value, err := strconv.ParseFloat(strings.ReplaceAll(expression, "_", ""), 64)
		return value, err == nil
	}
	if !patternkit.JsIdentifier.MatchString(expression) || visiting[expression] {
		return 0, false
	}
	definition, ok := constants[expression]
	if !ok {
		return 0, false
	}
	visiting[expression] = true
	value, ok := evalDayMillis(definition, constants, visiting)
	delete(visiting, expression)
	return value, ok
}

func stripOuterParens(expression string) string {
	for {
		expression = strings.TrimSpace(expression)
		if len(expression) < 2 || expression[0] != '(' || expression[len(expression)-1] != ')' {
			return expression
		}
		depth := 0
		closesAtEnd := false
	endScan:
		for i, char := range expression {
			switch char {
			case '(':
				depth++
			case ')':
				depth--
				if depth == 0 {
					closesAtEnd = i == len(expression)-1
					break endScan
				}
			}
		}
		if !closesAtEnd {
			return expression
		}
		expression = expression[1 : len(expression)-1]
	}
}

func splitTopLevel(expression string, operator byte) []string {
	depth, start := 0, 0
	var parts []string
	for i := 0; i < len(expression); i++ {
		switch expression[i] {
		case '(':
			depth++
		case ')':
			depth--
		default:
			if expression[i] == operator && depth == 0 {
				parts = append(parts, strings.TrimSpace(expression[start:i]))
				start = i + 1
			}
		}
	}
	if len(parts) == 0 {
		return []string{strings.TrimSpace(expression)}
	}
	return append(parts, strings.TrimSpace(expression[start:]))
}

func hasTopLevelOperator(expression string, operator byte) bool {
	parts := splitTopLevel(expression, operator)
	return len(parts) == 2 && parts[0] != "" && parts[1] != ""
}
