package moneyrules

import (
	"fmt"
	"go/constant"
	"go/token"
	"go/types"
	"golang.org/x/tools/go/packages"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patterntest"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func runBusinessConstantRule(t *testing.T, files map[string]string) []*core.Violation {
	t.Helper()
	project := patterntest.DecimalProject(t, files)
	violations, err := NewBusinessConstantInCodeRule().AnalyzeGoProject(project)
	require.NoError(t, err)
	return violations
}

func TestBusinessConstantInCode_TrimpathNestedReplaceModule(t *testing.T) {
	root, contexts := rulestest.Module(t, map[string]string{
		"go.mod":           "module example.com/app\n\ngo 1.24\n\nrequire example.com/shared v0.0.0\nreplace example.com/shared => ./shared\n",
		"shared/go.mod":    "module example.com/shared\n\ngo 1.24\n",
		"shared/limits.go": "package shared\n\nconst MaxDays = 5\n",
		"shared/other.go": `package shared

func localConst() { const MaxDays = 9; _ = MaxDays }
func localVar() { var MaxDays = 9; _ = MaxDays }
func localType() { type MaxDays int; var _ MaxDays }
func parameter(MaxDays int) { _ = MaxDays }
func identity[MaxDays any](value MaxDays) MaxDays { return value }
`,
		"app.go": "package app\n\nimport (\"time\"; \"example.com/shared\")\n\nfunc F(now time.Time) time.Time { return now.AddDate(0, 0, shared.MaxDays) }\n",
	})
	list := func(cfg *packages.Config, patterns ...string) ([]*packages.Package, error) {
		cfg.BuildFlags = []string{"-trimpath"}
		return packages.Load(cfg, patterns...)
	}
	for range 8 {
		project, err := core.LoadGoProject(root, contexts, core.GoProjectOptions{ListPackages: list})
		require.NoError(t, err)
		violations, err := NewBusinessConstantInCodeRule().AnalyzeGoProject(project)
		require.NoError(t, err)
		require.Len(t, violations, 1)
		assert.Equal(t, "shared/limits.go", violations[0].File)
		assert.Equal(t, 3, violations[0].Line)
	}
}

// A //line directive moves the declaration of a constant to another file and
// line: the finding names the position the directive gives, file and line
// together, and a directive to a file outside the analyzed ones - a grammar,
// a file outside the project - reports nothing, in the module's own syntax
// as in the export data of a nested module. Export data, as go/packages
// reads it, keeps the file of the directive and the line in the source file,
// so the constant of the nested module is reported at line 10, as it is
// without -trimpath.
func TestBusinessConstantInCode_LineDirective(t *testing.T) {
	root := t.TempDir()
	contexts := rulestest.ModuleIn(t, root, map[string]string{
		"go.mod":          "module example.com/app\n\ngo 1.24\n\nrequire example.com/shared v0.0.0\nreplace example.com/shared => ./shared\n",
		"limits/other.go": "package limits\n\n// The declaration of Spare is told to be here.\n",
		"limits/gen.go": "package limits\n\n//line limits.y:40\nconst MaxDays = 5\n\n//line /elsewhere/rules.y:7\nconst GraceDays = 3\n\n//line " +
			filepath.Join(root, "limits", "other.go") + ":3\nconst Spare = 2\n",
		"shared/go.mod":   "module example.com/shared\n\ngo 1.24\n",
		"shared/other.go": "package shared\n\n// The declaration of Spare is told to be here.\n",
		"shared/gen.go": "package shared\n\n//line limits.y:40\nconst MaxDays = 5\n\n//line /elsewhere/rules.y:7\nconst GraceDays = 3\n\n//line " +
			filepath.Join(root, "shared", "other.go") + ":3\nconst Spare = 2\n",
		"app.go": `package app

import (
	"time"

	"example.com/app/limits"
	"example.com/shared"
)

func Due(now time.Time) time.Time {
	now = now.AddDate(0, 0, limits.MaxDays).AddDate(0, 0, limits.GraceDays).AddDate(0, 0, limits.Spare)
	return now.AddDate(0, 0, shared.MaxDays).AddDate(0, 0, shared.GraceDays).AddDate(0, 0, shared.Spare)
}
`,
	})
	project, err := core.LoadGoProject(root, contexts, core.GoProjectOptions{})
	require.NoError(t, err)
	violations, err := NewBusinessConstantInCodeRule().AnalyzeGoProject(project)
	require.NoError(t, err)
	var got []string
	for _, v := range violations {
		got = append(got, fmt.Sprintf("%s:%d %s", v.File, v.Line, v.Context["constant"]))
	}
	assert.Equal(t, []string{"limits/other.go:3 Spare", "shared/other.go:10 Spare"}, got)
}

// A constant of a cgo package of a nested module is declared, as the export
// data tells, in the cgo source, which the run analyzes as no package file:
// the go command type-checks the files it generated from it. Nothing is
// reported there, as without -trimpath.
func TestBusinessConstantInCode_CgoNestedModuleNotAnalyzed(t *testing.T) {
	rulestest.RequireCgo(t)
	root, contexts := rulestest.Module(t, map[string]string{
		"go.mod":        "module example.com/app\n\ngo 1.24\n\nrequire example.com/shared v0.0.0\nreplace example.com/shared => ./shared\n",
		"shared/go.mod": "module example.com/shared\n\ngo 1.24\n",
		"shared/cgo.go": "package shared\n\n/*\nstatic int seven(void) { return 7; }\n*/\nimport \"C\"\n\nconst CgoDays = 11\n\nfunc Seven() int { return int(C.seven()) }\n",
		"app.go":        "package app\n\nimport (\"time\"; \"example.com/shared\")\n\nfunc F(now time.Time) time.Time { return now.AddDate(0, 0, shared.CgoDays) }\n",
	})
	project, err := core.LoadGoProject(root, contexts, core.GoProjectOptions{})
	require.NoError(t, err)
	var cgoDays types.Object
	for _, pkg := range project.Packages {
		for _, imported := range pkg.Package.Types.Imports() {
			if imported.Path() == "example.com/shared" {
				cgoDays = imported.Scope().Lookup("CgoDays")
			}
		}
	}
	require.NotNil(t, cgoDays)
	declFile, err := project.FileForObject(cgoDays)
	require.NoError(t, err, "the cgo source is a project file: only the analyzed set leaves it out")
	assert.Equal(t, "shared/cgo.go", declFile.RelPath)
	violations, err := NewBusinessConstantInCodeRule().AnalyzeGoProject(project)
	require.NoError(t, err)
	assert.Empty(t, violations)
}

func TestBusinessConstantInCode_CalendarArithmetic(t *testing.T) {
	violations := runBusinessConstantRule(t, map[string]string{
		"credit/credit.go": `package credit

import "time"

// HoldDays is how many days a new deposit earns nothing.
const HoldDays = 4

// MaturedDays is how long a released deposit stays in the feed.
const MaturedDays = 7

func AccrualFrom(day time.Time) time.Time {
	return day.AddDate(0, 0, HoldDays)
}
`,
		"api/router.go": `package api

import (
	"time"

	"example.com/rulestest/credit"
)

func MaturedSince(now time.Time) time.Time {
	return now.AddDate(0, 0, -credit.MaturedDays)
}
`,
	})

	require.Len(t, violations, 2)
	assert.Contains(t, violations[0].Message, "HoldDays = 4")
	assert.Contains(t, violations[0].Message, "calendar arithmetic")
	assert.Equal(t, 6, violations[0].Line)
	assert.Contains(t, violations[1].Message, "MaturedDays = 7", "a use in another package counts")
	assert.Contains(t, violations[1].Message, "router.go")
}

func TestBusinessConstantInCode_MoneyAmount(t *testing.T) {
	violations := runBusinessConstantRule(t, map[string]string{
		"check/check.go": `package check

import "github.com/shopspring/decimal"

const minToleranceUSD = 50

const percentBase = 100

const basisPoints = 0.0001

const daysInYear = 365

const driftShare = 0.005

func Tolerance() decimal.Decimal {
	return decimal.NewFromInt(minToleranceUSD)
}

func Drift(d decimal.Decimal) decimal.Decimal {
	return d.Mul(decimal.NewFromFloat(driftShare))
}

func Percent(d decimal.Decimal) (decimal.Decimal, decimal.Decimal) {
	_ = decimal.NewFromInt(daysInYear)
	return decimal.NewFromInt(percentBase), decimal.NewFromFloat(basisPoints)
}
`,
	})

	require.Len(t, violations, 2, "powers of ten and calendar units convert units and are not reported")
	assert.Contains(t, violations[0].Message, "minToleranceUSD = 50")
	assert.Contains(t, violations[0].Message, "decimal amount")
	assert.Contains(t, violations[1].Message, "driftShare = 0.005", "a fraction reads as a decimal, not as 1/200")
}

// A technical constant never takes a business use: a TTL added to a time, a
// page size, a retry count.
func TestBusinessConstantInCode_TechnicalConstantsAreSilent(t *testing.T) {
	violations := runBusinessConstantRule(t, map[string]string{
		"cache/cache.go": `package cache

import "time"

const ttl = 5 * time.Minute

const pageSize = 50

const zeroDays = 0

func Expiry(now time.Time) time.Time {
	local := 3
	_ = now.AddDate(0, 0, zeroDays)
	_ = now.AddDate(0, 0, local)
	_ = now.AddDate(0, 0, 1)
	return now.Add(ttl)
}

func Page() int { return pageSize }
`,
	})

	assert.Empty(t, violations)
}

// A constant that is the default of a setting read from the environment or a
// command-line flag is already configurable: an operator changes it without a
// release. Seeding the same default elsewhere does not make it hardcoded.
func TestBusinessConstantInCode_DefaultOfConfigurableSettingIsSilent(t *testing.T) {
	violations := runBusinessConstantRule(t, map[string]string{
		"monitor/monitor.go": `package monitor

import (
	"flag"
	"os"
	"time"

	"github.com/shopspring/decimal"
)

const defaultReserveUSD = 250_000

const defaultLimitUSD = 700

const defaultWindowDays = 5

const hardcodedUSD = 500

func New() decimal.Decimal { return decimal.NewFromInt(defaultReserveUSD) }

func envDecimal(name string, def int64) (decimal.Decimal, error) {
	raw, ok := os.LookupEnv(name)
	if !ok {
		return decimal.NewFromInt(def), nil
	}
	return decimal.NewFromString(raw)
}

func Load() (decimal.Decimal, error) {
	return envDecimal("PROJECTA_RESERVE_USD", defaultReserveUSD)
}

var limit = flag.Int64("limit-usd", defaultLimitUSD, "limit")

var window = flag.Int("window-days", int(defaultWindowDays), "window")

func Limit() decimal.Decimal { return decimal.NewFromInt(defaultLimitUSD) }

func Since(now time.Time) time.Time { return now.AddDate(0, 0, -defaultWindowDays) }

func Hard() decimal.Decimal { return decimal.NewFromInt(hardcodedUSD) }
`,
	})

	require.Len(t, violations, 1, "only the constant no setting overrides is reported")
	assert.Contains(t, violations[0].Message, "hardcodedUSD = 500")
}

// A constant passed to a function that does not read the environment is not
// a setting's default: the value stays hardcoded.
func TestBusinessConstantInCode_OrdinaryHelperArgumentStillReported(t *testing.T) {
	violations := runBusinessConstantRule(t, map[string]string{
		"fee/fee.go": `package fee

import "github.com/shopspring/decimal"

const minFeeUSD = 3

func atLeast(name string, floor int64) decimal.Decimal {
	_ = name
	return decimal.NewFromInt(floor)
}

func Fee() decimal.Decimal {
	_ = atLeast("fee", minFeeUSD)
	return decimal.NewFromInt(minFeeUSD)
}
`,
	})

	require.Len(t, violations, 1)
	assert.Contains(t, violations[0].Message, "minFeeUSD = 3")
}

func TestIsPowerOfTen(t *testing.T) {
	tests := map[string]bool{"1": true, "100": true, "0.01": true, "1000": true, "50": false, "0.5": false, "110": false, "0.0003": false}
	for literal, expected := range tests {
		kind := token.INT
		if strings.Contains(literal, ".") {
			kind = token.FLOAT
		}
		assert.Equal(t, expected, isPowerOfTen(constant.MakeFromLiteral(literal, kind, 0)), literal)
	}
}

// Months in a quarter and quarters in a year are calendar units too, but 3
// and 4 are also ordinary amounts: the constant's name says which.
func TestBusinessConstantInCode_QuarterUnits(t *testing.T) {
	violations := runBusinessConstantRule(t, map[string]string{
		"check/check.go": `package check

import "github.com/shopspring/decimal"

const monthsPerQuarter = 3

const quartersInYear = 4

const minDepositUSD = 3

func Units() (decimal.Decimal, decimal.Decimal, decimal.Decimal) {
	return decimal.NewFromInt(monthsPerQuarter), decimal.NewFromInt(quartersInYear), decimal.NewFromInt(minDepositUSD)
}
`,
	})

	require.Len(t, violations, 1, "a quarter's months and a year's quarters convert units")
	assert.Contains(t, violations[0].Message, "minDepositUSD = 3")
}
