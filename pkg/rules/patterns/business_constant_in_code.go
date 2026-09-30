package patterns

import (
	"errors"
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"math/big"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"golang.org/x/tools/go/types/typeutil"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewBusinessConstantInCodeRule())
}

// decimalPackage is the import path of the decimal type money code uses.
const decimalPackage = "github.com/shopspring/decimal"

// decimalConstructors build a decimal from a number; their first argument is
// the value.
var decimalConstructors = map[string]bool{
	"New": true, "NewFromInt": true, "NewFromInt32": true, "NewFromInt64": true,
	"NewFromUint64": true, "NewFromFloat": true, "NewFromFloat32": true,
}

// BusinessConstantInCodeRule detects a business rule written as a named
// constant in code:
//
//	// HoldDays — how many days a new deposit earns nothing.
//	const HoldDays = 4
//	...
//	return day.AddDate(0, 0, HoldDays)
//
// magic-number is satisfied by the name, yet the value is a decision of the
// business, not of the code: changing it for one environment, or switching the
// rule off on a test stand, takes a release. Two uses give such a constant
// away, because a page size, a buffer or a duration-based TTL never takes them:
//   - calendar arithmetic: an argument of time.Time.AddDate;
//   - money or a rate: the value of a decimal constructor
//     (decimal.NewFromInt(X)), except powers of ten, which convert units
//     (percent, basis points, cents), and calendar units (365 days, 24 hours),
//     which convert periods.
//
// A day-granular technical window (a cache eviction, a lookback that finds a
// data point) takes AddDate too; the rule cannot tell it from a business one.
// A constant that is the default of a setting — handed to a flag or
// configuration-key definer, or to a project function that reads the
// environment — is already configurable and is not reported.
//
// The finding sits on the constant's declaration and names the first such use,
// wherever in the project it is.
type BusinessConstantInCodeRule struct {
	*rules.BaseRule
}

// NewBusinessConstantInCodeRule creates the rule
func NewBusinessConstantInCodeRule() *BusinessConstantInCodeRule {
	return &BusinessConstantInCodeRule{
		BaseRule: rules.NewBaseRule(
			"business-constant-in-code",
			"patterns",
			"Detects a business rule hardcoded as a named constant — a constant that drives calendar arithmetic (AddDate) or a decimal amount (decimal constructor) and is not the default of an environment variable or a flag belongs in configuration",
			core.SeverityMedium,
		),
	}
}

// AnalyzeFile is a no-op: the rule needs every package's uses of a constant.
func (r *BusinessConstantInCodeRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *BusinessConstantInCodeRule) RequiresSSA() bool { return false }

// businessUse is the first place a constant is used as a business value.
type businessUse struct {
	pos  token.Pos
	kind string
}

// AnalyzeGoProject collects the business uses of package-level constants
// across all loaded packages and reports the constants declared in analyzed
// files.
func (r *BusinessConstantInCodeRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil || ctx.FileSet == nil {
		return nil, errors.New("business-constant-in-code: project has no file set")
	}

	uses := make(map[*types.Const]businessUse)
	analyzed := make(map[string]bool)
	settings := newSettingDefaults()
	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil || pkg.Package.TypesInfo == nil {
			return nil, errors.New("business-constant-in-code: package has no typed syntax")
		}
		for _, fileCtx := range pkg.Files {
			if !fileCtx.IsTestFile() {
				analyzed[fileCtx.Path] = true
			}
		}
		info := pkg.Package.TypesInfo
		for _, file := range pkg.Package.Syntax {
			ast.Inspect(file, func(n ast.Node) bool {
				switch node := n.(type) {
				case *ast.FuncDecl:
					settings.recordReader(info, node)
				case *ast.CallExpr:
					settings.recordCall(info, node)
					for _, use := range r.businessArgs(info, node) {
						if prev, seen := uses[use.obj]; !seen || use.pos < prev.pos {
							uses[use.obj] = businessUse{pos: use.pos, kind: use.kind}
						}
					}
				}
				return true
			})
		}
	}
	configurable := settings.defaults()

	var violations []*core.Violation
	for obj, use := range uses {
		declared := ctx.FileSet.Position(obj.Pos())
		if !analyzed[declared.Filename] || configurable[obj] {
			continue
		}
		at := ctx.FileSet.Position(use.pos)
		v := r.CreateViolation(declared.Filename, declared.Line, fmt.Sprintf(
			"Constant %s = %s is a business rule: it drives %s (%s:%d) — the value belongs in configuration, not in code",
			obj.Name(), constantText(obj.Val()), use.kind, shortPath(ctx, at.Filename), at.Line))
		v.WithSuggestion("Move the value into the configuration with a validated default, so it can change per environment without a release")
		v.WithContext("constant", obj.Name())
		violations = append(violations, v)
	}
	sort.Slice(violations, func(i, j int) bool {
		if violations[i].File != violations[j].File {
			return violations[i].File < violations[j].File
		}
		if violations[i].Line != violations[j].Line {
			return violations[i].Line < violations[j].Line
		}
		return violations[i].Message < violations[j].Message
	})
	return violations, nil
}

// constantText prints an integer exactly and a float as a decimal: an exact
// float prints as a fraction (1/200), which nobody reads as 0.005.
func constantText(v constant.Value) string {
	if v.Kind() == constant.Float {
		return v.String()
	}
	return v.ExactString()
}

// settingPackages define command-line flags and configuration keys: a
// constant handed to them is the default of a setting.
var settingPackages = map[string]bool{
	"flag": true, "github.com/spf13/pflag": true, "github.com/spf13/viper": true,
}

// environmentReaders are the calls that read the process environment, by
// package path and function name.
var environmentReaders = map[string]map[string]bool{
	"os":      {"Getenv": true, "LookupEnv": true},
	"syscall": {"Getenv": true},
}

// settingDefaults finds the constants that are the default of a setting: an
// argument of a flag or configuration-key definer, or of a function of the
// project that reads the environment (envInt("LIMIT", defaultLimit)). An
// operator already overrides such a value without a release.
type settingDefaults struct {
	// readers are the project functions whose body reads the environment.
	readers map[*types.Func]bool
	// passed are the constants handed to a call, resolved once every
	// reader is known.
	passed []constArgument
}

type constArgument struct {
	callee *types.Func
	obj    *types.Const
}

func newSettingDefaults() *settingDefaults {
	return &settingDefaults{readers: make(map[*types.Func]bool)}
}

// recordReader remembers a function whose body reads the environment.
func (s *settingDefaults) recordReader(info *types.Info, decl *ast.FuncDecl) {
	if decl.Body == nil {
		return
	}
	fn, ok := info.Defs[decl.Name].(*types.Func)
	if !ok {
		return
	}
	reads := false
	ast.Inspect(decl.Body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			callee := typeutil.StaticCallee(info, call)
			reads = callee != nil && callee.Pkg() != nil && environmentReaders[callee.Pkg().Path()][callee.Name()]
		}
		return !reads
	})
	if reads {
		s.readers[fn] = true
	}
}

// recordCall remembers the package-level constants a call receives.
func (s *settingDefaults) recordCall(info *types.Info, call *ast.CallExpr) {
	callee := typeutil.StaticCallee(info, call)
	if callee == nil {
		return
	}
	for _, arg := range call.Args {
		if obj := packageConstant(info, arg); obj != nil {
			s.passed = append(s.passed, constArgument{callee: callee.Origin(), obj: obj})
		}
	}
}

// defaults returns the constants handed to a setting definer or to an
// environment reader.
func (s *settingDefaults) defaults() map[*types.Const]bool {
	configurable := make(map[*types.Const]bool)
	for _, arg := range s.passed {
		if s.readers[arg.callee] || (arg.callee.Pkg() != nil && settingPackages[arg.callee.Pkg().Path()]) {
			configurable[arg.obj] = true
		}
	}
	return configurable
}

type constUse struct {
	obj  *types.Const
	pos  token.Pos
	kind string
}

// businessArgs returns the package-level constants the call uses as business
// values: any argument of time.Time.AddDate, the value of a decimal
// constructor.
func (r *BusinessConstantInCodeRule) businessArgs(info *types.Info, call *ast.CallExpr) []constUse {
	sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok {
		return nil
	}
	fn, ok := info.Uses[sel.Sel].(*types.Func)
	if !ok || fn.Pkg() == nil {
		return nil
	}

	var uses []constUse
	switch {
	case fn.Pkg().Path() == "time" && fn.Name() == "AddDate" && isTimeMethod(fn):
		for _, arg := range call.Args {
			if obj := packageConstant(info, arg); obj != nil {
				uses = append(uses, constUse{obj: obj, pos: arg.Pos(), kind: "calendar arithmetic"})
			}
		}
	case fn.Pkg().Path() == decimalPackage && decimalConstructors[fn.Name()] && len(call.Args) > 0:
		if obj := packageConstant(info, call.Args[0]); obj != nil && !isPowerOfTen(obj.Val()) && !isCalendarUnit(obj.Val()) {
			uses = append(uses, constUse{obj: obj, pos: call.Args[0].Pos(), kind: "a decimal amount (money or a rate)"})
		}
	}
	return uses
}

// isTimeMethod reports whether fn is a method of time.Time.
func isTimeMethod(fn *types.Func) bool {
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return false
	}
	named, ok := types.Unalias(sig.Recv().Type()).(*types.Named)
	return ok && named.Obj().Name() == "Time"
}

// packageConstant returns the package-level constant the expression names,
// looking through parentheses, a sign and a conversion: AddDate(0, 0, -Days),
// NewFromInt(int64(Limit)).
func packageConstant(info *types.Info, expr ast.Expr) *types.Const {
	for {
		switch e := ast.Unparen(expr).(type) {
		case *ast.UnaryExpr:
			if e.Op != token.SUB && e.Op != token.ADD {
				return nil
			}
			expr = e.X
			continue
		case *ast.CallExpr:
			tv, ok := info.Types[e.Fun]
			if !ok || !tv.IsType() || len(e.Args) != 1 {
				return nil
			}
			expr = e.Args[0]
			continue
		case *ast.Ident:
			return packageLevelConst(info.Uses[e])
		case *ast.SelectorExpr:
			return packageLevelConst(info.Uses[e.Sel])
		}
		return nil
	}
}

func packageLevelConst(obj types.Object) *types.Const {
	c, ok := obj.(*types.Const)
	if !ok || c.Pkg() == nil || c.Parent() != c.Pkg().Scope() {
		return nil
	}
	if c.Val().Kind() != constant.Int && c.Val().Kind() != constant.Float {
		return nil
	}
	if constant.Sign(c.Val()) == 0 {
		return nil
	}
	return c
}

// calendarUnits are the numbers of one time unit in the next — a day-count
// convention (365, 360) or an hour, not an amount somebody decides on.
var calendarUnits = []int64{7, 12, 24, weeksPerYear, 60, 360, 365, 366, 3600, 86400}

// weeksPerYear converts weekly figures to yearly ones.
const weeksPerYear = 52

// isCalendarUnit reports whether v is one of calendarUnits.
func isCalendarUnit(v constant.Value) bool {
	n, exact := constant.Int64Val(constant.ToInt(v))
	return exact && constant.ToInt(v).Kind() == constant.Int && slices.Contains(calendarUnits, n)
}

// isPowerOfTen reports whether |v| is 1, 10, 100, ... or 0.1, 0.01, ...:
// such a constant converts units rather than setting an amount.
func isPowerOfTen(v constant.Value) bool {
	rat, ok := new(big.Rat).SetString(v.ExactString())
	if !ok || rat.Sign() == 0 {
		return false
	}
	num, den := new(big.Int).Abs(rat.Num()), rat.Denom()
	one := big.NewInt(1)
	return isIntPowerOfTen(num) && isIntPowerOfTen(den) && (num.Cmp(one) == 0 || den.Cmp(one) == 0)
}

func isIntPowerOfTen(n *big.Int) bool {
	ten := big.NewInt(10)
	rest, mod := new(big.Int).Set(n), new(big.Int)
	for rest.Cmp(ten) >= 0 {
		rest.QuoRem(rest, ten, mod)
		if mod.Sign() != 0 {
			return false
		}
	}
	return rest.Cmp(big.NewInt(1)) == 0
}

// shortPath names a file relative to the project root for a message; a file
// outside the root keeps its absolute path.
func shortPath(ctx *core.GoProjectContext, path string) string {
	return strings.TrimPrefix(path, ctx.ProjectRoot+string(filepath.Separator))
}
