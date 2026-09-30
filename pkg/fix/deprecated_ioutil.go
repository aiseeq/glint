package fix

import (
	"go/ast"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
)

// DeprecatedIoutilFixer fixes deprecated io/ioutil usage
type DeprecatedIoutilFixer struct{}

// NewDeprecatedIoutilFixer creates the fixer
func NewDeprecatedIoutilFixer() *DeprecatedIoutilFixer {
	return &DeprecatedIoutilFixer{}
}

// RuleName returns the rule name
func (f *DeprecatedIoutilFixer) RuleName() string {
	return "deprecated-ioutil"
}

// ioutilReplacementPackages are the packages a replacement may come from.
var ioutilReplacementPackages = map[string]bool{"io": true, "os": true}

// CanFix reports whether the rule named a drop-in replacement for the use it
// points to. The rule names none for ioutil.ReadDir: its replacement returns a
// different type, and the call sites would stop compiling.
func (f *DeprecatedIoutilFixer) CanFix(v *core.Violation) bool {
	if v == nil || v.Rule != "deprecated-ioutil" || v.Column < 1 {
		return false
	}
	_, _, ok := ioutilReplacement(v)
	return ok
}

// ioutilReplacement splits the replacement the rule named into its package and
// the full selector.
func ioutilReplacement(v *core.Violation) (pkg, replacement string, ok bool) {
	replacement, ok = v.Context["replacement"].(string)
	if !ok {
		return "", "", false
	}
	pkg, _, found := strings.Cut(replacement, ".")
	if !found || !ioutilReplacementPackages[pkg] {
		return "", "", false
	}
	return pkg, replacement, true
}

// GenerateFix replaces the ioutil selector the violation points to, adds the
// import of its replacement and drops io/ioutil once nothing uses it.
func (f *DeprecatedIoutilFixer) GenerateFix(ctx *core.FileContext, v *core.Violation) []*Fix {
	if ctx == nil || ctx.GoAST == nil || !f.CanFix(v) {
		return nil
	}
	pkg, replacement, _ := ioutilReplacement(v)
	if !canReferToPackage(ctx.GoAST, pkg) {
		return nil
	}

	var use *ast.SelectorExpr
	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		if use != nil {
			return false
		}
		selector, ok := n.(*ast.SelectorExpr)
		if ok && violationPosition(ctx, v, selector) {
			use = selector
			return false
		}
		return true
	})
	if use == nil || use.Sel.Name != v.Context["ioutil_function"] {
		return nil
	}

	fix, ok := nodeFix(ctx, use.Pos(), use.End(), replacement)
	if !ok {
		return nil
	}
	fix.Message = "Replace deprecated ioutil." + use.Sel.Name + " with " + replacement
	fix.RuleName = "deprecated-ioutil"
	fix.Violation = v
	fix.Imports = []string{pkg}
	fix.DropImports = []string{"io/ioutil"}
	return []*Fix{fix}
}

func init() {
	DefaultRegistry.Register(NewDeprecatedIoutilFixer())
}
