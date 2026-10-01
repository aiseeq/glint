package patterns

import (
	"errors"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewZeroThresholdNotHonoredRule())
}

// ZeroThresholdNotHonoredRule detects a threshold configured as 0 that a
// check compares against without asking whether it is 0:
//
//	"mail": {Inactivity: 0},                                // inactivity does not apply
//	if now.Sub(s.LastSuccess) <= t.Inactivity { return }   // ...but every pause exceeds 0
//	s.Warning = true
//
// Zero is the "off" of a duration threshold, and the code that set it meant
// that; the comparison reads it as "warn after no time at all". The field is
// judged when it is a duration, or when a sibling field of the same struct is
// already checked for 0 elsewhere — the struct's own convention.
type ZeroThresholdNotHonoredRule struct {
	*rules.BaseRule
}

// NewZeroThresholdNotHonoredRule creates the rule
func NewZeroThresholdNotHonoredRule() *ZeroThresholdNotHonoredRule {
	return &ZeroThresholdNotHonoredRule{BaseRule: rules.NewBaseRule(
		"zero-threshold-not-honored",
		"patterns",
		"Detects a threshold configured as 0 (off) compared against without a zero check — every value exceeds it and the check fires constantly",
		core.SeverityMedium,
	)}
}

// AnalyzeFile is a no-op: the zero may be set in any file.
func (r *ZeroThresholdNotHonoredRule) AnalyzeFile(_ *core.FileContext) []*core.Violation { return nil }

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *ZeroThresholdNotHonoredRule) RequiresSSA() bool { return false }

// zeroThresholds is what the whole project says about threshold fields.
type zeroThresholds struct {
	// setZero are the fields some literal sets to 0 explicitly.
	setZero map[*types.Var]bool
	// guardedStructs are the struct types with a field checked for 0.
	guardedStructs map[*types.Named]bool
}

// AnalyzeGoProject reports the comparisons against a zero-able threshold.
func (r *ZeroThresholdNotHonoredRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, errors.New("zero threshold: nil Go project context")
	}
	known := zeroThresholds{setZero: make(map[*types.Var]bool), guardedStructs: make(map[*types.Named]bool)}
	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil || pkg.Package.TypesInfo == nil {
			continue
		}
		for _, file := range pkg.Files {
			if file.GoAST != nil && !file.IsTestFile() {
				known.collect(file.GoAST, pkg.Package.TypesInfo)
			}
		}
	}
	if len(known.setZero) == 0 {
		return nil, nil
	}
	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(file *core.FileContext, info *types.Info) []*core.Violation {
		var violations []*core.Violation
		for _, decl := range file.GoAST.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			guarded := zeroGuardedFields(fn.Body, info)
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				cmp, ok := n.(*ast.BinaryExpr)
				if !ok || !thresholdOrderedOp(cmp.Op) {
					return true
				}
				field, ok := known.threshold(cmp, info)
				if !ok || guarded[field] {
					return true
				}
				line := file.LineFor(cmp)
				if file.IsSuppressed(line, r.Name()) {
					return true
				}
				v := r.CreateViolation(file.RelPath, line, "Threshold "+field.Name()+" is configured as 0 somewhere, and this comparison does not check for it — every value exceeds 0 and the check fires constantly")
				v.WithCode(strings.TrimSpace(file.GetLine(line)))
				v.WithSuggestion("Return early when the threshold is 0 (off), as the sibling checks do, or reject 0 when the configuration is loaded")
				violations = append(violations, v)
				return true
			})
		}
		return violations
	})
}

// collect records the fields set to 0 in literals and the structs whose
// fields are checked for 0.
func (z zeroThresholds) collect(file *ast.File, info *types.Info) {
	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.KeyValueExpr:
			key, ok := node.Key.(*ast.Ident)
			if !ok || !isNumericZero(node.Value, info) {
				return true
			}
			if field, ok := info.ObjectOf(key).(*types.Var); ok && field.IsField() {
				z.setZero[field] = true
			}
		case *ast.BinaryExpr:
			if sel := zeroComparedSelector(node, info); sel != nil {
				if named := thresholdStruct(info.TypeOf(sel.X)); named != nil {
					z.guardedStructs[named] = true
				}
			}
		}
		return true
	})
}

// threshold returns the zero-able threshold field one side of an ordered
// comparison reads, when the other side is not a constant.
func (z zeroThresholds) threshold(cmp *ast.BinaryExpr, info *types.Info) (*types.Var, bool) {
	for _, pair := range [][2]ast.Expr{{cmp.X, cmp.Y}, {cmp.Y, cmp.X}} {
		sel, ok := ast.Unparen(pair[0]).(*ast.SelectorExpr)
		if !ok || info.Types[pair[1]].Value != nil {
			continue
		}
		field, ok := info.ObjectOf(sel.Sel).(*types.Var)
		if !ok || !field.IsField() || !z.setZero[field] {
			continue
		}
		if other, ok := ast.Unparen(pair[1]).(*ast.SelectorExpr); ok && info.ObjectOf(other.Sel) == field {
			continue // two values of the field ordered, as a sort does: no threshold
		}
		if thresholdIsDuration(field.Type()) || z.guardedStructs[thresholdStruct(info.TypeOf(sel.X))] {
			return field, true
		}
	}
	return nil, false
}

// zeroGuardedFields returns the fields a body compares with 0.
func zeroGuardedFields(body *ast.BlockStmt, info *types.Info) map[*types.Var]bool {
	guarded := make(map[*types.Var]bool)
	ast.Inspect(body, func(n ast.Node) bool {
		cmp, ok := n.(*ast.BinaryExpr)
		if !ok {
			return true
		}
		if sel := zeroComparedSelector(cmp, info); sel != nil {
			if field, ok := info.ObjectOf(sel.Sel).(*types.Var); ok {
				guarded[field] = true
			}
		}
		return true
	})
	return guarded
}

// zeroComparedSelector returns the field selector a comparison holds
// against the constant 0.
func zeroComparedSelector(cmp *ast.BinaryExpr, info *types.Info) *ast.SelectorExpr {
	if !isComparisonOp(cmp.Op) {
		return nil
	}
	for _, pair := range [][2]ast.Expr{{cmp.X, cmp.Y}, {cmp.Y, cmp.X}} {
		sel, ok := ast.Unparen(pair[0]).(*ast.SelectorExpr)
		if ok && isNumericZero(pair[1], info) {
			return sel
		}
	}
	return nil
}

func thresholdOrderedOp(op token.Token) bool {
	return op == token.LSS || op == token.LEQ || op == token.GTR || op == token.GEQ
}

func isNumericZero(expr ast.Expr, info *types.Info) bool {
	tv, ok := info.Types[expr]
	if !ok || tv.Value == nil {
		return false
	}
	switch tv.Value.Kind() {
	case constant.Int, constant.Float:
		return constant.Sign(tv.Value) == 0
	}
	return false
}

func thresholdIsDuration(t types.Type) bool {
	named, ok := types.Unalias(t).(*types.Named)
	return ok && named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == "time" && named.Obj().Name() == "Duration"
}

// thresholdStruct returns the named struct type behind a value or a pointer.
func thresholdStruct(t types.Type) *types.Named {
	if t == nil {
		return nil
	}
	if ptr, ok := t.(*types.Pointer); ok {
		t = ptr.Elem()
	}
	named, ok := types.Unalias(t).(*types.Named)
	if !ok {
		return nil
	}
	if _, ok := named.Underlying().(*types.Struct); !ok {
		return nil
	}
	return named
}
