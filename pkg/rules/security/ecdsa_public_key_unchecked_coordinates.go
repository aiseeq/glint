package security

import (
	"go/ast"
	"go/types"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewECDSAPublicKeyUncheckedCoordinatesRule())
}

// ECDSAPublicKeyUncheckedCoordinatesRule detects ECDSA public keys built from unvalidated byte coordinates.
type ECDSAPublicKeyUncheckedCoordinatesRule struct {
	*rules.BaseRule
}

// NewECDSAPublicKeyUncheckedCoordinatesRule creates the rule.
func NewECDSAPublicKeyUncheckedCoordinatesRule() *ECDSAPublicKeyUncheckedCoordinatesRule {
	return &ECDSAPublicKeyUncheckedCoordinatesRule{BaseRule: rules.NewBaseRule(
		"ecdsa-public-key-from-unchecked-coordinates",
		"security",
		"Detects ECDSA public keys built from byte coordinates without validating the point",
		core.SeverityHigh,
	)}
}

// AnalyzeFile is a no-op because this rule needs type information.
func (r *ECDSAPublicKeyUncheckedCoordinatesRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that type information is enough for this rule.
func (r *ECDSAPublicKeyUncheckedCoordinatesRule) RequiresSSA() bool { return false }

// AnalyzeGoProject reports unvalidated ECDSA public key coordinates.
func (r *ECDSAPublicKeyUncheckedCoordinatesRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(file *core.FileContext, info *types.Info) []*core.Violation {
		if file.IsTestFile() {
			return nil
		}
		var violations []*core.Violation
		for _, decl := range file.GoAST.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			unchecked := make(map[types.Object]bool)
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				switch node := n.(type) {
				case *ast.AssignStmt:
					for i, lhs := range node.Lhs {
						id, ok := lhs.(*ast.Ident)
						if ok && i < len(node.Rhs) {
							if obj := info.ObjectOf(id); obj != nil {
								unchecked[obj] = isBigIntSetBytes(node.Rhs[i], info)
							}
						}
					}
				case *ast.ValueSpec:
					for i, name := range node.Names {
						if i < len(node.Values) {
							if obj := info.ObjectOf(name); obj != nil {
								unchecked[obj] = isBigIntSetBytes(node.Values[i], info)
							}
						}
					}
				}
				return true
			})
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				lit, ok := n.(*ast.CompositeLit)
				if !ok || !isECDSAPublicKey(lit, info) || !hasUncheckedCoordinates(lit, unchecked, info) || hasECDSAPointValidation(fn.Body, lit, unchecked, info) {
					return true
				}
				line := file.LineFor(lit)
				if file.IsSuppressed(line, r.Name()) {
					return true
				}
				v := r.CreateViolation(file.RelPath, line,
					"ECDSA public key coordinates built from bytes are used without checking that the point belongs to the curve")
				v.WithCode(strings.TrimSpace(file.GetLine(line)))
				v.WithSuggestion("Validate the coordinate lengths and parse the uncompressed point with ecdsa.ParseUncompressedPublicKey, or check Curve.IsOnCurve before using it")
				violations = append(violations, v)
				return true
			})
		}
		return violations
	})
}

func isECDSAPublicKey(lit *ast.CompositeLit, info *types.Info) bool {
	t := info.TypeOf(lit.Type)
	if ptr, ok := t.(*types.Pointer); ok {
		t = ptr.Elem()
	}
	named, ok := t.(*types.Named)
	return ok && named.Obj().Name() == "PublicKey" && named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == "crypto/ecdsa"
}

func isBigIntSetBytes(expr ast.Expr, info *types.Info) bool {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "SetBytes" {
		return false
	}
	selection := info.Selections[sel]
	if selection == nil {
		return false
	}
	fn, ok := selection.Obj().(*types.Func)
	if !ok || fn.Pkg() == nil || fn.Pkg().Path() != "math/big" {
		return false
	}
	return fn.Name() == "SetBytes"
}

func hasUncheckedCoordinates(lit *ast.CompositeLit, unchecked map[types.Object]bool, info *types.Info) bool {
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok || key.Name != "X" && key.Name != "Y" {
			continue
		}
		if isBigIntSetBytes(kv.Value, info) {
			return true
		}
		if id, ok := kv.Value.(*ast.Ident); ok && unchecked[info.ObjectOf(id)] {
			return true
		}
	}
	return false
}

func hasECDSAPointValidation(body *ast.BlockStmt, lit *ast.CompositeLit, unchecked map[types.Object]bool, info *types.Info) bool {
	coordinates := make(map[types.Object]bool, 2)
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok || key.Name != "X" && key.Name != "Y" {
			continue
		}
		id, ok := kv.Value.(*ast.Ident)
		if ok && unchecked[info.ObjectOf(id)] {
			coordinates[info.ObjectOf(id)] = true
		}
	}
	if len(coordinates) != 2 {
		return false
	}
	validates := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "IsOnCurve" {
			return true
		}
		matched := make(map[types.Object]bool, 2)
		for _, arg := range call.Args {
			id, ok := arg.(*ast.Ident)
			if ok && coordinates[info.ObjectOf(id)] {
				matched[info.ObjectOf(id)] = true
			}
		}
		if len(matched) == len(coordinates) {
			validates = true
			return false
		}
		return true
	})
	return validates
}
