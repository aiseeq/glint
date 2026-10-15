package patterns

import (
	"go/ast"
	"go/token"
	"go/types"
	"slices"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewMapKeyBuiltByFormatRule())
}

// NewMapKeyBuiltByFormatRule creates map-key-built-by-format: a map with
// string keys is indexed by fmt.Sprintf or fmt.Sprint of comparable values,
// directly or through a function that only returns such a Sprintf (a
// Key() method). Every lookup formats, allocates and hashes a long string,
// while a struct of the same values is a map key as it is:
//
//	c.counts[fmt.Sprintf("%s:%s:%d", kind, name, n)]++
//	c.counts[Target{kind, name, n}]++ // map[Target]int; the string only for output
//
// A map is not reported when the program needs its strings: it is indexed
// anywhere by a key that is not formatted this way, or it is used whole -
// serialized, passed on, returned. A format with a precision (%.2f) merges
// keys a struct would keep apart and is not reported either. The finding is
// low in ordinary code and medium in a //glint:hot function.
func NewMapKeyBuiltByFormatRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"map-key-built-by-format",
			"patterns",
			"Detects a map indexed by fmt.Sprintf/fmt.Sprint of comparable values (directly or through a Key() method) — every lookup formats, allocates and hashes a string; a struct of the same fields is a map key as it is",
			core.SeverityLow,
		),
		suggestion: "Key the map by a struct of the formatted values (map[Target]int with Target{Kind, Name, N}) and format the string only for output",
	}
	r.severityOf = hotRaisesSeverity
	r.forProject = func(decls map[*types.Func]typedFuncDecl) func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		needsStrings := stringKeyedMapsInUse(decls)
		return func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
			var findings []funcFinding
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				index, ok := n.(*ast.IndexExpr)
				if !ok {
					return true
				}
				obj := stringMapObject(scope.info, index.X)
				if obj == nil || needsStrings[obj] {
					return true
				}
				if how, formatted := formattedKey(scope.info, decls, index.Index); formatted {
					findings = append(findings, funcFinding{node: index, message: "The map " + obj.Name() + " is keyed by " + how + " — every lookup formats, allocates and hashes a string; a struct of the same values is a key as it is"})
				}
				return true
			})
			return findings
		}
	}
	return r
}

// stringMapObject returns the variable or field a map with string keys is
// held in, nil for any other expression.
func stringMapObject(info *types.Info, expr ast.Expr) types.Object {
	t := info.TypeOf(expr)
	if t == nil {
		return nil
	}
	m, ok := t.Underlying().(*types.Map)
	if !ok {
		return nil
	}
	if key, isBasic := m.Key().Underlying().(*types.Basic); !isBasic || key.Info()&types.IsString == 0 {
		return nil
	}
	switch e := ast.Unparen(expr).(type) {
	case *ast.Ident:
		return info.Uses[e]
	case *ast.SelectorExpr:
		return info.Uses[e.Sel]
	}
	return nil
}

// stringKeyedMapsInUse returns the maps with string keys whose strings the
// program needs: indexed somewhere by a key that is not formatted from
// comparable values, or used whole other than by range, len, delete and an
// initialization.
func stringKeyedMapsInUse(decls map[*types.Func]typedFuncDecl) map[types.Object]bool {
	needs := map[types.Object]bool{}
	for _, decl := range decls {
		info := decl.info
		allowed := map[ast.Expr]bool{}
		ast.Inspect(decl.decl.Body, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.IndexExpr:
				if obj := stringMapObject(info, node.X); obj != nil {
					allowed[ast.Unparen(node.X)] = true
					if _, formatted := formattedKey(info, decls, node.Index); !formatted {
						needs[obj] = true
					}
				}
			case *ast.RangeStmt:
				allowed[ast.Unparen(node.X)] = true
			case *ast.CallExpr:
				switch builtinCallName(info, node) {
				case "len", "clear":
					allowed[ast.Unparen(node.Args[0])] = true
				case "delete":
					if obj := stringMapObject(info, node.Args[0]); obj != nil {
						allowed[ast.Unparen(node.Args[0])] = true
						if _, formatted := formattedKey(info, decls, node.Args[1]); !formatted {
							needs[obj] = true
						}
					}
				}
			case *ast.AssignStmt:
				for i, lhs := range node.Lhs {
					if i < len(node.Rhs) && freshMapValue(info, node.Rhs[i]) {
						allowed[ast.Unparen(lhs)] = true
					}
				}
			case *ast.KeyValueExpr:
				if freshMapValue(info, node.Value) {
					allowed[node.Key] = true
				}
			}
			return true
		})
		ast.Inspect(decl.decl.Body, func(n ast.Node) bool {
			expr, ok := n.(ast.Expr)
			if !ok || allowed[expr] {
				return !ok || !allowed[expr]
			}
			if obj := stringMapObject(info, expr); obj != nil {
				needs[obj] = true
				return false
			}
			return true
		})
	}
	return needs
}

// freshMapValue reports a new empty map: make or a literal.
func freshMapValue(info *types.Info, expr ast.Expr) bool {
	switch e := ast.Unparen(expr).(type) {
	case *ast.CompositeLit:
		return true
	case *ast.CallExpr:
		return builtinCallName(info, e) == "make"
	}
	return false
}

// formattedKey describes a key built by fmt.Sprintf or fmt.Sprint of values
// of basic types, directly or through a loaded function whose body only
// returns such a call.
func formattedKey(info *types.Info, decls map[*types.Func]typedFuncDecl, key ast.Expr) (string, bool) {
	call, ok := ast.Unparen(key).(*ast.CallExpr)
	if !ok {
		return "", false
	}
	if name, isFmt := packageFuncName(nil, info, call, "fmt"); isFmt {
		if (name == "Sprintf" || name == "Sprint") && formatOfComparables(info, call, name) {
			return "fmt." + name, true
		}
		return "", false
	}
	fn := staticFunc(info, call)
	if fn == nil {
		return "", false
	}
	decl, loaded := decls[fn.Origin()]
	if !loaded || len(decl.decl.Body.List) != 1 {
		return "", false
	}
	ret, isReturn := decl.decl.Body.List[0].(*ast.ReturnStmt)
	if !isReturn || len(ret.Results) != 1 {
		return "", false
	}
	inner, isCall := ast.Unparen(ret.Results[0]).(*ast.CallExpr)
	if !isCall {
		return "", false
	}
	name, isFmt := packageFuncName(nil, decl.info, inner, "fmt")
	if !isFmt || (name != "Sprintf" && name != "Sprint") || !formatOfComparables(decl.info, inner, name) {
		return "", false
	}
	return fn.Name() + "() (a fmt." + name + ")", true
}

// formatOfComparables reports a Sprintf or Sprint whose values are of basic
// types and whose format keeps them apart: a constant format without a
// precision (%.2f merges values) or a * width.
func formatOfComparables(info *types.Info, call *ast.CallExpr, name string) bool {
	args := call.Args
	if name == "Sprintf" {
		if len(args) < 2 {
			return false
		}
		format, isConst := stringConstant(info, args[0])
		if !isConst || slices.ContainsFunc(formatDirectives(format), func(d string) bool { return strings.ContainsAny(d, ".*") }) {
			return false
		}
		args = args[1:]
	}
	if len(args) == 0 || call.Ellipsis != token.NoPos {
		return false
	}
	for _, arg := range args {
		t := info.TypeOf(arg)
		if t == nil {
			return false
		}
		if _, basic := t.Underlying().(*types.Basic); !basic {
			return false
		}
	}
	return true
}
