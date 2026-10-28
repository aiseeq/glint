package concurrencyrules

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
)

func init() {
	rules.Register(NewSmallConstantMapInHotFunctionRule())
}

// smallMapMaxKeys is the most keys a map literal can have and still be a
// set of constants a switch spells out.
const smallMapMaxKeys = 8

// NewSmallConstantMapInHotFunctionRule creates
// small-constant-map-in-hot-function: a hot function reads a package-level
// map built from a literal of at most eight constant keys that nothing ever
// writes to. Every read hashes the key and probes the table, where a switch
// on the constants or an array indexed by a dense id answers without
// hashing:
//
//	var fastKinds = map[uint32]bool{KindA: true, KindB: true, KindC: true}
//	func isFast(t uint32) bool { return fastKinds[t] }
//	func isFast(t uint32) bool { switch t { case KindA, KindB, KindC: return true }; return false }
//
// Outside hot code such a map is the readable form and is not reported. A
// map written anywhere, passed somewhere or taken by address is a table the
// program fills and is not reported either.
func NewSmallConstantMapInHotFunctionRule() *hotFuncRule {
	return &hotFuncRule{
		BaseRule: rules.NewBaseRule(
			"small-constant-map-in-hot-function",
			"patterns",
			"Detects a //glint:hot function reading a package-level map literal of at most eight constant keys that nothing writes — every read hashes the key; a switch on the constants or an array by a dense id answers without hashing",
			core.SeverityLow,
		),
		suggestion: "Replace the lookup with a switch on the constants (case A, B, C: ...) or an array indexed by a dense id; keep the map where the code is not hot",
		forProject: func(ctx *core.GoProjectContext) (func(scope hotScope, fn *ast.FuncDecl) []patternkit.FuncFinding, error) {
			maps, err := smallConstantMaps(ctx)
			if err != nil {
				return nil, err
			}
			return func(scope hotScope, fn *ast.FuncDecl) []patternkit.FuncFinding {
				return smallMapReads(scope, fn, maps)
			}, nil
		},
	}
}

// smallMapReads returns the reads of a small constant map in a function body.
func smallMapReads(scope hotScope, fn *ast.FuncDecl, maps map[types.Object]int) []patternkit.FuncFinding {
	var findings []patternkit.FuncFinding
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		index, ok := n.(*ast.IndexExpr)
		if !ok {
			return true
		}
		ident, ok := ast.Unparen(index.X).(*ast.Ident)
		if !ok {
			return true
		}
		obj := scope.info.Uses[ident]
		if keys, small := maps[obj]; small {
			findings = append(findings, patternkit.FuncFinding{Node: index, Message: fmt.Sprintf("the map %s of %d constant keys is read with a hash lookup%s — a switch on the constants answers without hashing", ident.Name, keys, scope.in)})
		}
		return true
	})
	return findings
}

// smallConstantMapsKey caches the small constant maps once per module load.
type smallConstantMapsKey struct{}

// smallConstantMaps returns the package-level maps built from a literal of
// at most smallMapMaxKeys constant keys that the loaded code only reads -
// m[k], range m, len(m) - with their number of keys.
func smallConstantMaps(ctx *core.GoProjectContext) (map[types.Object]int, error) {
	return core.SharedLoad(ctx, smallConstantMapsKey{}, func() (map[types.Object]int, error) {
		maps := map[types.Object]int{}
		for _, pkg := range ctx.Packages {
			if pkg == nil || pkg.Package == nil || pkg.Package.TypesInfo == nil {
				return nil, fmt.Errorf("package has no typed syntax")
			}
			info := pkg.Package.TypesInfo
			for _, file := range pkg.Package.Syntax {
				for _, decl := range file.Decls {
					collectSmallMaps(info, decl, maps)
				}
			}
		}
		for _, pkg := range ctx.Packages {
			info := pkg.Package.TypesInfo
			for _, file := range pkg.Package.Syntax {
				dropWrittenMaps(info, file, maps)
			}
		}
		return maps, nil
	})
}

// collectSmallMaps adds the small constant map literals a package-level var
// declaration defines.
func collectSmallMaps(info *types.Info, decl ast.Decl, maps map[types.Object]int) {
	gen, ok := decl.(*ast.GenDecl)
	if !ok || gen.Tok != token.VAR {
		return
	}
	for _, spec := range gen.Specs {
		value, ok := spec.(*ast.ValueSpec)
		if !ok || len(value.Names) != len(value.Values) {
			continue
		}
		for i, name := range value.Names {
			lit, isLit := ast.Unparen(value.Values[i]).(*ast.CompositeLit)
			if !isLit || len(lit.Elts) == 0 || len(lit.Elts) > smallMapMaxKeys {
				continue
			}
			if _, isMap := info.TypeOf(lit).Underlying().(*types.Map); !isMap || !constantKeys(info, lit) {
				continue
			}
			if obj := info.Defs[name]; obj != nil {
				maps[obj] = len(lit.Elts)
			}
		}
	}
}

// constantKeys reports a map literal whose every key is a constant.
func constantKeys(info *types.Info, lit *ast.CompositeLit) bool {
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok || info.Types[kv.Key].Value == nil {
			return false
		}
	}
	return true
}

// dropWrittenMaps removes the maps a file uses other than by reading them:
// an assignment or increment of an element, an element's address, delete,
// clear, passing the map on, assigning it. A read is m[k], range m, len(m).
func dropWrittenMaps(info *types.Info, file *ast.File, maps map[types.Object]int) {
	written := map[ast.Expr]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			for _, lhs := range node.Lhs {
				written[ast.Unparen(lhs)] = true
			}
		case *ast.IncDecStmt:
			written[ast.Unparen(node.X)] = true
		case *ast.UnaryExpr:
			if node.Op == token.AND {
				written[ast.Unparen(node.X)] = true
			}
		}
		return true
	})
	reads := map[*ast.Ident]bool{}
	read := func(expr ast.Expr) {
		if ident, ok := ast.Unparen(expr).(*ast.Ident); ok {
			reads[ident] = true
		}
	}
	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.IndexExpr:
			if !written[node] {
				read(node.X)
			}
		case *ast.RangeStmt:
			read(node.X)
		case *ast.CallExpr:
			if patternkit.BuiltinCallName(info, node) == "len" && len(node.Args) == 1 {
				read(node.Args[0])
			}
		}
		return true
	})
	ast.Inspect(file, func(n ast.Node) bool {
		ident, ok := n.(*ast.Ident)
		if !ok {
			return true
		}
		obj := info.Uses[ident]
		if _, tracked := maps[obj]; tracked && !reads[ident] {
			delete(maps, obj)
		}
		return true
	})
}
