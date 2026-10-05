package patterns

import (
	"errors"
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"golang.org/x/tools/go/types/typeutil"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewJSONShapeByFailedUnmarshalRule())
}

// JSONShapeByFailedUnmarshalRule detects a JSON value whose shape is told
// apart by a failed decode: json.Unmarshal into one type, and on failure the
// same raw value decoded again into another one.
//
//	if err := json.Unmarshal(raw, &rule); err != nil {
//		options, err := parseOptions(raw) // json.Unmarshal(raw, &options)
//		...
//	}
//
// The failure of the first decode says the value is not a valid instance of
// the first type - not that it is of the second. A malformed value of the
// first shape is reported as a broken second one, and a shape nobody
// expected passes as whatever the fallback makes of it. Decoded once into
// any (or json.RawMessage plus its first byte), the shape is a switch with
// an error for the unknown case.
type JSONShapeByFailedUnmarshalRule struct {
	*rules.BaseRule
}

// NewJSONShapeByFailedUnmarshalRule creates the rule
func NewJSONShapeByFailedUnmarshalRule() *JSONShapeByFailedUnmarshalRule {
	return &JSONShapeByFailedUnmarshalRule{BaseRule: rules.NewBaseRule(
		"json-shape-by-failed-unmarshal",
		"patterns",
		"Detects a JSON value decoded again into another type when a first json.Unmarshal of it fails — the failure is taken for the other shape, a malformed or unknown value passes as it",
		core.SeverityMedium,
	)}
}

// AnalyzeFile is a no-op: decoding helpers are followed across files.
func (r *JSONShapeByFailedUnmarshalRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *JSONShapeByFailedUnmarshalRule) RequiresSSA() bool { return false }

// AnalyzeGoProject reports the decodes whose failure picks another shape.
func (r *JSONShapeByFailedUnmarshalRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, errors.New("json shape by failed unmarshal: nil Go project context")
	}
	decoders := jsonDecodingFuncs(ctx)
	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(file *core.FileContext, info *types.Info) []*core.Violation {
		var violations []*core.Violation
		ast.Inspect(file.GoAST, func(n ast.Node) bool {
			block, ok := n.(*ast.BlockStmt)
			if !ok {
				return true
			}
			for i, stmt := range block.List {
				call, failure := checkedUnmarshal(file.GoAST, info, block.List, i, stmt)
				if call == nil || !decodesAgain(file.GoAST, info, decoders, failure, types.ExprString(call.Args[0])) || scalarChain(file.GoAST, info, call, failure) {
					continue
				}
				line := file.LineFor(call)
				if file.IsSuppressed(line, r.Name()) {
					continue
				}
				v := r.CreateViolation(file.RelPath, line,
					"A failure of this json.Unmarshal is taken for another shape, and the same value is decoded again — a malformed value of this shape is reported as the other one, an unknown shape passes as it")
				v.WithCode(strings.TrimSpace(file.GetLine(line)))
				v.WithSuggestion("Decode once into any (or look at the first byte of the json.RawMessage), switch on the shape, and return an error for a shape you do not expect")
				violations = append(violations, v)
			}
			return true
		})
		return violations
	})
}

// checkedUnmarshal returns the json.Unmarshal of a statement whose error the
// next branch tests, with the statements that run when it fails: the branch
// of `err != nil`, or what follows a branch of `err == nil` that returns.
func checkedUnmarshal(file *ast.File, info *types.Info, list []ast.Stmt, i int, stmt ast.Stmt) (*ast.CallExpr, []ast.Stmt) {
	var call *ast.CallExpr
	var check *ast.IfStmt
	if node, ok := stmt.(*ast.IfStmt); ok && node.Init != nil {
		call, check = stmtCall(node.Init), node
	} else if call = stmtCall(stmt); call != nil && i+1 < len(list) {
		check, _ = list[i+1].(*ast.IfStmt)
		if check != nil && check.Init != nil {
			check = nil
		}
	}
	if call == nil || check == nil || !isPackageFuncCall(file, info, call, "encoding/json", "Unmarshal") || len(call.Args) != 2 {
		return nil, nil
	}
	bin, ok := ast.Unparen(check.Cond).(*ast.BinaryExpr)
	if !ok || !isNilIdent(ast.Unparen(bin.Y)) {
		return nil, nil
	}
	if _, isIdent := ast.Unparen(bin.X).(*ast.Ident); !isIdent {
		return nil, nil
	}
	switch bin.Op {
	case token.NEQ:
		return call, check.Body.List
	case token.EQL:
		if !lastIsReturn(check.Body) {
			return nil, nil
		}
		var failure []ast.Stmt
		if elseBlock, ok := check.Else.(*ast.BlockStmt); ok {
			failure = append(failure, elseBlock.List...)
		}
		for j, s := range list {
			if s == check {
				failure = append(failure, list[j+1:]...)
			}
		}
		return call, failure
	}
	return nil, nil
}

// lastIsReturn reports a block ending in a return.
func lastIsReturn(body *ast.BlockStmt) bool {
	if len(body.List) == 0 {
		return false
	}
	_, ok := body.List[len(body.List)-1].(*ast.ReturnStmt)
	return ok
}

// decodesAgain reports statements decoding the raw value spelled raw again:
// json.Unmarshal(raw, ...) or a call handing raw to a function that decodes
// that parameter.
func decodesAgain(file *ast.File, info *types.Info, decoders map[*types.Func]map[int]bool, stmts []ast.Stmt, raw string) bool {
	found := false
	for _, stmt := range stmts {
		ast.Inspect(stmt, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || found {
				return !found
			}
			if isPackageFuncCall(file, info, call, "encoding/json", "Unmarshal") && len(call.Args) == 2 && types.ExprString(call.Args[0]) == raw {
				found = true
				return false
			}
			callee, ok := typeutil.Callee(info, call).(*types.Func)
			if !ok {
				return true
			}
			for index := range decoders[callee.Origin()] {
				if index < len(call.Args) && types.ExprString(call.Args[index]) == raw {
					found = true
				}
			}
			return !found
		})
	}
	return found
}

// jsonDecodingFuncs returns the project's functions that json.Unmarshal a
// parameter, with the indexes of those parameters.
func jsonDecodingFuncs(ctx *core.GoProjectContext) map[*types.Func]map[int]bool {
	decoders := make(map[*types.Func]map[int]bool)
	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil || pkg.Package.TypesInfo == nil {
			continue
		}
		info := pkg.Package.TypesInfo
		for _, file := range pkg.Package.Syntax {
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				obj, ok := info.Defs[fn.Name].(*types.Func)
				if !ok {
					continue
				}
				params := make(map[types.Object]int)
				index := 0
				for _, field := range fn.Type.Params.List {
					for _, name := range field.Names {
						params[info.Defs[name]] = index
						index++
					}
					if len(field.Names) == 0 {
						index++
					}
				}
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok || len(call.Args) != 2 || !isPackageFuncCall(file, info, call, "encoding/json", "Unmarshal") {
						return true
					}
					ident, ok := ast.Unparen(call.Args[0]).(*ast.Ident)
					if !ok {
						return true
					}
					if at, ok := params[info.Uses[ident]]; ok {
						if decoders[obj] == nil {
							decoders[obj] = make(map[int]bool)
						}
						decoders[obj][at] = true
					}
					return true
				})
			}
		}
	}
	return decoders
}

// scalarChain reports a decode into a scalar whose failure decodes the same
// value again, directly, into scalars only: a number sent quoted or bare.
// Neither target has fields whose error the other decode could hide.
func scalarChain(file *ast.File, info *types.Info, call *ast.CallExpr, failure []ast.Stmt) bool {
	if !scalarTarget(info, call.Args[1]) {
		return false
	}
	raw := types.ExprString(call.Args[0])
	again, scalar := false, true
	for _, stmt := range failure {
		ast.Inspect(stmt, func(n ast.Node) bool {
			next, ok := n.(*ast.CallExpr)
			if !ok || len(next.Args) != 2 || !isPackageFuncCall(file, info, next, "encoding/json", "Unmarshal") || types.ExprString(next.Args[0]) != raw {
				return true
			}
			again = true
			scalar = scalar && scalarTarget(info, next.Args[1])
			return true
		})
	}
	return again && scalar
}

// scalarTarget reports &x where x is a string, a number, a bool or a
// json.Number.
func scalarTarget(info *types.Info, target ast.Expr) bool {
	addr, ok := ast.Unparen(target).(*ast.UnaryExpr)
	if !ok || addr.Op != token.AND {
		return false
	}
	t := info.TypeOf(addr.X)
	if t == nil {
		return false
	}
	if isNamedType(t, "encoding/json", "Number") {
		return true
	}
	_, basic := t.Underlying().(*types.Basic)
	return basic
}
