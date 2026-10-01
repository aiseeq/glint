package patterns

import (
	"go/ast"
	"go/types"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewDecimalMarshalRoundsRule())
}

// DecimalMarshalRoundsRule detects a decimal type whose serialization rounds
// the value:
//
//	type Amount struct{ decimal.Decimal }
//
//	func (a Amount) MarshalJSON() ([]byte, error) {
//	    return json.Marshal(a.StringFixed(6))
//	}
//
// Every value of the type crosses the API, the database or a file through
// this method, so every one of them loses what lies past the sixth digit:
// 0.0000096770512613 of a token becomes 0.000010, and the client sends the
// rounded amount back. Fixed places are a display format; the wire carries
// the exact value (String) and the screen rounds it. A precision the value
// carries itself (a.StringFixed(a.places)) is its own scale and is not
// reported.
type DecimalMarshalRoundsRule struct {
	*rules.BaseRule
}

// NewDecimalMarshalRoundsRule creates the rule
func NewDecimalMarshalRoundsRule() *DecimalMarshalRoundsRule {
	return &DecimalMarshalRoundsRule{BaseRule: rules.NewBaseRule(
		"decimal-marshal-rounds",
		"patterns",
		"Detects MarshalJSON/MarshalText/Value of a decimal type that rounds the value (StringFixed, Round, Truncate) — every serialized amount loses digits",
		core.SeverityHigh,
	)}
}

// AnalyzeFile is a no-op: the receiver's type decides.
func (r *DecimalMarshalRoundsRule) AnalyzeFile(_ *core.FileContext) []*core.Violation { return nil }

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *DecimalMarshalRoundsRule) RequiresSSA() bool { return false }

// serializingMethods are the methods through which a value leaves the
// program.
var serializingMethods = map[string]bool{
	"MarshalJSON": true, "MarshalText": true, "MarshalYAML": true, "MarshalBinary": true, "Value": true,
}

// roundingMethods are the decimal methods that drop digits.
var roundingMethods = map[string]bool{
	"StringFixed": true, "StringFixedBank": true, "StringFixedCash": true,
	"Round": true, "RoundBank": true, "RoundCash": true, "RoundUp": true, "RoundDown": true,
	"RoundCeil": true, "RoundFloor": true, "Truncate": true, "Ceil": true, "Floor": true,
}

// AnalyzeGoProject reports the rounding calls in the serializing methods of
// decimal types.
func (r *DecimalMarshalRoundsRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(file *core.FileContext, info *types.Info) []*core.Violation {
		if file.IsTestFile() {
			return nil
		}
		var violations []*core.Violation
		for _, decl := range file.GoAST.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || fn.Recv == nil || len(fn.Recv.List) != 1 || !serializingMethods[fn.Name.Name] {
				continue
			}
			if fn.Type.Params != nil && len(fn.Type.Params.List) > 0 {
				continue
			}
			receiver := namedOf(info.TypeOf(fn.Recv.List[0].Type))
			if receiver == nil || !decimalWrapper(receiver) {
				continue
			}
			var receiverObj types.Object
			if names := fn.Recv.List[0].Names; len(names) == 1 {
				receiverObj = info.Defs[names[0]]
			}
			reported := make(map[int]bool)
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || !roundingMethods[sel.Sel.Name] {
					return true
				}
				operand := info.TypeOf(sel.X)
				if !isShopspringDecimalType(operand) && namedOf(operand) != receiver {
					return true
				}
				if ownPrecision(info, call.Args, receiverObj) {
					return true
				}
				line := file.LineFor(call)
				if reported[line] || file.IsSuppressed(line, r.Name()) {
					return true
				}
				reported[line] = true
				v := r.CreateViolation(file.RelPath, line, receiver.Obj().Name()+"."+fn.Name.Name+" rounds the value with "+sel.Sel.Name+" — every amount of the type loses its digits past the fixed places on the way out, and comes back rounded")
				v.WithCode(strings.TrimSpace(file.GetLine(line)))
				v.WithSuggestion("Serialize the exact value (String()), and round where the value is displayed")
				violations = append(violations, v)
				return true
			})
		}
		return violations
	})
}

// decimalWrapper reports a struct that is a decimal value: it embeds
// decimal.Decimal, or holds one decimal field beside nothing but numbers and
// flags (a scale, a Valid bit).
func decimalWrapper(named *types.Named) bool {
	st, ok := named.Underlying().(*types.Struct)
	if !ok {
		return false
	}
	decimals := 0
	for i := range st.NumFields() {
		field := st.Field(i)
		if isShopspringDecimalType(field.Type()) {
			if field.Embedded() {
				return true
			}
			decimals++
			continue
		}
		basic, ok := field.Type().Underlying().(*types.Basic)
		if !ok || basic.Info()&(types.IsNumeric|types.IsBoolean) == 0 {
			return false
		}
	}
	return decimals == 1
}

// ownPrecision reports a rounding to places the value carries itself: an
// argument reading a field of the receiver.
func ownPrecision(info *types.Info, args []ast.Expr, receiver types.Object) bool {
	if receiver == nil {
		return false
	}
	for _, arg := range args {
		found := false
		ast.Inspect(arg, func(n ast.Node) bool {
			if ident, ok := n.(*ast.Ident); ok && info.Uses[ident] == receiver {
				found = true
			}
			return !found
		})
		if found {
			return true
		}
	}
	return false
}
