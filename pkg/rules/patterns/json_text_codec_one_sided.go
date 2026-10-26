package patterns

import (
	"fmt"
	"go/ast"
	"go/types"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewJSONTextCodecOneSidedRule())
}

// JSONTextCodecOneSidedRule detects a field of a type the code stores as
// JSON and reads back whose type has only one of the text methods:
//
//	type Duration time.Duration
//	func (d *Duration) UnmarshalText(b []byte) error { ... } // no MarshalText
//
//	type Trace struct {
//		Lifetime Duration `json:"lifetime"` // written as 3600000000000
//	}
//	json.Marshal(state)        // saved
//	json.Unmarshal(raw, state) // cannot unmarshal number into ... of type Duration
//
// encoding/json writes the value by its base kind and reads it as text (or
// the reverse), so what the program saved does not load back. A string base
// kind is left out: there both sides are a JSON string.
type JSONTextCodecOneSidedRule struct {
	*rules.BaseRule
}

// NewJSONTextCodecOneSidedRule creates the rule
func NewJSONTextCodecOneSidedRule() *JSONTextCodecOneSidedRule {
	return &JSONTextCodecOneSidedRule{BaseRule: rules.NewBaseRule(
		"json-text-codec-one-sided",
		"patterns",
		"Detects a field of a type the code both marshals and unmarshals as JSON whose type has UnmarshalText without MarshalText, or the reverse, and is not a string — JSON writes it by its base kind and reads it as text, so the stored value does not load back",
		core.SeverityHigh,
	)}
}

// AnalyzeFile is a no-op: the check needs every package's types.
func (r *JSONTextCodecOneSidedRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough.
func (r *JSONTextCodecOneSidedRule) RequiresSSA() bool { return false }

// AnalyzeGoProject reports the one-sided fields of the round-tripped types.
func (r *JSONTextCodecOneSidedRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%s: nil Go project context", r.Name())
	}
	trip := jsonRoundTrip{marshalled: map[*types.TypeName]bool{}, unmarshalled: map[*types.TypeName]bool{}}
	eachProductionGoFile(ctx, func(info *types.Info, file *ast.File) {
		ast.Inspect(file, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				trip.jsonCall(info, call, map[*types.TypeName]bool{})
			}
			return true
		})
	})
	return trip.analyzeStructs(ctx, r.Name(), func(file *core.FileContext, info *types.Info, name *types.TypeName, st *ast.StructType) []*core.Violation {
		var violations []*core.Violation
		for _, field := range st.Fields.List {
			if field.Tag != nil && jsonIgnored(strings.Trim(field.Tag.Value, "`")) {
				continue
			}
			for _, ident := range field.Names {
				v, ok := info.Defs[ident].(*types.Var)
				if !ok || !v.Exported() {
					continue
				}
				named, has, lacks := oneSidedTextCodec(v.Type())
				if named == nil {
					continue
				}
				line := file.LineFor(ident)
				if file.IsSuppressed(line, r.Name()) {
					continue
				}
				violation := r.CreateViolation(file.RelPath, line, fmt.Sprintf(
					"%s of %s has %s without %s, and %s is stored as JSON and read back — JSON writes it by its base kind %s on one side and as text on the other, so the stored value does not load",
					ident.Name, named.Obj().Name(), has, lacks, name.Name(), named.Underlying()))
				violation.WithCode(strings.TrimSpace(file.GetLine(line)))
				violation.WithSuggestion("Add " + lacks + " to " + named.Obj().Name() + " so both sides use the same text, or store the field as its base type")
				violations = append(violations, violation)
			}
		}
		return violations
	})
}

// oneSidedTextCodec returns the named type a field of type typ carries
// (through pointers, slices, arrays and map values) when JSON reads it as
// text but writes it by its kind, or the reverse: it has one text method
// and neither JSON method, and is not a string.
func oneSidedTextCodec(typ types.Type) (named *types.Named, has, lacks string) {
	for {
		switch t := typ.(type) {
		case *types.Pointer:
			typ = t.Elem()
			continue
		case *types.Slice:
			typ = t.Elem()
			continue
		case *types.Array:
			typ = t.Elem()
			continue
		case *types.Map:
			typ = t.Elem()
			continue
		}
		break
	}
	named, ok := typ.(*types.Named)
	if !ok {
		return nil, "", ""
	}
	if basic, ok := named.Underlying().(*types.Basic); ok && basic.Info()&types.IsString != 0 {
		return nil, "", ""
	}
	if _, ok := named.Underlying().(*types.Interface); ok {
		return nil, "", ""
	}
	methods := types.NewMethodSet(types.NewPointer(named))
	method := func(name string) bool { return methods.Lookup(nil, name) != nil }
	if method("MarshalJSON") || method("UnmarshalJSON") {
		return nil, "", ""
	}
	switch marshal, unmarshal := method("MarshalText"), method("UnmarshalText"); {
	case unmarshal && !marshal:
		return named, "UnmarshalText", "MarshalText"
	case marshal && !unmarshal:
		return named, "MarshalText", "UnmarshalText"
	}
	return nil, "", ""
}
