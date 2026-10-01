package patterns

import (
	"cmp"
	"errors"
	"go/token"
	"go/types"
	"maps"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewOptionalInterfaceUnsatisfiedRule())
}

// OptionalInterfaceUnsatisfiedRule detects an assertion of a value to an
// optional interface that none of the types the value can hold has:
//
//	type batchMembers interface { GetMembers(ids []string) (map[string]*Member, error) }
//
//	repo := s.repos.Members()                 // always the adapter
//	if batch, ok := repo.(batchMembers); ok { // the adapter has no GetMembers
//		... one query ...
//	} else {
//		... one query per id ...
//	}
//
// The fast branch never runs and the slow one serves every call. The types
// the value can hold are followed back through the program (SSA): calls,
// the implementations an interface call reaches, struct fields and globals
// by their stores, parameters by their call sites, phis, conversions. The
// assertion is reported only when every source is known, at least one
// concrete type arrives, and none of them satisfies the asserted interface;
// an unknown source (a func value, a map, a channel, a parameter of a
// function passed around) leaves the assertion alone. Only values of
// interfaces declared in the project are judged: io.Writer and the like are
// implemented outside it.
type OptionalInterfaceUnsatisfiedRule struct {
	*rules.BaseRule
}

// NewOptionalInterfaceUnsatisfiedRule creates the rule
func NewOptionalInterfaceUnsatisfiedRule() *OptionalInterfaceUnsatisfiedRule {
	return &OptionalInterfaceUnsatisfiedRule{BaseRule: rules.NewBaseRule(
		"optional-interface-unsatisfied",
		"patterns",
		"Detects an assertion to an optional interface that no type the value can hold has — the branch never runs",
		core.SeverityMedium,
	)}
}

// AnalyzeFile is a no-op: the value's sources live in any package.
func (r *OptionalInterfaceUnsatisfiedRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that the value's sources are followed through SSA.
func (r *OptionalInterfaceUnsatisfiedRule) RequiresSSA() bool { return true }

// AnalyzeGoProject reports the assertions no held type can satisfy.
func (r *OptionalInterfaceUnsatisfiedRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, errors.New("optional interface unsatisfied: nil Go project context")
	}
	if ctx.Program == nil {
		if len(ctx.Packages) == 0 {
			return nil, nil
		}
		return nil, errors.New("optional interface unsatisfied: Go project has no SSA program")
	}
	project := make(map[*types.Package]bool)
	for _, pkg := range ctx.Packages {
		if pkg != nil && pkg.Package != nil {
			project[pkg.Package.Types] = true
		}
	}
	flow := newValueFlow(ctx.Program)
	// The assertions that never succeed, by file and line, with the
	// interface asserted.
	never := make(map[string]map[int]types.Type)
	for _, fn := range flow.functions {
		if fn.Pkg == nil || !project[fn.Pkg.Pkg] {
			continue
		}
		for _, block := range fn.Blocks {
			for _, instr := range block.Instrs {
				assert, ok := instr.(*ssa.TypeAssert)
				if !ok || !assert.Pos().IsValid() || !project[declaringPackage(assert.X.Type())] || !flow.never(assert) {
					continue
				}
				position := ctx.FileSet.PositionFor(assert.Pos(), false)
				path := filepath.Clean(position.Filename)
				if never[path] == nil {
					never[path] = make(map[int]types.Type)
				}
				never[path][position.Line] = assert.AssertedType
			}
		}
	}
	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(file *core.FileContext, _ *types.Info) []*core.Violation {
		lines := never[filepath.Clean(file.Path)]
		var violations []*core.Violation
		for _, line := range slices.Sorted(maps.Keys(lines)) {
			if file.IsSuppressed(line, r.Name()) {
				continue
			}
			v := r.CreateViolation(file.RelPath, line,
				"No type this value can hold implements "+typeName(lines[line])+" — the assertion always fails and its branch never runs")
			v.WithCode(strings.TrimSpace(file.GetLine(line)))
			v.WithSuggestion("Add the method to the type the value holds (a wrapper forwarding to the inner type), or drop the optional branch")
			violations = append(violations, v)
		}
		return violations
	})
}

// declaringPackage returns the package declaring a named interface type,
// nil for anything else.
func declaringPackage(t types.Type) *types.Package {
	named, ok := types.Unalias(t).(*types.Named)
	if !ok {
		return nil
	}
	if iface, ok := named.Underlying().(*types.Interface); !ok || iface.NumMethods() == 0 {
		return nil
	}
	return named.Obj().Pkg()
}

// valueFlow follows an interface value back to the concrete types that can
// arrive in it.
type valueFlow struct {
	prog      *ssa.Program
	functions []*ssa.Function
	fields    map[fieldSlot][]ssa.Value
	globals   map[*ssa.Global][]ssa.Value
	sites     map[*ssa.Function][]*ssa.CallCommon
	// escaped are functions used as values: their callers are not all known.
	escaped map[*ssa.Function]bool
	// invoked are the method names some interface call reaches.
	invoked map[string]bool
	memo    map[ssa.Value]heldTypes
	busy    map[ssa.Value]bool
	// cycles counts the returns into a value still being followed: a
	// result reached through one is partial and is not remembered.
	cycles int
}

// fieldSlot is a field of a struct type.
type fieldSlot struct {
	strct *types.Struct
	index int
}

// heldTypes are the concrete types a value can hold; known is false when
// some source cannot be followed.
type heldTypes struct {
	types []types.Type
	known bool
}

const maxFlowDepth = 30

func newValueFlow(prog *ssa.Program) *valueFlow {
	flow := &valueFlow{
		prog:    prog,
		fields:  make(map[fieldSlot][]ssa.Value),
		globals: make(map[*ssa.Global][]ssa.Value),
		sites:   make(map[*ssa.Function][]*ssa.CallCommon),
		escaped: make(map[*ssa.Function]bool),
		invoked: make(map[string]bool),
		memo:    make(map[ssa.Value]heldTypes),
		busy:    make(map[ssa.Value]bool),
	}
	for fn := range ssautil.AllFunctions(prog) {
		flow.functions = append(flow.functions, fn)
	}
	slices.SortFunc(flow.functions, func(a, b *ssa.Function) int { return cmp.Compare(a.Pos(), b.Pos()) })
	for _, fn := range flow.functions {
		for _, block := range fn.Blocks {
			for _, instr := range block.Instrs {
				flow.index(instr)
			}
		}
	}
	return flow
}

// index records what one instruction stores and calls.
func (f *valueFlow) index(instr ssa.Instruction) {
	if store, ok := instr.(*ssa.Store); ok {
		switch addr := store.Addr.(type) {
		case *ssa.FieldAddr:
			if slot, ok := slotOf(addr.X.Type(), addr.Field); ok {
				f.fields[slot] = append(f.fields[slot], store.Val)
			}
		case *ssa.Global:
			f.globals[addr] = append(f.globals[addr], store.Val)
		}
	}
	var common *ssa.CallCommon
	if call, ok := instr.(ssa.CallInstruction); ok {
		common = call.Common()
		switch {
		case common.IsInvoke():
			f.invoked[common.Method.Name()] = true
		case common.StaticCallee() != nil:
			f.sites[common.StaticCallee()] = append(f.sites[common.StaticCallee()], common)
		}
	}
	for _, operand := range instr.Operands(nil) {
		fn, ok := (*operand).(*ssa.Function)
		if !ok || (common != nil && *operand == common.Value) {
			continue
		}
		f.escaped[fn] = true
	}
}

// slotOf names the field of a struct or of a pointer to one.
func slotOf(t types.Type, index int) (fieldSlot, bool) {
	if ptr, ok := t.Underlying().(*types.Pointer); ok {
		t = ptr.Elem()
	}
	strct, ok := t.Underlying().(*types.Struct)
	return fieldSlot{strct: strct, index: index}, ok
}

// never reports an assertion to an interface that no type the value can
// hold satisfies.
func (f *valueFlow) never(assert *ssa.TypeAssert) bool {
	target, ok := assert.AssertedType.Underlying().(*types.Interface)
	if !ok || target.NumMethods() == 0 || types.Implements(assert.X.Type(), target) {
		return false
	}
	held := f.held(assert.X, 0)
	if !held.known || len(held.types) == 0 {
		return false
	}
	for _, concrete := range held.types {
		if types.Implements(concrete, target) {
			return false
		}
	}
	return true
}

func unknownTypes() heldTypes { return heldTypes{} }

func (h heldTypes) join(other heldTypes) heldTypes {
	return heldTypes{types: append(h.types, other.types...), known: h.known && other.known}
}

// held returns the concrete types that can arrive in a value.
func (f *valueFlow) held(v ssa.Value, depth int) heldTypes {
	if result, ok := f.memo[v]; ok {
		return result
	}
	if f.busy[v] {
		f.cycles++
		return heldTypes{known: true} // the value's other sources add its types
	}
	if depth > maxFlowDepth {
		return unknownTypes()
	}
	f.busy[v] = true
	cycles := f.cycles
	result := f.sources(v, depth+1)
	delete(f.busy, v)
	if f.cycles == cycles {
		f.memo[v] = result
	}
	return result
}

func (f *valueFlow) sources(v ssa.Value, depth int) heldTypes {
	switch value := v.(type) {
	case *ssa.MakeInterface:
		return heldTypes{types: []types.Type{value.X.Type()}, known: true}
	case *ssa.ChangeInterface:
		return f.held(value.X, depth)
	case *ssa.TypeAssert:
		return f.held(value.X, depth)
	case *ssa.Const:
		return heldTypes{known: value.IsNil()}
	case *ssa.Phi:
		result := heldTypes{known: true}
		for _, edge := range value.Edges {
			result = result.join(f.held(edge, depth))
		}
		return result
	case *ssa.UnOp:
		if value.Op != token.MUL {
			return unknownTypes()
		}
		switch addr := value.X.(type) {
		case *ssa.FieldAddr:
			if slot, ok := slotOf(addr.X.Type(), addr.Field); ok {
				return f.all(f.fields[slot], depth)
			}
		case *ssa.Global:
			return f.all(f.globals[addr], depth)
		}
		return unknownTypes()
	case *ssa.Field:
		if slot, ok := slotOf(value.X.Type(), value.Field); ok {
			return f.all(f.fields[slot], depth)
		}
		return unknownTypes()
	case *ssa.Call:
		return f.results(value.Common(), -1, depth)
	case *ssa.Extract:
		switch tuple := value.Tuple.(type) {
		case *ssa.Call:
			return f.results(tuple.Common(), value.Index, depth)
		case *ssa.TypeAssert:
			if value.Index == 0 {
				return f.held(tuple.X, depth)
			}
		}
		return unknownTypes()
	case *ssa.Parameter:
		return f.arguments(value, depth)
	}
	return unknownTypes()
}

func (f *valueFlow) all(values []ssa.Value, depth int) heldTypes {
	result := heldTypes{known: true}
	for _, value := range values {
		result = result.join(f.held(value, depth))
	}
	return result
}

// results follows the values a call returns (the index-th of a tuple, or
// the only one): a static callee's returns, or the returns of every method
// an interface call can reach.
func (f *valueFlow) results(common *ssa.CallCommon, index, depth int) heldTypes {
	var callees []*ssa.Function
	switch {
	case common.IsInvoke():
		receivers := f.held(common.Value, depth)
		if !receivers.known {
			return unknownTypes()
		}
		for _, concrete := range receivers.types {
			if method := f.prog.LookupMethod(concrete, common.Method.Pkg(), common.Method.Name()); method != nil {
				callees = append(callees, method)
			}
		}
	case common.StaticCallee() != nil:
		callees = []*ssa.Function{common.StaticCallee()}
	default:
		return unknownTypes()
	}
	result := heldTypes{known: true}
	for _, callee := range callees {
		if len(callee.Blocks) == 0 {
			return unknownTypes() // no body: an external or assembly function
		}
		for _, block := range callee.Blocks {
			ret, ok := block.Instrs[len(block.Instrs)-1].(*ssa.Return)
			if !ok {
				continue
			}
			i := max(index, 0)
			if i >= len(ret.Results) {
				return unknownTypes()
			}
			result = result.join(f.held(ret.Results[i], depth))
		}
	}
	return result
}

// arguments follows a parameter to the arguments its call sites pass; a
// function whose callers are not all known leaves it unknown.
func (f *valueFlow) arguments(param *ssa.Parameter, depth int) heldTypes {
	fn := param.Parent()
	if fn == nil || f.escaped[fn] || (fn.Signature.Recv() != nil && f.invoked[fn.Name()]) {
		return unknownTypes()
	}
	sites := f.sites[fn]
	if len(sites) == 0 {
		return unknownTypes()
	}
	index := slices.Index(fn.Params, param)
	if index < 0 {
		return unknownTypes()
	}
	result := heldTypes{known: true}
	for _, site := range sites {
		if index >= len(site.Args) {
			return unknownTypes()
		}
		result = result.join(f.held(site.Args[index], depth))
	}
	return result
}
