package patterns

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"maps"
	"slices"
	"sort"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewAlternateSyncPathDropsFieldsRule())
	rules.Register(NewParallelKeyToFieldMappingDriftsRule())
	rules.Register(NewFormFieldNameNotReadByHandlerRule())
	rules.Register(NewZeroPlaceholdersPassedForPersistedFieldsRule())
}

// NewAlternateSyncPathDropsFieldsRule creates alternate-sync-path-drops-fields:
// two paths apply the same external status to one entity - a webhook and a
// poller - through the same mapper, and one of them stores the raw fields the
// mapper read while the other stores only the mapped value. A record the
// second path moved keeps the stale provider fields:
//
//	status := MapStatus(payload.Status, payload.Reason)            // webhook
//	repo.UpdateFromWebhook(ctx, id, status, payload.Status, payload.Reason)
//
//	status := MapStatus(resp.Status, resp.Reason)                  // poller
//	repo.UpdateStatus(ctx, id, status)
func NewAlternateSyncPathDropsFieldsRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"alternate-sync-path-drops-fields",
			"patterns",
			"Detects a write that stores only the value a mapper derived from a response while another path applying the same mapper also stores the raw fields it read",
			core.SeverityMedium,
		),
		suggestion: "Store the same fields on both paths: pass the raw status (and the fields the other path keeps) to the write, or route both paths through one update",
	}
	r.forProject = func(decls map[*types.Func]typedFuncDecl) func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		byDecl := make(map[*ast.FuncDecl][]mappedWrite)
		keepers := make(map[*types.Func][]mappedWrite)
		for _, decl := range decls {
			writes := mappedWrites(decl)
			byDecl[decl.decl] = writes
			for _, w := range writes {
				if w.keepsRaw {
					keepers[w.mapper] = append(keepers[w.mapper], w)
				}
			}
		}
		return func(_ funcScope, fn *ast.FuncDecl) []funcFinding {
			var findings []funcFinding
			for _, w := range byDecl[fn] {
				if !w.keepsNone {
					continue
				}
				other := otherKeeper(keepers[w.mapper], fn)
				if other == nil {
					continue
				}
				findings = append(findings, funcFinding{node: w.call, message: fmt.Sprintf(
					"%s stores only what %s derives from %s, while %s applies the same mapping and also stores the raw fields — a record this path moved keeps them stale",
					callName(w.call), w.mapper.Name(), w.source, other.decl.Name.Name)})
			}
			return findings
		}
	}
	return r
}

// mappedWrite is a write call storing the result of a mapper called with
// fields of one value.
type mappedWrite struct {
	decl      *ast.FuncDecl
	call      *ast.CallExpr
	mapper    *types.Func
	source    string
	keepsRaw  bool // the write also passes a field the mapper read
	keepsNone bool // the write passes no field of the value
}

// fieldMapping is a call of a function returning a string-like value from
// fields of one value: MapStatus(resp.Status, resp.Reason).
type fieldMapping struct {
	mapper *types.Func
	source types.Object
	fields map[string]bool
}

// mappedWrites returns the writes of a body that store a mapped value.
func mappedWrites(decl typedFuncDecl) []mappedWrite {
	info := decl.info
	mapped := make(map[types.Object]fieldMapping)
	var writes []mappedWrite
	ast.Inspect(decl.decl.Body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.AssignStmt:
			if len(n.Lhs) != 1 || len(n.Rhs) != 1 {
				return true
			}
			id, ok := n.Lhs[0].(*ast.Ident)
			call, callOK := ast.Unparen(n.Rhs[0]).(*ast.CallExpr)
			if !ok || !callOK {
				return true
			}
			if m, ok := mappingOf(info, call); ok {
				if obj := info.ObjectOf(id); obj != nil {
					mapped[obj] = m
				}
			}
		case *ast.CallExpr:
			sel, ok := n.Fun.(*ast.SelectorExpr)
			if !ok || !helpers.IsWriteName(sel.Sel.Name) {
				return true
			}
			for _, arg := range n.Args {
				id, ok := ast.Unparen(arg).(*ast.Ident)
				if !ok {
					continue
				}
				m, ok := mapped[info.ObjectOf(id)]
				if !ok {
					continue
				}
				passed := fieldsOf(info, n.Args, m.source)
				keepsRaw := false
				for field := range passed {
					keepsRaw = keepsRaw || m.fields[field]
				}
				writes = append(writes, mappedWrite{decl: decl.decl, call: n, mapper: m.mapper, source: m.source.Name(),
					keepsRaw: keepsRaw, keepsNone: len(passed) == 0})
				break
			}
		}
		return true
	})
	return writes
}

// mappingOf matches a static call whose arguments are all fields of one
// variable and whose single result is a string.
func mappingOf(info *types.Info, call *ast.CallExpr) (fieldMapping, bool) {
	fn := staticFunc(info, call)
	if fn == nil || len(call.Args) == 0 {
		return fieldMapping{}, false
	}
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Results().Len() != 1 {
		return fieldMapping{}, false
	}
	if basic, ok := sig.Results().At(0).Type().Underlying().(*types.Basic); !ok || basic.Kind() != types.String {
		return fieldMapping{}, false
	}
	m := fieldMapping{mapper: fn.Origin(), fields: make(map[string]bool)}
	for _, arg := range call.Args {
		obj, field, ok := fieldRead(info, arg)
		if !ok || (m.source != nil && obj != m.source) {
			return fieldMapping{}, false
		}
		m.source = obj
		m.fields[field] = true
	}
	return m, true
}

// fieldRead matches v.Field of a local variable v.
func fieldRead(info *types.Info, expr ast.Expr) (types.Object, string, bool) {
	sel, ok := ast.Unparen(expr).(*ast.SelectorExpr)
	if !ok {
		return nil, "", false
	}
	id, ok := sel.X.(*ast.Ident)
	if !ok {
		return nil, "", false
	}
	v, ok := info.ObjectOf(id).(*types.Var)
	selection := info.Selections[sel]
	if !ok || selection == nil || selection.Kind() != types.FieldVal {
		return nil, "", false
	}
	return v, sel.Sel.Name, true
}

// fieldsOf returns the fields of source read anywhere in the arguments.
func fieldsOf(info *types.Info, args []ast.Expr, source types.Object) map[string]bool {
	fields := make(map[string]bool)
	for _, arg := range args {
		ast.Inspect(arg, func(n ast.Node) bool {
			if _, ok := n.(*ast.FuncLit); ok {
				return false
			}
			if expr, ok := n.(ast.Expr); ok {
				if obj, field, ok := fieldRead(info, expr); ok && obj == source {
					fields[field] = true
				}
			}
			return true
		})
	}
	return fields
}

// otherKeeper returns a write of another function that keeps the raw fields,
// the first by name for a stable message.
func otherKeeper(keepers []mappedWrite, fn *ast.FuncDecl) *mappedWrite {
	var best *mappedWrite
	for i := range keepers {
		w := &keepers[i]
		if w.decl == fn {
			continue
		}
		if best == nil || w.decl.Name.Name < best.decl.Name.Name {
			best = w
		}
	}
	return best
}

// NewParallelKeyToFieldMappingDriftsRule creates parallel-key-to-field-mapping-drifts:
// two functions fill the same struct from string-keyed sources (form values,
// a map of columns) with the same key spellings, and one of them leaves out
// fields the other sets - an entity created through it silently lacks them:
//
//	o.City = r.FormValue("city")         // form
//	o.ZipCode = r.FormValue("zipCode")
//
//	o.City = fields["city"]              // bulk upload: ZipCode never set
func NewParallelKeyToFieldMappingDriftsRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"parallel-key-to-field-mapping-drifts",
			"patterns",
			"Detects a function filling a struct from string keys that leaves out fields a sibling mapper of the same struct fills from the same keys",
			core.SeverityMedium,
		),
		suggestion: "Map the missing fields too, or build both paths from one key-to-field table",
	}
	r.forProject = func(decls map[*types.Func]typedFuncDecl) func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		byTarget := make(map[string][]keyedMapper)
		for _, decl := range decls {
			for _, m := range keyedMappers(decl) {
				byTarget[m.target] = append(byTarget[m.target], m)
			}
		}
		return func(_ funcScope, fn *ast.FuncDecl) []funcFinding {
			var findings []funcFinding
			for _, target := range slices.Sorted(maps.Keys(byTarget)) {
				mappers := byTarget[target]
				for _, a := range mappers {
					if a.decl != fn {
						continue
					}
					if missing, other := driftAgainst(a, mappers); len(missing) > 0 {
						findings = append(findings, funcFinding{node: fn.Name, message: fmt.Sprintf(
							"%s fills %s from the same keys as %s but never sets %s — an entity created through it lacks them",
							fn.Name.Name, shortType(a.target), other.decl.Name.Name, listFields(missing, other.keyed))})
					}
				}
			}
			return findings
		}
	}
	return r
}

// keyedMapper is one function's filling of one struct variable.
type keyedMapper struct {
	decl     *ast.FuncDecl
	target   string
	keyed    map[string]string // field -> key it is read from
	assigned map[string]bool   // every field the function sets
}

// minKeyedFields is how many fields a function must fill from keys to count
// as a mapper.
const minKeyedFields = 5

// keyedMappers returns the structs a body fills from string keys.
func keyedMappers(decl typedFuncDecl) []keyedMapper {
	info := decl.info
	byVar := make(map[types.Object]*keyedMapper)
	var order []types.Object
	ast.Inspect(decl.decl.Body, func(n ast.Node) bool {
		if _, ok := n.(*ast.FuncLit); ok {
			return false
		}
		assign, ok := n.(*ast.AssignStmt)
		if !ok || assign.Tok != token.ASSIGN || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
			return true
		}
		obj, field, ok := fieldRead(info, assign.Lhs[0])
		if !ok {
			return true
		}
		target := namedStruct(obj.Type())
		if target == "" {
			return true
		}
		m := byVar[obj]
		if m == nil {
			m = &keyedMapper{decl: decl.decl, target: target, keyed: map[string]string{}, assigned: map[string]bool{}}
			byVar[obj] = m
			order = append(order, obj)
		}
		m.assigned[field] = true
		if key, ok := singleKeyedRead(info, assign.Rhs[0]); ok {
			m.keyed[field] = key
		}
		return true
	})
	var mappers []keyedMapper
	for _, obj := range order {
		if m := byVar[obj]; len(m.keyed) >= minKeyedFields {
			mappers = append(mappers, *m)
		}
	}
	return mappers
}

// namedStruct returns the name of a named struct type or a pointer to one.
func namedStruct(t types.Type) string {
	if ptr, ok := t.(*types.Pointer); ok {
		t = ptr.Elem()
	}
	named, ok := t.(*types.Named)
	if !ok {
		return ""
	}
	if _, ok := named.Underlying().(*types.Struct); !ok {
		return ""
	}
	return types.TypeString(named, nil)
}

// singleKeyedRead returns the key of the one keyed read in an expression.
func singleKeyedRead(info *types.Info, expr ast.Expr) (string, bool) {
	var keys []string
	ast.Inspect(expr, func(n ast.Node) bool {
		if e, ok := n.(ast.Expr); ok {
			if key, ok := keyedRead(info, e); ok {
				keys = append(keys, key)
				return false
			}
		}
		return true
	})
	if len(keys) != 1 {
		return "", false
	}
	return keys[0], true
}

// formReadMethods read a submitted value by its field name.
var formReadMethods = map[string]bool{"FormValue": true, "PostFormValue": true}

// keyedRead matches a read of a value by a literal string key:
// r.FormValue("city"), r.Form.Get("city"), fields["city"].
func keyedRead(info *types.Info, expr ast.Expr) (string, bool) {
	key, literal, ok := keyedAccess(info, expr)
	if !ok || !literal {
		return "", false
	}
	return key, true
}

// keyedAccess matches a keyed read; literal false is one whose key is not a
// string literal.
func keyedAccess(info *types.Info, expr ast.Expr) (key string, literal, ok bool) {
	var keyExpr ast.Expr
	switch e := ast.Unparen(expr).(type) {
	case *ast.IndexExpr:
		m, isMap := typeUnderlying(info.TypeOf(e.X)).(*types.Map)
		if !isMap {
			return "", false, false
		}
		if basic, ok := m.Key().Underlying().(*types.Basic); !ok || basic.Kind() != types.String {
			return "", false, false
		}
		keyExpr = e.Index
	case *ast.CallExpr:
		sel, isSel := e.Fun.(*ast.SelectorExpr)
		if !isSel || len(e.Args) != 1 {
			return "", false, false
		}
		if !formReadMethods[sel.Sel.Name] && (sel.Sel.Name != "Get" || !isNamedType(info.TypeOf(sel.X), "net/url", "Values")) {
			return "", false, false
		}
		keyExpr = e.Args[0]
	default:
		return "", false, false
	}
	if s, isLit := stringLiteral(keyExpr); isLit {
		return s, true, true
	}
	return "", false, true
}

// driftAgainst returns the fields a sibling mapper fills from keys that a
// does not set, against the sibling sharing the most key spellings with a.
// A sibling counts when it reads most of a's keys the same way and a covers
// at least half of what it adds: a deliberate subset (an edit form changing
// two fields of fifty) is not drift.
func driftAgainst(a keyedMapper, mappers []keyedMapper) ([]string, keyedMapper) {
	var bestMissing []string
	var best keyedMapper
	bestShared := 0
	for _, b := range mappers {
		if b.decl == a.decl {
			continue
		}
		shared := 0
		for field, key := range a.keyed {
			if b.keyed[field] == key {
				shared++
			}
		}
		if shared < minKeyedFields || shared*4 < len(a.keyed)*3 {
			continue
		}
		var missing []string
		for field := range b.keyed {
			if !a.assigned[field] {
				missing = append(missing, field)
			}
		}
		if len(missing) == 0 || len(missing) > shared {
			continue
		}
		if shared > bestShared || (shared == bestShared && b.decl.Name.Name < best.decl.Name.Name) {
			bestShared, bestMissing, best = shared, missing, b
		}
	}
	sort.Strings(bestMissing)
	return bestMissing, best
}

// listFields names up to five fields with the keys they are read from.
func listFields(fields []string, keys map[string]string) string {
	const shown = 5
	parts := make([]string, 0, shown)
	for i, field := range fields {
		if i == shown {
			parts = append(parts, fmt.Sprintf("and %d more", len(fields)-shown))
			break
		}
		parts = append(parts, fmt.Sprintf("%s (%q)", field, keys[field]))
	}
	return strings.Join(parts, ", ")
}

// shortType drops the package path of a type name.
func shortType(name string) string {
	if i := strings.LastIndex(name, "/"); i >= 0 {
		return name[i+1:]
	}
	return name
}

// NewFormFieldNameNotReadByHandlerRule creates form-field-name-not-read-by-handler:
// a field definition table (Label, Name) declares the names a form submits,
// and a name no read in the package asks for is lost on submit - typically a
// spelling the handler reads with a prefix:
//
//	{Label: "Referral Code", Name: "referralCode"}
//	o.ReferralCode = r.FormValue("customerReferralCode")
func NewFormFieldNameNotReadByHandlerRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"form-field-name-not-read-by-handler",
			"patterns",
			"Detects a form field name declared in a Label/Name definition table that no FormValue, Form.Get or keyed read of the package asks for",
			core.SeverityMedium,
		),
		suggestion: "Declare the name the handler reads, or read the declared one in the handler",
	}
	r.forProject = func(decls map[*types.Func]typedFuncDecl) func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		forms := make(map[string]*packageForms)
		for obj, decl := range decls {
			if obj.Pkg() == nil {
				continue
			}
			pf := forms[obj.Pkg().Path()]
			if pf == nil {
				pf = &packageForms{reads: map[string]bool{}, declared: map[string][]declaredName{}}
				forms[obj.Pkg().Path()] = pf
			}
			pf.collect(decl)
		}
		return func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
			obj, ok := scope.info.Defs[fn.Name].(*types.Func)
			if !ok || obj.Pkg() == nil {
				return nil
			}
			pf := forms[obj.Pkg().Path()]
			if pf == nil || pf.dynamic || len(pf.reads) == 0 {
				return nil
			}
			var findings []funcFinding
			for name, lits := range pf.declared {
				first := lits[0]
				for _, d := range lits[1:] {
					if d.before(first) {
						first = d
					}
				}
				if pf.reads[name] || first.fn != fn {
					continue
				}
				findings = append(findings, funcFinding{node: first.lit, message: fmt.Sprintf(
					"The form field %q (declared %d time(s)) is read by no handler of the package — what the user enters there is dropped on submit",
					name, len(lits))})
			}
			sort.Slice(findings, func(i, j int) bool { return findings[i].node.Pos() < findings[j].node.Pos() })
			return findings
		}
	}
	return r
}

// packageForms is what one package declares and reads as form field names.
type packageForms struct {
	reads    map[string]bool
	dynamic  bool // a form read by a definition's Name, or a copy keyed by it: every declared name is read
	declared map[string][]declaredName
}

// declaredName is one declaration of a form field name.
type declaredName struct {
	lit *ast.BasicLit
	fn  *ast.FuncDecl
}

// before orders declarations by function name and place in it: positions
// of different files depend on the order the files were parsed in.
func (d declaredName) before(other declaredName) bool {
	if d.fn.Name.Name != other.fn.Name.Name {
		return d.fn.Name.Name < other.fn.Name.Name
	}
	return d.lit.Pos()-d.fn.Pos() < other.lit.Pos()-other.fn.Pos()
}

// collect adds the declarations and the reads of one body.
func (pf *packageForms) collect(decl typedFuncDecl) {
	info := decl.info
	ast.Inspect(decl.decl.Body, func(n ast.Node) bool {
		switch e := n.(type) {
		case *ast.CompositeLit:
			if !isFieldDefinition(info.TypeOf(e)) {
				return true
			}
			for _, elt := range e.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok || !isIdentNamed(kv.Key, "Name") {
					continue
				}
				if lit, ok := kv.Value.(*ast.BasicLit); ok && lit.Kind == token.STRING {
					if name, ok := stringLiteral(lit); ok && name != "" {
						pf.declared[name] = append(pf.declared[name], declaredName{lit: lit, fn: decl.decl})
					}
				}
			}
		case *ast.AssignStmt:
			for i, rhs := range e.Rhs {
				if _, literal, ok := keyedAccess(info, rhs); ok && !literal && readsDefinitionName(rhs) && i < len(e.Lhs) && storesValue(e.Lhs[i]) {
					pf.dynamic = true
				}
			}
		case ast.Expr:
			key, literal, ok := keyedAccess(info, e)
			if !ok {
				return true
			}
			if literal {
				pf.reads[key] = true
			} else if _, isCall := ast.Unparen(e).(*ast.CallExpr); isCall && readsDefinitionName(e) {
				pf.dynamic = true
			}
		}
		return true
	})
}

// isFieldDefinition reports a struct with string fields Label and Name: a
// form field definition.
func isFieldDefinition(t types.Type) bool {
	if t == nil {
		return false
	}
	st, ok := t.Underlying().(*types.Struct)
	if !ok {
		return false
	}
	found := 0
	for i := range st.NumFields() {
		f := st.Field(i)
		if basic, ok := f.Type().Underlying().(*types.Basic); ok && basic.Kind() == types.String && (f.Name() == "Label" || f.Name() == "Name") {
			found++
		}
	}
	return found == 2
}

// storesValue reports an assignment target that keeps the value: a map
// entry or a field, not a local checked and dropped.
func storesValue(lhs ast.Expr) bool {
	switch ast.Unparen(lhs).(type) {
	case *ast.IndexExpr, *ast.SelectorExpr:
		return true
	}
	return false
}

// readsDefinitionName reports a keyed read whose key is x.Name.
func readsDefinitionName(expr ast.Expr) bool {
	var key ast.Expr
	switch e := ast.Unparen(expr).(type) {
	case *ast.IndexExpr:
		key = e.Index
	case *ast.CallExpr:
		key = e.Args[0]
	}
	sel, ok := ast.Unparen(key).(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "Name"
}

// NewZeroPlaceholdersPassedForPersistedFieldsRule creates zero-placeholders-passed-for-persisted-fields:
// a call of a persistence method passes zero values (T{}, "", nil, 0) at
// positions its other call sites fill from computed values - the row written
// through this call lacks what the other paths store:
//
//	repo.ApplyQuote(ctx, id, amount, tx.AmountLocal, tx.RateLocal, tx.RateSource, ...) // live path
//	repo.ApplyQuote(ctx, id, amount, decimal.Decimal{}, decimal.Decimal{}, "", ...) // admin path
func NewZeroPlaceholdersPassedForPersistedFieldsRule() *typedFuncRule {
	r := &typedFuncRule{
		BaseRule: rules.NewBaseRule(
			"zero-placeholders-passed-for-persisted-fields",
			"patterns",
			"Detects a persistence call passing zero placeholders for two or more parameters that the method's other call sites fill from computed values",
			core.SeverityMedium,
		),
		suggestion: "Compute the values on this path as the other callers do, or split the method so this path does not write those columns",
	}
	r.check = func(scope funcScope, fn *ast.FuncDecl) []funcFinding {
		if fn.Body == nil {
			return nil
		}
		// A failure has nothing to record for what a result would have
		// filled: calls in the body of an if err != nil are left alone.
		var failures []*ast.BlockStmt
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if ifStmt, ok := n.(*ast.IfStmt); ok && errorPresent(scope.info, ifStmt.Cond) {
				failures = append(failures, ifStmt.Body)
			}
			return true
		})
		var findings []funcFinding
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || slices.ContainsFunc(failures, func(b *ast.BlockStmt) bool { return b.Pos() <= call.Pos() && call.End() <= b.End() }) {
				return true
			}
			if f, ok := zeroPlaceholders(scope, fn, call); ok {
				findings = append(findings, f)
			}
			return true
		})
		return findings
	}
	return r
}

// errorPresent matches x != nil of an error x.
func errorPresent(info *types.Info, cond ast.Expr) bool {
	bin, ok := ast.Unparen(cond).(*ast.BinaryExpr)
	return ok && bin.Op == token.NEQ && isNilIdent(bin.Y) && isErrorType(info.TypeOf(bin.X))
}

// zeroPlaceholders reports a persistence call passing zero placeholders that
// another function's call of the method fills.
func zeroPlaceholders(scope funcScope, fn *ast.FuncDecl, call *ast.CallExpr) (funcFinding, bool) {
	callee := staticFunc(scope.info, call)
	if callee == nil || !persistenceMethod(callee) || call.Ellipsis.IsValid() {
		return funcFinding{}, false
	}
	sig, ok := callee.Type().(*types.Signature)
	if !ok || sig.Variadic() || sig.Params().Len() != len(call.Args) {
		return funcFinding{}, false
	}
	placeholders, other := filledElsewhere(call, fn, scope.callers[callee.Origin()])
	if len(placeholders) < 2 {
		return funcFinding{}, false
	}
	names := make([]string, 0, len(placeholders))
	for _, i := range placeholders {
		names = append(names, sig.Params().At(i).Name())
	}
	return funcFinding{node: call.Args[placeholders[0]], message: fmt.Sprintf(
		"%s gets zero placeholders for %s, which %s fills from computed values — the row written here lacks them",
		callee.Name(), strings.Join(names, ", "), other)}, true
}

// persistenceMethod reports a method that writes stored state: a write verb
// leading its name, or a receiver named as a store.
func persistenceMethod(fn *types.Func) bool {
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return false
	}
	if helpers.IsWriteName(fn.Name()) {
		return true
	}
	return isDataAccessReceiver(shortType(namedStruct(sig.Recv().Type())))
}

// filledElsewhere returns the positions where call passes a zero placeholder
// and a call site of another function passes a computed value, with that
// site's caller; nothing when every placeholder is nil (an optional value
// left out). A site of the same function is another outcome of one
// operation, not another path.
func filledElsewhere(call *ast.CallExpr, fn *ast.FuncDecl, sites []funcCallSite) ([]int, string) {
	var positions []int
	other := ""
	nonNil := false
	for i, arg := range call.Args {
		arg = ast.Unparen(arg)
		if !isZeroValueExpr(arg) {
			continue
		}
		for _, site := range sites {
			if site.caller.decl == fn || len(site.call.Args) != len(call.Args) || !computedValue(site.call.Args[i]) {
				continue
			}
			positions = append(positions, i)
			nonNil = nonNil || !isNilIdent(arg)
			if other == "" || site.caller.decl.Name.Name < other {
				other = site.caller.decl.Name.Name
			}
			break
		}
	}
	if !nonNil {
		return nil, ""
	}
	return positions, other
}

// computedValue reports an argument that is not a literal: a variable, a
// field, a call.
func computedValue(expr ast.Expr) bool {
	switch e := ast.Unparen(expr).(type) {
	case *ast.BasicLit, *ast.CompositeLit, *ast.FuncLit:
		return false
	case *ast.Ident:
		return e.Name != "nil" && e.Name != "true" && e.Name != "false"
	}
	return true
}
