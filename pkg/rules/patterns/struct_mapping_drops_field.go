package patterns

import (
	"go/ast"
	"go/token"
	"go/types"
	"reflect"
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewStructMappingDropsFieldRule())
}

// StructMappingDropsFieldRule detects a struct literal mapping one struct
// into another that leaves out fields both types have:
//
//	return models.Withdrawal{
//		ID:        r.ID,
//		Amount:    r.Amount,
//		UserEmail: r.UserEmail,
//	} // r has TxHash and CreatedAt too, Withdrawal has them: left zero
//
// The literal copies fields from a source value by name, at least two of
// them, and the target type has further fields the source holds under the
// same name and an assignable type. The value the source had never reaches
// the target: the response shows it empty, the next step reads a zero.
// Not reported: fields the function sets afterwards (w.TxHash = ...,
// &w.TxHash) or a literal handed to a call that may fill it, fields an
// outer literal sets, fields tagged json:"-", credentials (password,
// secret, tokens), a copy into the source's own type, a group holding a
// list of sources, and the ID and timestamps of a new record (a literal
// that does not copy the source's ID).
type StructMappingDropsFieldRule struct {
	*rules.BaseRule
}

// NewStructMappingDropsFieldRule creates the rule
func NewStructMappingDropsFieldRule() *StructMappingDropsFieldRule {
	return &StructMappingDropsFieldRule{BaseRule: rules.NewBaseRule(
		"struct-mapping-drops-field",
		"patterns",
		"Detects a struct literal mapping one struct into another that leaves out fields both have — the value never reaches the target",
		core.SeverityMedium,
	)}
}

// AnalyzeFile is a no-op: the fields of both types decide.
func (r *StructMappingDropsFieldRule) AnalyzeFile(_ *core.FileContext) []*core.Violation { return nil }

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *StructMappingDropsFieldRule) RequiresSSA() bool { return false }

var credentialField = regexp.MustCompile(`(?i)password|secret|salt|privatekey|token$`)

// recordLifecycle are the fields a new record gets on its own: a literal
// that does not copy the source's ID makes another record, not a view of
// the source.
var recordLifecycle = map[string]bool{"ID": true, "CreatedAt": true, "UpdatedAt": true, "DeletedAt": true, "Version": true}

// AnalyzeGoProject reports the mapping literals that drop fields.
func (r *StructMappingDropsFieldRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(file *core.FileContext, info *types.Info) []*core.Violation {
		var violations []*core.Violation
		outer := outerKeys(file.GoAST)
		for _, body := range functionBodies(file.GoAST) {
			ast.Inspect(body, func(n ast.Node) bool {
				if _, nested := n.(*ast.FuncLit); nested {
					return false // its own body is walked on its own
				}
				lit, ok := n.(*ast.CompositeLit)
				if !ok {
					return true
				}
				src, dropped := droppedFields(lit, body, info, outer[lit])
				if len(dropped) == 0 {
					return true
				}
				line := file.LineFor(lit)
				if file.IsSuppressed(line, r.Name()) {
					return true
				}
				v := r.CreateViolation(file.RelPath, line, "Struct literal copies fields from "+types.ExprString(src)+" by name but leaves out "+strings.Join(dropped, ", ")+" — the source has them, and the target gets zero values")
				v.WithCode(strings.TrimSpace(file.GetLine(line)))
				v.WithSuggestion("Copy the fields too, or set them after the literal; a field left out on purpose is worth a suppression with the reason")
				violations = append(violations, v)
				return true
			})
		}
		return violations
	})
}

// droppedFields returns the literal's mapping source and the fields of the
// literal's struct type that the source has under the same name and an
// assignable type, and that nothing in the function sets.
func droppedFields(lit *ast.CompositeLit, body *ast.BlockStmt, info *types.Info, outerSet map[string]bool) (ast.Expr, []string) {
	target, ok := structOf(info.TypeOf(lit))
	if !ok {
		return nil, nil
	}
	src := mappingSource(lit, info)
	if src == nil {
		return nil, nil
	}
	srcType := info.TypeOf(src)
	if ptr, isPtr := srcType.(*types.Pointer); isPtr {
		srcType = ptr.Elem()
	}
	if types.Identical(srcType, info.TypeOf(lit)) || collects(target, srcType) {
		return nil, nil // a narrowed view of the same type, or a group of sources
	}
	after, filled := setAfter(lit, body, info)
	if filled {
		return nil, nil
	}
	set := make(map[string]bool)
	for name := range outerSet {
		set[name] = true
	}
	for name := range after {
		set[name] = true
	}
	for _, elt := range lit.Elts {
		if kv, ok := elt.(*ast.KeyValueExpr); ok {
			if key, ok := kv.Key.(*ast.Ident); ok {
				set[key.Name] = true
			}
		}
	}
	newRecord := !copiesField(lit, info, "ID")
	var dropped []string
	for i := range target.fields.NumFields() {
		field := target.fields.Field(i)
		name := field.Name()
		if set[name] || field.Embedded() || !field.Exported() && field.Pkg() != target.pkg ||
			credentialField.MatchString(name) || jsonOmitted(target.fields.Tag(i)) || newRecord && recordLifecycle[name] {
			continue
		}
		obj, _, _ := types.LookupFieldOrMethod(srcType, true, target.pkg, name)
		srcField, ok := obj.(*types.Var)
		if !ok || !srcField.IsField() || !types.AssignableTo(srcField.Type(), field.Type()) {
			continue
		}
		dropped = append(dropped, name)
	}
	return src, dropped
}

type structTarget struct {
	fields *types.Struct
	pkg    *types.Package
}

// structOf returns the struct of a named struct type, through a pointer.
func structOf(t types.Type) (structTarget, bool) {
	if ptr, ok := t.(*types.Pointer); ok {
		t = ptr.Elem()
	}
	named, ok := types.Unalias(t).(*types.Named)
	if !ok {
		return structTarget{}, false
	}
	st, ok := named.Underlying().(*types.Struct)
	return structTarget{fields: st, pkg: named.Obj().Pkg()}, ok
}

// mappingSource returns the value a keyed literal copies at least two
// fields from under their own names (ID: r.ID), nil when there is none.
func mappingSource(lit *ast.CompositeLit, info *types.Info) ast.Expr {
	counts := make(map[string]int)
	sources := make(map[string]ast.Expr)
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok {
			continue
		}
		sel, ok := copiedField(kv.Value, info)
		if !ok || sel.Sel.Name != key.Name {
			continue
		}
		text := types.ExprString(sel.X)
		counts[text]++
		sources[text] = sel.X
	}
	var best ast.Expr
	bestText := ""
	most := 1
	for text, n := range counts {
		if n > most || n == most && best != nil && text < bestText {
			best, bestText, most = sources[text], text, n
		}
	}
	return best
}

// copiedField returns the field selection a value copies: src.X, through
// a conversion or a call on it alone (string(src.X), ptr(src.X)), &src.X
// or *src.X.
func copiedField(expr ast.Expr, info *types.Info) (*ast.SelectorExpr, bool) {
	for {
		switch e := ast.Unparen(expr).(type) {
		case *ast.UnaryExpr:
			if e.Op != token.AND {
				return nil, false
			}
			expr = e.X
		case *ast.StarExpr:
			expr = e.X
		case *ast.CallExpr:
			if len(e.Args) != 1 {
				return nil, false
			}
			expr = e.Args[0]
		case *ast.SelectorExpr:
			selection, ok := info.Selections[e]
			return e, ok && selection.Kind() == types.FieldVal
		default:
			return nil, false
		}
	}
}

// copiesField reports a literal setting the named field from its mapping
// source's field of the same name.
func copiesField(lit *ast.CompositeLit, info *types.Info, name string) bool {
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		if key, ok := kv.Key.(*ast.Ident); ok && key.Name == name {
			sel, copied := copiedField(kv.Value, info)
			return copied && sel.Sel.Name == name
		}
	}
	return false
}

// setAfter returns the fields the function sets on the variable the literal
// is stored in: w.CreatedAt = ..., or through &w.TxHash. filled reports the
// variable handed to a call (fill(&w, r)): the call may set any field.
func setAfter(lit *ast.CompositeLit, body *ast.BlockStmt, info *types.Info) (set map[string]bool, filled bool) {
	set = make(map[string]bool)
	holder := literalHolder(lit, body, info)
	if holder == nil {
		return set, false
	}
	isHolder := func(expr ast.Expr) bool {
		id, ok := ast.Unparen(expr).(*ast.Ident)
		return ok && info.ObjectOf(id) == holder
	}
	_, pointer := holder.Type().(*types.Pointer)
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			for _, lhs := range node.Lhs {
				if sel, ok := lhs.(*ast.SelectorExpr); ok && isHolder(sel.X) {
					set[sel.Sel.Name] = true
				}
			}
		case *ast.UnaryExpr:
			if sel, ok := ast.Unparen(node.X).(*ast.SelectorExpr); ok && node.Op == token.AND && isHolder(sel.X) {
				set[sel.Sel.Name] = true
			}
		case *ast.CallExpr:
			for _, arg := range node.Args {
				unary, isAddr := ast.Unparen(arg).(*ast.UnaryExpr)
				if isAddr && unary.Op == token.AND && isHolder(unary.X) || pointer && isHolder(arg) {
					filled = true
				}
			}
		}
		return true
	})
	return set, filled
}

// literalHolder returns the variable a literal is assigned to: w := T{...},
// w = &T{...}; nil for a literal returned or passed on right away.
func literalHolder(lit *ast.CompositeLit, body *ast.BlockStmt, info *types.Info) types.Object {
	var holder types.Object
	ast.Inspect(body, func(n ast.Node) bool {
		if holder != nil {
			return false
		}
		assign, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for i, rhs := range assign.Rhs {
			value := ast.Unparen(rhs)
			if unary, ok := value.(*ast.UnaryExpr); ok && unary.Op == token.AND {
				value = ast.Unparen(unary.X)
			}
			if value != lit || i >= len(assign.Lhs) {
				continue
			}
			if id, ok := assign.Lhs[i].(*ast.Ident); ok {
				holder = info.ObjectOf(id)
			}
		}
		return true
	})
	return holder
}

// outerKeys maps a literal written as a field of another literal to the
// fields the outer one sets: Result: Result{...}, SessionID: c.SessionID
// sets SessionID over the embedded Result's own.
func outerKeys(file *ast.File) map[*ast.CompositeLit]map[string]bool {
	outer := make(map[*ast.CompositeLit]map[string]bool)
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		keys := make(map[string]bool)
		var inner []*ast.CompositeLit
		for _, elt := range lit.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			if key, ok := kv.Key.(*ast.Ident); ok {
				keys[key.Name] = true
			}
			value := ast.Unparen(kv.Value)
			if unary, ok := value.(*ast.UnaryExpr); ok && unary.Op == token.AND {
				value = ast.Unparen(unary.X)
			}
			if child, ok := value.(*ast.CompositeLit); ok {
				inner = append(inner, child)
			}
		}
		for _, child := range inner {
			outer[child] = keys
		}
		return true
	})
	return outer
}

// collects reports a target holding a list of sources: a group built from
// its first member, whose other fields come from the whole list.
func collects(target structTarget, source types.Type) bool {
	for i := range target.fields.NumFields() {
		slice, ok := target.fields.Field(i).Type().Underlying().(*types.Slice)
		if !ok {
			continue
		}
		elem := slice.Elem()
		if ptr, ok := elem.(*types.Pointer); ok {
			elem = ptr.Elem()
		}
		if types.Identical(elem, source) {
			return true
		}
	}
	return false
}

// jsonOmitted reports a field tagged json:"-".
func jsonOmitted(tag string) bool {
	return reflect.StructTag(tag).Get("json") == "-"
}
