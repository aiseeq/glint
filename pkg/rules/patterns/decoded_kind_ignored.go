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
	rules.Register(NewDecodedKindFieldIgnoredRule())
}

// DecodedKindFieldIgnoredRule detects a converter from a decoded API record
// that never reads the record's discriminator and writes one fixed kind:
//
//	type TokenEvent struct { ...; Type string `json:"type"` } // Transfer, Approval
//
//	func convert(event *TokenEvent) *Row {
//	    row := &Row{From: event.From, To: event.To, Amount: event.Value}
//	    row.Kind = KindTransfer
//
// Every event the provider sends becomes a transfer: an approval (often of
// the maximum amount) enters balances and accounting as money moved.
// Reported: a function reading at least three fields of a parameter whose
// struct is decoded from JSON and carries a discriminator (type, kind, event,
// action, category, operation) the function never reads, while it stores a
// constant into a field named ...Type or ...Kind.
type DecodedKindFieldIgnoredRule struct {
	*rules.BaseRule
}

// NewDecodedKindFieldIgnoredRule creates the rule
func NewDecodedKindFieldIgnoredRule() *DecodedKindFieldIgnoredRule {
	return &DecodedKindFieldIgnoredRule{BaseRule: rules.NewBaseRule(
		"decoded-kind-field-ignored",
		"patterns",
		"Detects a converter from a decoded API record that never reads the record's type field and writes one fixed kind — every other kind the provider sends is stored as that one",
		core.SeverityMedium,
	)}
}

// AnalyzeFile is a no-op: the decoded struct may live in another package.
func (r *DecodedKindFieldIgnoredRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *DecodedKindFieldIgnoredRule) RequiresSSA() bool { return false }

// discriminatorNames are the JSON names of a record's kind.
var discriminatorNames = map[string]bool{
	"type": true, "kind": true, "event": true, "event_type": true, "eventtype": true, "action": true,
	"category": true, "operation": true, "op": true,
}

// AnalyzeGoProject reports the converters that ignore the decoded kind.
func (r *DecodedKindFieldIgnoredRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%s: nil Go project context", r.Name())
	}
	index, err := indexKindReaders(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", r.Name(), err)
	}
	return rules.AnalyzeTypedFiles(ctx, r.Name(), func(fileCtx *core.FileContext, info *types.Info) []*core.Violation {
		return analyzeGoFunctions(fileCtx, func(fn *ast.FuncDecl) []*core.Violation {
			return r.checkFunction(fileCtx, info, fn, index)
		})
	})
}

// kindReaders indexes the project's function bodies and the calls made to
// each function, to find the kind read outside the converter.
type kindReaders struct {
	decls map[*types.Func]kindReaderDecl
	calls map[*types.Func][]kindReaderCall
}

type kindReaderDecl struct {
	decl *ast.FuncDecl
	info *types.Info
}

// kindReaderCall is a call and the function it is made in.
type kindReaderCall struct {
	call   *ast.CallExpr
	caller kindReaderDecl
}

func indexKindReaders(ctx *core.GoProjectContext) (*kindReaders, error) {
	index := &kindReaders{decls: map[*types.Func]kindReaderDecl{}, calls: map[*types.Func][]kindReaderCall{}}
	err := forEachTypedFuncDecl(ctx, func(info *types.Info, fn *ast.FuncDecl, obj *types.Func) {
		decl := kindReaderDecl{decl: fn, info: info}
		if obj != nil {
			index.decls[obj] = decl
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if callee := staticFunc(info, call); callee != nil {
					index.calls[callee.Origin()] = append(index.calls[callee.Origin()], kindReaderCall{call: call, caller: decl})
				}
			}
			return true
		})
	})
	return index, err
}

// readsElsewhere reports the discriminator of the parameter at index read
// outside the converter: by a function it hands the record to, or by a
// caller that hands it the record (the dispatcher picking it for one kind).
func (index *kindReaders) readsElsewhere(info *types.Info, fn *ast.FuncDecl, param types.Object, paramIndex int, discriminator string) bool {
	found := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || found {
			return !found
		}
		callee := staticFunc(info, call)
		if callee == nil {
			return true
		}
		target, ok := index.decls[callee.Origin()]
		if !ok {
			return true
		}
		for i, arg := range call.Args {
			if ident, ok := ast.Unparen(arg).(*ast.Ident); ok && info.Uses[ident] == param {
				if calleeParam := target.info.Defs[paramIdentAt(target.decl.Type, i)]; calleeParam != nil && fieldsRead(target.info, target.decl.Body, calleeParam)[discriminator] {
					found = true
				}
			}
		}
		return !found
	})
	if found {
		return true
	}
	obj, ok := info.Defs[fn.Name].(*types.Func)
	if !ok {
		return false
	}
	for _, site := range index.calls[obj] {
		if paramIndex >= len(site.call.Args) {
			continue
		}
		if ident, ok := ast.Unparen(site.call.Args[paramIndex]).(*ast.Ident); ok {
			if arg := site.caller.info.Uses[ident]; arg != nil && fieldsRead(site.caller.info, site.caller.decl.Body, arg)[discriminator] {
				return true
			}
		}
	}
	return false
}

func (r *DecodedKindFieldIgnoredRule) checkFunction(ctx *core.FileContext, info *types.Info, fn *ast.FuncDecl, index *kindReaders) []*core.Violation {
	if !storesConstantKind(info, fn.Body) {
		return nil
	}
	var violations []*core.Violation
	paramIndex := -1
	for _, field := range fn.Type.Params.List {
		if len(field.Names) == 0 {
			paramIndex++
		}
		for _, name := range field.Names {
			paramIndex++
			param := info.Defs[name]
			if param == nil {
				continue
			}
			record, ok := structOf(param.Type())
			if !ok {
				continue
			}
			discriminator := decodedDiscriminator(record.fields)
			if discriminator == "" {
				continue
			}
			read := fieldsRead(info, fn.Body, param)
			if len(read) < 3 || read[discriminator] || index.readsElsewhere(info, fn, param, paramIndex, discriminator) {
				continue
			}
			line := ctx.LineFor(fn)
			if ctx.IsSuppressed(line, r.Name()) {
				continue
			}
			v := r.CreateViolation(ctx.RelPath, line, fmt.Sprintf("%s never reads %s.%s and writes one fixed kind — every other kind the provider sends is stored as that one",
				fn.Name.Name, name.Name, discriminator))
			v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
			v.WithSuggestion("Switch on the record's " + discriminator + ": map each kind it can carry, and reject the unknown ones")
			violations = append(violations, v)
		}
	}
	return violations
}

// decodedDiscriminator returns the string field naming the kind of a struct
// decoded from JSON (four or more tagged fields), "" when there is none.
func decodedDiscriminator(s *types.Struct) string {
	tagged := 0
	discriminator := ""
	for i := range s.NumFields() {
		name, ok := jsonTagName(s.Tag(i))
		if !ok {
			continue
		}
		tagged++
		if basic, ok := s.Field(i).Type().Underlying().(*types.Basic); ok && basic.Kind() == types.String && discriminatorNames[strings.ToLower(name)] {
			discriminator = s.Field(i).Name()
		}
	}
	if tagged < 4 {
		return ""
	}
	return discriminator
}

// fieldsRead returns the fields of a parameter the body reads: param.Field.
func fieldsRead(info *types.Info, body *ast.BlockStmt, param types.Object) map[string]bool {
	read := map[string]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if ident, ok := ast.Unparen(sel.X).(*ast.Ident); ok && info.Uses[ident] == param {
			read[sel.Sel.Name] = true
		}
		return true
	})
	return read
}

// storesConstantKind reports a body storing a constant into a field named
// ...Type or ...Kind: row.Kind = KindTransfer, Row{Kind: KindTransfer}.
func storesConstantKind(info *types.Info, body *ast.BlockStmt) bool {
	kindName := func(name string) bool {
		return strings.HasSuffix(name, "Type") || strings.HasSuffix(name, "Kind")
	}
	constant := func(expr ast.Expr) bool {
		tv, ok := info.Types[expr]
		return ok && tv.Value != nil
	}
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			for i, lhs := range node.Lhs {
				if sel, ok := lhs.(*ast.SelectorExpr); ok && kindName(sel.Sel.Name) && i < len(node.Rhs) && constant(node.Rhs[i]) {
					found = true
				}
			}
		case *ast.KeyValueExpr:
			if key, ok := node.Key.(*ast.Ident); ok && kindName(key.Name) && constant(node.Value) {
				if field, ok := info.Uses[key].(*types.Var); ok && field.IsField() {
					found = true
				}
			}
		}
		return !found
	})
	return found
}
