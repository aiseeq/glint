package patterns

import (
	"fmt"
	"go/ast"
	"go/types"
	"path"
	"strconv"
	"strings"
	"unicode"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewContextKeyUnpairedRule())
}

// ContextKeyUnpairedRule detects context keys of the project whose writes
// and reads do not meet:
//
//	ctx = context.WithValue(ctx, adminIDKeyAlt, id) // the cookie middleware
//	roles := ctx.Value(adminRolesKey)               // nil on every cookie request
//
// When a middleware stores one key of a family (Admin…) that another
// middleware or context builder stores whole, the requests it admits miss
// the rest of the family, and the handlers reading them treat an
// authenticated admin as anonymous. With type information two more
// mismatches are reported: a key read and never stored (always nil) and a
// key stored and never read. Keys are compared as the context compares
// them, by type and value, so a constant alias is the same key; a key of a
// type the project reads or writes through a variable (a lookup helper
// taking the key as a parameter) is not judged on that side. Where a
// package has no type information, keys are compared by name and only the
// family check runs.
type ContextKeyUnpairedRule struct {
	*rules.BaseRule
}

// NewContextKeyUnpairedRule creates the rule
func NewContextKeyUnpairedRule() *ContextKeyUnpairedRule {
	return &ContextKeyUnpairedRule{BaseRule: rules.NewBaseRule(
		"context-key-unpaired",
		"patterns",
		"Detects a middleware storing part of a context key family another writer stores whole, and context keys read but never stored or stored but never read",
		core.SeverityHigh,
	)}
}

// AnalyzeFile is a no-op: writers and readers live in different files.
func (r *ContextKeyUnpairedRule) AnalyzeFile(_ *core.FileContext) []*core.Violation { return nil }

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *ContextKeyUnpairedRule) RequiresSSA() bool { return false }

// contextKeySite is one WithValue or Value call with a key of the project.
type contextKeySite struct {
	file    *core.FileContext
	line    int
	typedID string // the key by type and value, "" without type information
	name    string
	write   bool
	fn      *ast.FuncDecl
	// middleware: the function takes or returns an http.Handler; enricher:
	// it takes a context and returns one built from it.
	middleware, enricher bool
}

// contextKeyUse gathers the key sites of the project.
type contextKeyUse struct {
	sites        []contextKeySite
	byName       bool // some package has no type information
	dynamicRead  map[string]bool
	dynamicWrite map[string]bool
	keyType      map[string]string
	read, wrote  map[string]bool
}

func (u *contextKeyUse) id(site contextKeySite) string {
	if u.byName {
		return site.name
	}
	return site.typedID
}

// AnalyzeGoProject reports the unpaired keys.
func (r *ContextKeyUnpairedRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	use := gatherContextKeys(ctx)
	partial := partialWriters(use)
	return rules.AnalyzeGoFiles(ctx, r.Name(), func(file *core.FileContext, _ *types.Info) []*core.Violation {
		var violations []*core.Violation
		for _, site := range use.sites {
			if site.file != file || file.IsSuppressed(site.line, r.Name()) {
				continue
			}
			id := use.id(site)
			message := partial[site]
			switch {
			case message != "":
			case use.byName:
				continue
			case !site.write && !use.wrote[id] && !use.dynamicWrite[use.keyType[id]]:
				message = fmt.Sprintf("Context key %s is read here, but no code stores it — the value is always nil", site.name)
			case site.write && !use.read[id] && !use.dynamicRead[use.keyType[id]]:
				message = fmt.Sprintf("Context key %s is stored here, but nothing reads it", site.name)
			default:
				continue
			}
			v := r.CreateViolation(file.RelPath, site.line, message)
			v.WithCode(strings.TrimSpace(file.GetLine(site.line)))
			v.WithSuggestion("Store and read a value under one key: the same constant on both sides, and every key of the family the handlers read stored by each middleware that admits the request")
			violations = append(violations, v)
		}
		return violations
	})
}

func gatherContextKeys(ctx *core.GoProjectContext) *contextKeyUse {
	use := &contextKeyUse{
		read: map[string]bool{}, wrote: map[string]bool{},
		dynamicRead: map[string]bool{}, dynamicWrite: map[string]bool{},
		keyType: map[string]string{},
	}
	own := map[string]bool{}
	typed := map[*core.FileContext]bool{}
	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil {
			continue
		}
		own[pkg.Package.PkgPath] = true
	}
	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil || pkg.Package.TypesInfo == nil {
			continue
		}
		for _, file := range pkg.Files {
			typed[file] = true
			use.gatherFile(file, pkg.Package.TypesInfo, own)
		}
	}
	for _, file := range ctx.Files {
		if file != nil && !typed[file] {
			use.gatherFile(file, nil, own)
		}
	}
	for _, site := range use.sites {
		if site.typedID == "" {
			use.byName = true
		}
	}
	for _, site := range use.sites {
		id := use.id(site)
		if site.write {
			use.wrote[id] = true
		} else {
			use.read[id] = true
		}
	}
	return use
}

func (u *contextKeyUse) gatherFile(file *core.FileContext, info *types.Info, own map[string]bool) {
	if file.GoAST == nil || file.IsTestFile() || !file.IsGoFile() {
		return
	}
	for _, decl := range file.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		middleware := fieldOfType(file.GoAST, info, fn.Type.Params, "net/http", "Handler", "HandlerFunc") ||
			fieldOfType(file.GoAST, info, fn.Type.Results, "net/http", "Handler", "HandlerFunc")
		enricher := fieldOfType(file.GoAST, info, fn.Type.Params, "context", "Context") &&
			fieldOfType(file.GoAST, info, fn.Type.Results, "context", "Context")
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			key, write, ok := contextKeyCall(file.GoAST, info, call)
			if !ok {
				return true
			}
			site := contextKeySite{file: file, line: file.LineFor(key), write: write, fn: fn, middleware: middleware, enricher: enricher}
			if info == nil {
				if site.name = keyName(key); site.name != "" {
					u.sites = append(u.sites, site)
				}
				return true
			}
			named, ok := types.Unalias(info.TypeOf(key)).(*types.Named)
			if !ok || named.Obj().Pkg() == nil || !own[named.Obj().Pkg().Path()] {
				return true
			}
			typeName := types.TypeString(named, nil)
			id, name, ok := contextKeyIdentity(info, key, typeName)
			if !ok {
				if write {
					u.dynamicWrite[typeName] = true
				} else {
					u.dynamicRead[typeName] = true
				}
				return true
			}
			u.keyType[id] = typeName
			site.typedID, site.name = id, name
			u.sites = append(u.sites, site)
			return true
		})
	}
}

// contextKeyCall returns the key of context.WithValue(parent, key, value) or
// ctx.Value(key). Without type information a Value call counts only on a
// receiver that names a context (ctx, r.Context()).
func contextKeyCall(file *ast.File, info *types.Info, call *ast.CallExpr) (ast.Expr, bool, bool) {
	if info != nil {
		key, verb, ok := contextKeyArg(call, info)
		return key, verb == "stored", ok
	}
	if len(call.Args) == 3 && isPackageFuncCall(file, nil, call, "context", "WithValue") {
		return call.Args[1], true, true
	}
	sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Value" || len(call.Args) != 1 {
		return nil, false, false
	}
	receiver := strings.ToLower(types.ExprString(sel.X))
	return call.Args[0], false, strings.HasSuffix(receiver, "ctx") || strings.HasSuffix(receiver, "context()")
}

// keyName returns the identifier a key expression names: Key or pkg.Key.
func keyName(key ast.Expr) string {
	switch expr := ast.Unparen(key).(type) {
	case *ast.Ident:
		return expr.Name
	case *ast.SelectorExpr:
		return expr.Sel.Name
	}
	return ""
}

// contextKeyIdentity names a key the way the context compares it: a
// constant by its type and value, a package-level variable by itself.
func contextKeyIdentity(info *types.Info, key ast.Expr, typeName string) (string, string, bool) {
	name := keyName(key)
	if name == "" {
		return "", "", false
	}
	if tv, ok := info.Types[key]; ok && tv.Value != nil {
		return typeName + "=" + tv.Value.ExactString(), name, true
	}
	ident, ok := ast.Unparen(key).(*ast.Ident)
	if sel, isSel := ast.Unparen(key).(*ast.SelectorExpr); isSel {
		ident, ok = sel.Sel, true
	}
	if !ok {
		return "", "", false
	}
	v, ok := info.Uses[ident].(*types.Var)
	if !ok || v.Pkg() == nil || v.Parent() != v.Pkg().Scope() {
		return "", "", false
	}
	return v.Pkg().Path() + "." + v.Name(), name, true
}

// partialWriters returns, for the key a middleware shares with another
// writer (a middleware or a context builder), the message naming the keys
// of that key's family the other writer stores, this one does not, and some
// code reads. The family is the key name's first word: AdminIDKey and
// AdminRolesKey describe one admin.
func partialWriters(use *contextKeyUse) map[contextKeySite]string {
	type writer struct {
		fn         *ast.FuncDecl
		middleware bool
		keys       map[string]contextKeySite
		order      []string
	}
	writers := map[*ast.FuncDecl]*writer{}
	var order []*writer
	for _, site := range use.sites {
		if !site.write || (!site.middleware && !site.enricher) {
			continue
		}
		w := writers[site.fn]
		if w == nil {
			w = &writer{fn: site.fn, middleware: site.middleware, keys: map[string]contextKeySite{}}
			writers[site.fn] = w
			order = append(order, w)
		}
		id := use.id(site)
		if _, seen := w.keys[id]; !seen {
			w.keys[id] = site
			w.order = append(w.order, id)
		}
	}
	byKey := map[string][]*writer{}
	for _, w := range order {
		for _, id := range w.order {
			byKey[id] = append(byKey[id], w)
		}
	}
	messages := map[contextKeySite]string{}
	for _, part := range order {
		if !part.middleware {
			continue
		}
		for _, shared := range part.order {
			family := keyFamily(part.keys[shared].name)
			for _, whole := range byKey[shared] {
				if whole == part {
					continue
				}
				var missing []string
				for _, id := range whole.order {
					site := whole.keys[id]
					if _, has := part.keys[id]; has || keyFamily(site.name) != family {
						continue
					}
					if use.read[id] || use.dynamicRead[use.keyType[id]] {
						missing = append(missing, site.name)
					}
				}
				if len(missing) == 0 {
					continue
				}
				site := part.keys[shared]
				messages[site] = fmt.Sprintf("%s stores %s but not %s, which %s stores with it and other code reads — requests admitted here miss them",
					part.fn.Name.Name, site.name, strings.Join(missing, ", "), whole.fn.Name.Name)
				break
			}
		}
	}
	return messages
}

// keyFamily returns the first word of a key name: Admin for AdminRolesKey,
// admin for adminRolesKey.
func keyFamily(name string) string {
	for i, r := range name {
		if i > 0 && unicode.IsUpper(r) {
			return name[:i]
		}
	}
	return name
}

// fieldOfType reports a field list holding pkgPath.name for one of names:
// by type with type information, otherwise by a selector on the file's
// import of pkgPath.
func fieldOfType(file *ast.File, info *types.Info, fields *ast.FieldList, pkgPath string, names ...string) bool {
	if fields == nil {
		return false
	}
	aliases := helpers.PackageAliases(file, strconv.Quote(pkgPath), path.Base(pkgPath))
	for _, field := range fields.List {
		for _, name := range names {
			if info != nil {
				if isNamedType(info.TypeOf(field.Type), pkgPath, name) {
					return true
				}
				continue
			}
			sel, ok := ast.Unparen(field.Type).(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != name {
				continue
			}
			if pkg, ok := sel.X.(*ast.Ident); ok && aliases[pkg.Name] {
				return true
			}
		}
	}
	return false
}
