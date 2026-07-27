package patterns

import (
	"errors"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"sort"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewUnguardedSharedFieldRule())
}

// lockedNameSuffixes mark a method whose contract is "the caller already holds
// the lock", so touching the field without taking it again is deliberate.
var lockedNameSuffixes = []string{"locked", "nolock", "unsafe", "unlocked"}

// UnguardedSharedFieldRule detects a field that some methods protect with the
// struct's mutex and others touch without it:
//
//	func (c *Counter) Add(n int) { c.mu.Lock(); defer c.mu.Unlock(); c.value += n }
//	func (c *Counter) Reset()    { c.value = 0 }   // same field, no lock
//
// The lock proves the field is shared between goroutines; the method that skips
// it is a data race. Unlike a missing Unlock it breaks nothing locally, and the
// race detector only reports it when two goroutines happen to collide during a
// test — so it survives review and CI and fails in production.
//
// Not flagged: fields no method ever guards (they may be immutable after
// construction), helpers called from inside a critical section, methods whose
// name promises the caller holds the lock (…Locked, …NoLock, …Unsafe), and
// plain functions such as constructors, where the value is not shared yet.
type UnguardedSharedFieldRule struct {
	*rules.BaseRule
}

// NewUnguardedSharedFieldRule creates the rule
func NewUnguardedSharedFieldRule() *UnguardedSharedFieldRule {
	return &UnguardedSharedFieldRule{
		BaseRule: rules.NewBaseRule(
			"unguarded-shared-field",
			"patterns",
			"Detects fields guarded by a mutex in some methods and touched without it in others (data race)",
			core.SeverityHigh,
		),
	}
}

// AnalyzeFile is a no-op: the methods of a type may live in several files.
func (r *UnguardedSharedFieldRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that typed syntax is enough for this rule.
func (r *UnguardedSharedFieldRule) RequiresSSA() bool { return false }

// guardedType is a struct that owns at least one mutex.
type guardedType struct {
	named *types.Named
	// mutexFields holds the field names of the mutexes; an embedded mutex is
	// stored as "" because it is locked on the receiver itself.
	mutexFields map[string]bool
}

// fieldAccess is one mention of a field inside a method of its own type.
type fieldAccess struct {
	fileCtx  *core.FileContext
	pos      token.Pos
	method   string
	guarded  bool
	mutating bool
}

// AnalyzeGoProject compares, for every mutex-owning type, where its fields are
// touched under the lock and where they are not.
func (r *UnguardedSharedFieldRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, errors.New("unguarded shared field: nil Go project context")
	}

	var violations []*core.Violation
	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil || pkg.Package.TypesInfo == nil {
			return nil, errors.New("unguarded shared field: package has no typed syntax")
		}
		pkgViolations, err := r.analyzePackage(pkg)
		if err != nil {
			return nil, err
		}
		violations = append(violations, pkgViolations...)
	}

	sort.SliceStable(violations, func(i, j int) bool {
		if violations[i].File != violations[j].File {
			return violations[i].File < violations[j].File
		}
		return violations[i].Line < violations[j].Line
	})
	return violations, nil
}

func (r *UnguardedSharedFieldRule) analyzePackage(pkg *core.GoPackageContext) ([]*core.Violation, error) {
	info := pkg.Package.TypesInfo
	guarded := collectGuardedTypes(pkg)
	if len(guarded) == 0 {
		return nil, nil
	}

	accesses := make(map[*types.Var][]fieldAccess)
	calledUnderLock := make(map[string]bool)

	for _, fileCtx := range pkg.Files {
		if fileCtx.GoAST == nil || fileCtx.IsTestFile() {
			continue
		}
		for _, decl := range fileCtx.GoAST.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || fn.Recv == nil {
				continue
			}
			owner, receiver, ok := methodOwner(fn, info, guarded)
			if !ok {
				continue
			}
			collectFieldAccesses(fileCtx, fn, receiver, owner, info, accesses, calledUnderLock)
		}
	}

	var violations []*core.Violation
	for field, list := range accesses {
		if !guardedByMutex(field, list) {
			continue
		}
		for _, access := range list {
			if access.guarded || calledUnderLock[access.method] || hasLockedName(access.method) {
				continue
			}
			violations = append(violations, r.report(field, access, guarded))
		}
	}
	return violations, nil
}

func (r *UnguardedSharedFieldRule) report(field *types.Var, access fieldAccess, guarded map[*types.Named]guardedType) *core.Violation {
	line := access.fileCtx.LineForPos(access.pos)
	v := r.CreateViolation(access.fileCtx.RelPath, line,
		fmt.Sprintf("Field %q is guarded by %s in other methods but %s touches it without the lock — concurrent access is a data race",
			field.Name(), mutexNames(guarded), access.method))
	v.WithCode(strings.TrimSpace(access.fileCtx.GetLine(line)))
	v.WithSuggestion(fmt.Sprintf("Take the same lock in %s, or move the access into a helper the locked methods call",
		access.method))
	v.WithContext("pattern", "unguarded_shared_field")
	v.WithContext("field", field.Name())
	return v
}

// mutexNames renders the mutex field names of the analyzed types for the message.
func mutexNames(guarded map[*types.Named]guardedType) string {
	names := make([]string, 0, len(guarded))
	seen := make(map[string]bool)
	for _, entry := range guarded {
		for name := range entry.mutexFields {
			if name == "" {
				name = "the embedded mutex"
			}
			if seen[name] {
				continue
			}
			seen[name] = true
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return strings.Join(names, "/")
}

// collectGuardedTypes returns the package's struct types that own a mutex.
func collectGuardedTypes(pkg *core.GoPackageContext) map[*types.Named]guardedType {
	guarded := make(map[*types.Named]guardedType)

	for _, name := range pkg.Package.Types.Scope().Names() {
		obj, ok := pkg.Package.Types.Scope().Lookup(name).(*types.TypeName)
		if !ok {
			continue
		}
		named, ok := obj.Type().(*types.Named)
		if !ok {
			continue
		}
		structType, ok := named.Underlying().(*types.Struct)
		if !ok {
			continue
		}

		mutexFields := make(map[string]bool)
		for i := range structType.NumFields() {
			field := structType.Field(i)
			if !isMutexType(field.Type()) {
				continue
			}
			if field.Embedded() {
				mutexFields[""] = true
				continue
			}
			mutexFields[field.Name()] = true
		}
		if len(mutexFields) > 0 {
			guarded[named] = guardedType{named: named, mutexFields: mutexFields}
		}
	}

	return guarded
}

// isMutexType reports whether the type is a sync mutex, by value or by pointer.
func isMutexType(t types.Type) bool {
	if ptr, ok := t.(*types.Pointer); ok {
		t = ptr.Elem()
	}
	named, ok := t.(*types.Named)
	if !ok || named.Obj().Pkg() == nil {
		return false
	}
	if named.Obj().Pkg().Path() != "sync" {
		return false
	}
	return named.Obj().Name() == "Mutex" || named.Obj().Name() == "RWMutex"
}

// methodOwner returns the mutex-owning type the method belongs to, together
// with the receiver name it is reached through.
func methodOwner(fn *ast.FuncDecl, info *types.Info, guarded map[*types.Named]guardedType) (guardedType, string, bool) {
	if len(fn.Recv.List) != 1 || len(fn.Recv.List[0].Names) != 1 {
		return guardedType{}, "", false
	}
	receiver := fn.Recv.List[0].Names[0].Name
	if receiver == "" || receiver == "_" {
		return guardedType{}, "", false
	}

	obj, ok := info.Defs[fn.Recv.List[0].Names[0]].(*types.Var)
	if !ok {
		return guardedType{}, "", false
	}
	t := obj.Type()
	if ptr, ok := t.(*types.Pointer); ok {
		t = ptr.Elem()
	}
	named, ok := t.(*types.Named)
	if !ok {
		return guardedType{}, "", false
	}
	owner, ok := guarded[named]
	return owner, receiver, ok
}

// collectFieldAccesses records every `receiver.field` mention of the method and
// whether it happens inside a critical section, plus the sibling methods the
// critical sections call.
func collectFieldAccesses(
	fileCtx *core.FileContext,
	fn *ast.FuncDecl,
	receiver string,
	owner guardedType,
	info *types.Info,
	accesses map[*types.Var][]fieldAccess,
	calledUnderLock map[string]bool,
) {
	sections := criticalSections(fn, receiver, owner.mutexFields)
	mutations := mutatedSelectors(fn)

	ast.Inspect(fn.Body, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		base, ok := sel.X.(*ast.Ident)
		if !ok || base.Name != receiver {
			return true
		}

		selection, ok := info.Selections[sel]
		if !ok {
			return true
		}
		inSection := within(sections, sel.Pos())

		switch selection.Kind() {
		case types.FieldVal:
			field, ok := selection.Obj().(*types.Var)
			if !ok || isMutexType(field.Type()) {
				return true
			}
			accesses[field] = append(accesses[field], fieldAccess{
				fileCtx:  fileCtx,
				pos:      sel.Pos(),
				method:   fn.Name.Name,
				guarded:  inSection,
				mutating: mutations[sel.Pos()],
			})
		case types.MethodVal:
			if inSection {
				calledUnderLock[sel.Sel.Name] = true
			}
		}
		return true
	})
}

// mutatedSelectors returns the positions of the selectors the method writes to:
// assignment targets, ++/--, map and slice element writes, delete arguments and
// taken addresses.
func mutatedSelectors(fn *ast.FuncDecl) map[token.Pos]bool {
	mutated := make(map[token.Pos]bool)

	mark := func(expr ast.Expr) {
		for {
			switch e := expr.(type) {
			case *ast.IndexExpr:
				expr = e.X
			case *ast.StarExpr:
				expr = e.X
			case *ast.ParenExpr:
				expr = e.X
			case *ast.SelectorExpr:
				mutated[e.Pos()] = true
				return
			default:
				return
			}
		}
	}

	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			for _, lhs := range node.Lhs {
				mark(lhs)
			}
		case *ast.IncDecStmt:
			mark(node.X)
		case *ast.UnaryExpr:
			if node.Op == token.AND {
				mark(node.X)
			}
		case *ast.CallExpr:
			if ident, ok := node.Fun.(*ast.Ident); ok && ident.Name == "delete" && len(node.Args) > 0 {
				mark(node.Args[0])
			}
		}
		return true
	})

	return mutated
}

// criticalSection is the source range in which a lock is held.
type criticalSection struct {
	start token.Pos
	end   token.Pos
}

// criticalSections returns the ranges of the method body where one of the
// receiver's mutexes is held. A deferred Unlock holds the lock until the end of
// the body; an explicit Unlock ends the section where it is called.
func criticalSections(fn *ast.FuncDecl, receiver string, mutexFields map[string]bool) []criticalSection {
	type lockEvent struct {
		pos      token.Pos
		mutex    string
		locking  bool
		deferred bool
	}

	var events []lockEvent
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.DeferStmt:
			if call, ok := unlockCall(node.Call); ok && ownedMutex(call.receiver, receiver, mutexFields) {
				events = append(events, lockEvent{pos: node.Pos(), mutex: call.receiver, deferred: true})
			}
		case *ast.CallExpr:
			if call, ok := lockCall(node); ok && ownedMutex(call.receiver, receiver, mutexFields) {
				events = append(events, lockEvent{pos: node.Pos(), mutex: call.receiver, locking: true})
				return true
			}
			if call, ok := unlockCall(node); ok && ownedMutex(call.receiver, receiver, mutexFields) {
				events = append(events, lockEvent{pos: node.Pos(), mutex: call.receiver})
			}
		}
		return true
	})

	sort.SliceStable(events, func(i, j int) bool { return events[i].pos < events[j].pos })

	var sections []criticalSection
	for i, event := range events {
		if !event.locking {
			continue
		}
		end := fn.Body.End()
		for _, later := range events[i+1:] {
			if later.locking || later.mutex != event.mutex {
				continue
			}
			if later.deferred {
				break // the lock is held until the body ends
			}
			end = later.pos
			break
		}
		sections = append(sections, criticalSection{start: event.pos, end: end})
	}
	return sections
}

// ownedMutex reports whether the locked expression is one of the receiver's
// mutex fields: "c.mu" for a named field, "c" for an embedded one.
func ownedMutex(locked, receiver string, mutexFields map[string]bool) bool {
	if locked == receiver {
		return mutexFields[""]
	}
	name, ok := strings.CutPrefix(locked, receiver+".")
	return ok && mutexFields[name]
}

func within(sections []criticalSection, pos token.Pos) bool {
	for _, section := range sections {
		if pos >= section.start && pos <= section.end {
			return true
		}
	}
	return false
}

// guardedByMutex reports whether the mutex is meant to protect this field.
// A mutation under the lock says so outright. For a reference type — a map, a
// slice, a channel, a pointer — reading it under the lock says so too, because
// the contents are what the lock protects. A plain value merely read inside a
// critical section proves nothing: a setting configured once before any
// goroutine starts is often read there by accident.
func guardedByMutex(field *types.Var, list []fieldAccess) bool {
	// Поле, которое ни один метод не меняет, — это зависимость, выставленная
	// конструктором (logger, config, репозиторий). Гонки на нём нет, и мьютекс
	// защищает не его, даже если оно читается внутри критической секции.
	mutatedSomewhere := false
	for _, access := range list {
		if access.mutating {
			mutatedSomewhere = true
			break
		}
	}
	if !mutatedSomewhere {
		return false
	}

	reference := isReferenceType(field.Type())
	for _, access := range list {
		if access.guarded && (access.mutating || reference) {
			return true
		}
	}
	return false
}

func isReferenceType(t types.Type) bool {
	switch t.Underlying().(type) {
	case *types.Map, *types.Slice, *types.Chan, *types.Pointer, *types.Interface:
		return true
	}
	return false
}

func hasLockedName(method string) bool {
	lower := strings.ToLower(method)
	for _, suffix := range lockedNameSuffixes {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	return false
}
