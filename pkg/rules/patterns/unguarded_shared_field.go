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

// UnguardedSharedFieldRule detects a field that some methods protect with a
// mutex and others touch without it:
//
//	func (c *Counter) Add(n int) { c.mu.Lock(); defer c.mu.Unlock(); c.value += n }
//	func (c *Counter) Reset()    { c.value = 0 }   // same field, no lock
//
// The lock proves the field is shared between goroutines; the method that skips
// it is a data race. Unlike a missing Unlock it breaks nothing locally, and the
// race detector only reports it when two goroutines happen to collide during a
// test — so it survives review and CI and fails in production.
//
// A lock covers the object that owns it, at any depth: s.metrics.mu.Lock()
// guards s.metrics.total, not s.other.
//
// Not flagged: fields no lock ever covers (they may be set once and only read
// afterwards), helpers called from inside a critical section, methods whose name
// promises the caller holds the lock (…Locked, …NoLock, …Unsafe), and plain
// functions such as constructors, where the value is not shared yet.
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

// fieldAccess is one mention of a field inside a method of its own type.
type fieldAccess struct {
	fileCtx  *core.FileContext
	pos      token.Pos
	method   string
	mutex    string
	guarded  bool
	mutating bool
}

// AnalyzeGoProject compares, for every field a lock covers somewhere, the places
// that take the lock with the places that do not.
func (r *UnguardedSharedFieldRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, errors.New("unguarded shared field: nil Go project context")
	}

	var violations []*core.Violation
	for _, pkg := range ctx.Packages {
		if pkg == nil || pkg.Package == nil || pkg.Package.TypesInfo == nil {
			return nil, errors.New("unguarded shared field: package has no typed syntax")
		}
		violations = append(violations, r.analyzePackage(pkg)...)
	}

	sort.SliceStable(violations, func(i, j int) bool {
		if violations[i].File != violations[j].File {
			return violations[i].File < violations[j].File
		}
		return violations[i].Line < violations[j].Line
	})
	return violations, nil
}

func (r *UnguardedSharedFieldRule) analyzePackage(pkg *core.GoPackageContext) []*core.Violation {
	info := pkg.Package.TypesInfo
	accesses := make(map[*types.Var][]fieldAccess)
	fieldOrder := make([]*types.Var, 0)
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
			receiver, ok := receiverName(fn)
			if !ok {
				continue
			}
			collectFieldAccesses(fileCtx, fn, receiver, info, accesses, &fieldOrder, calledUnderLock)
		}
	}

	var violations []*core.Violation
	for _, field := range fieldOrder {
		list := accesses[field]
		if !guardedByMutex(field, list) {
			continue
		}
		mutex := guardingMutex(list)
		for _, access := range list {
			if access.guarded || calledUnderLock[access.method] || hasLockedName(access.method) {
				continue
			}
			violations = append(violations, r.report(field, access, mutex))
		}
	}
	return violations
}

func (r *UnguardedSharedFieldRule) report(field *types.Var, access fieldAccess, mutex string) *core.Violation {
	line := access.fileCtx.LineForPos(access.pos)
	v := r.CreateViolation(access.fileCtx.RelPath, line,
		fmt.Sprintf("Field %q is guarded by %s in other methods but %s touches it without the lock — concurrent access is a data race",
			field.Name(), mutex, access.method))
	v.WithCode(strings.TrimSpace(access.fileCtx.GetLine(line)))
	v.WithSuggestion(fmt.Sprintf("Take %s in %s too, or move the access into a helper the locked methods call",
		mutex, access.method))
	v.WithContext("pattern", "unguarded_shared_field")
	v.WithContext("field", field.Name())
	return v
}

// guardedByMutex reports whether a lock is meant to protect this field.
// A mutation under the lock says so outright. For a map, a slice or a channel,
// reading it under the lock says so too, because the contents are what the lock
// protects. A plain value merely read inside a critical section proves nothing:
// a setting configured once before any goroutine starts is often read there by
// accident.
func guardedByMutex(field *types.Var, list []fieldAccess) bool {
	contents := hasSharedContents(field.Type())
	for _, access := range list {
		if access.guarded && (access.mutating || contents) {
			return true
		}
	}
	return false
}

// guardingMutex returns the lock that covers the field, for the message.
func guardingMutex(list []fieldAccess) string {
	for _, access := range list {
		if access.guarded && access.mutex != "" {
			return access.mutex
		}
	}
	return "a mutex"
}

// hasSharedContents reports whether the value behind the field is mutated
// through the field rather than by replacing it.
func hasSharedContents(t types.Type) bool {
	switch t.Underlying().(type) {
	case *types.Map, *types.Slice, *types.Chan:
		return true
	}
	return false
}

func receiverName(fn *ast.FuncDecl) (string, bool) {
	if len(fn.Recv.List) != 1 || len(fn.Recv.List[0].Names) != 1 {
		return "", false
	}
	name := fn.Recv.List[0].Names[0].Name
	if name == "" || name == "_" {
		return "", false
	}
	return name, true
}

// collectFieldAccesses records every `receiver.…` field mention of the method
// and whether a lock covering it is held, plus the sibling methods the critical
// sections call.
func collectFieldAccesses(
	fileCtx *core.FileContext,
	fn *ast.FuncDecl,
	receiver string,
	info *types.Info,
	accesses map[*types.Var][]fieldAccess,
	fieldOrder *[]*types.Var,
	calledUnderLock map[string]bool,
) {
	sections := criticalSections(fn, info)
	mutations, atomicAccesses := mutatedSelectors(fn)

	ast.Inspect(fn.Body, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		path := receiverChain(sel)
		if path == "" || !strings.HasPrefix(path, receiver+".") {
			return true
		}

		selection, ok := info.Selections[sel]
		if !ok {
			return true
		}
		mutex, inSection := coveringSection(sections, path, sel.Pos())

		switch selection.Kind() {
		case types.FieldVal:
			field, ok := selection.Obj().(*types.Var)
			if !ok || isMutexType(field.Type()) {
				return true
			}
			if atomicAccesses[sel.Pos()] {
				return false
			}
			// Доступ через sync/atomic синхронизирован сам по себе — мьютекс ему не нужен.
			if atomicAccesses[sel.Pos()] {
				return false
			}
			if _, seen := accesses[field]; !seen {
				*fieldOrder = append(*fieldOrder, field)
			}
			accesses[field] = append(accesses[field], fieldAccess{
				fileCtx:  fileCtx,
				pos:      sel.Pos(),
				method:   fn.Name.Name,
				mutex:    mutex,
				guarded:  inSection,
				mutating: mutations[sel.Pos()],
			})
			// The path stops here: `s.metrics.total` is an access to total, not
			// to metrics.
			return false
		case types.MethodVal:
			if inSection && !isMutexMethod(selection) {
				calledUnderLock[sel.Sel.Name] = true
			}
		}
		return true
	})
}

// mutatedSelectors returns the positions of the selectors the method writes to
// — assignment targets, ++/--, map and slice element writes, delete arguments
// and taken addresses — and, separately, those handed to sync/atomic.
func mutatedSelectors(fn *ast.FuncDecl) (mutated, atomicAccess map[token.Pos]bool) {
	mutated = make(map[token.Pos]bool)
	atomicAccess = make(map[token.Pos]bool)

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

	markAtomic := func(expr ast.Expr) {
		for {
			switch e := expr.(type) {
			case *ast.IndexExpr:
				expr = e.X
			case *ast.StarExpr:
				expr = e.X
			case *ast.ParenExpr:
				expr = e.X
			case *ast.SelectorExpr:
				atomicAccess[e.Pos()] = true
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
			// atomic.AddInt64(&s.counter) synchronizes on its own: counting such
			// an access as unguarded would demand a lock where none is needed.
			if sel, ok := node.Fun.(*ast.SelectorExpr); ok {
				if pkgIdent, ok := sel.X.(*ast.Ident); ok && pkgIdent.Name == "atomic" {
					for _, arg := range node.Args {
						if unary, ok := arg.(*ast.UnaryExpr); ok && unary.Op == token.AND {
							markAtomic(unary.X)
						}
					}
				}
			}
		}
		return true
	})

	return mutated, atomicAccess
}

// criticalSection is the source range in which a lock is held, together with
// the path of the object it covers: "s" for s.mu.Lock(), "s.metrics" for
// s.metrics.mu.Lock().
type criticalSection struct {
	owner string
	mutex string
	start token.Pos
	end   token.Pos
}

// criticalSections returns the ranges of the method body where a lock is held.
//
// The Unlock that ends a section is the one standing beside the Lock in the same
// statement list. An Unlock nested deeper — the classic `if closed { mu.Unlock();
// return }` — releases the lock on its own path only, and the statements after
// the if are still protected.
func criticalSections(fn *ast.FuncDecl, info *types.Info) []criticalSection {
	var sections []criticalSection

	ast.Inspect(fn.Body, func(n ast.Node) bool {
		for _, list := range statementLists(n) {
			sections = append(sections, sectionsInList(list, fn, info)...)
		}
		return true
	})

	return sections
}

// statementLists returns the statement sequences a node holds directly.
func statementLists(n ast.Node) [][]ast.Stmt {
	switch node := n.(type) {
	case *ast.BlockStmt:
		return [][]ast.Stmt{node.List}
	case *ast.CaseClause:
		return [][]ast.Stmt{node.Body}
	case *ast.CommClause:
		return [][]ast.Stmt{node.Body}
	}
	return nil
}

// sectionsInList pairs each Lock in the list with the Unlock that follows it at
// the same level, or with the end of the enclosing scope when there is none.
func sectionsInList(list []ast.Stmt, fn *ast.FuncDecl, info *types.Info) []criticalSection {
	var sections []criticalSection

	for i, stmt := range list {
		call, ok := callOf(stmt)
		if !ok {
			continue
		}
		owner, mutex, ok := mutexTarget(call, info, lockMethodNames)
		if !ok {
			continue
		}

		end := fn.Body.End()
		for _, later := range list[i+1:] {
			if deferred, ok := later.(*ast.DeferStmt); ok {
				if _, deferredMutex, ok := mutexTarget(deferred.Call, info, unlockMethods); ok && deferredMutex == mutex {
					break // the lock is held until the body ends
				}
				continue
			}
			laterCall, ok := callOf(later)
			if !ok {
				continue
			}
			if _, laterMutex, ok := mutexTarget(laterCall, info, unlockMethods); ok && laterMutex == mutex {
				end = later.Pos()
				break
			}
		}
		sections = append(sections, criticalSection{owner: owner, mutex: mutex, start: stmt.Pos(), end: end})
	}

	return sections
}

// callOf returns the call of a bare call statement.
func callOf(stmt ast.Stmt) (*ast.CallExpr, bool) {
	exprStmt, ok := stmt.(*ast.ExprStmt)
	if !ok {
		return nil, false
	}
	call, ok := exprStmt.X.(*ast.CallExpr)
	return call, ok
}

// mutexTarget reports the object a Lock/Unlock call covers and the mutex path
// used, for calls whose method really belongs to a sync mutex.
func mutexTarget(call *ast.CallExpr, info *types.Info, methods map[string]bool) (owner, mutex string, ok bool) {
	sel, isSelector := call.Fun.(*ast.SelectorExpr)
	if !isSelector || !methods[sel.Sel.Name] {
		return "", "", false
	}
	selection, found := info.Selections[sel]
	if !found || !isMutexMethod(selection) {
		return "", "", false
	}

	path := receiverChain(sel.X)
	if path == "" {
		return "", "", false
	}
	// c.mu.Lock() locks the field itself, so the object it covers is c;
	// c.Lock() on an embedded mutex is already called on that object.
	if isMutexType(info.TypeOf(sel.X)) {
		return trimLastSegment(path), path, true
	}
	return path, path + ".(embedded)", true
}

func trimLastSegment(path string) string {
	idx := strings.LastIndex(path, ".")
	if idx < 0 {
		return path
	}
	return path[:idx]
}

// isMutexMethod reports whether the selected method is declared on a sync mutex.
func isMutexMethod(selection *types.Selection) bool {
	fn, ok := selection.Obj().(*types.Func)
	if !ok {
		return false
	}
	signature, ok := fn.Type().(*types.Signature)
	if !ok || signature.Recv() == nil {
		return false
	}
	return isMutexType(signature.Recv().Type())
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

// coveringSection reports whether a lock covering the accessed path is held at
// the position, and which mutex it is.
func coveringSection(sections []criticalSection, path string, pos token.Pos) (string, bool) {
	for _, section := range sections {
		if pos < section.start || pos > section.end {
			continue
		}
		if path == section.owner || strings.HasPrefix(path, section.owner+".") {
			return section.mutex, true
		}
	}
	return "", false
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
