package patterns

import (
	"go/ast"
	"go/token"
	"go/types"
	"regexp"
	"sort"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewPerKeyMutexMapRule())
}

// PerKeyMutexMapRule detects a map of mutexes by key serializing the
// operations on one entity in a package that talks to a database:
//
//	var userLocks = make(map[string]*sync.Mutex)
//
//	lock := userLock(req.UserID)
//	lock.Lock()
//	defer lock.Unlock()
//	balance, err := s.repo.Balance(ctx, req.UserID)
//
// The lock holds inside one process only: a second instance, a worker or a
// restart runs the same operation on the same user at once, and the check
// before the write passes twice. The map also keeps a mutex for every key
// it ever saw. The database is what the processes share: lock the row
// (SELECT ... FOR UPDATE) or take an advisory lock.
type PerKeyMutexMapRule struct {
	*rules.BaseRule
}

// NewPerKeyMutexMapRule creates the rule
func NewPerKeyMutexMapRule() *PerKeyMutexMapRule {
	return &PerKeyMutexMapRule{BaseRule: rules.NewBaseRule(
		"per-key-mutex-map",
		"patterns",
		"Detects a map of mutexes by key, or a service mutex guarding no data of its own, serializing database operations — the lock holds in one process only",
		core.SeverityMedium,
	)}
}

// AnalyzeFile reports the mutex maps of a file that also queries a database.
func (r *PerKeyMutexMapRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !productionGoFile(ctx) || !queriesDatabase(ctx.GoAST) {
		return nil
	}
	var violations []*core.Violation
	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		mapType, ok := n.(*ast.MapType)
		if !ok || !isSyncMutexExpr(mapType.Value) {
			return true
		}
		line := ctx.LineFor(mapType)
		if ctx.IsSuppressed(line, r.Name()) {
			return true
		}
		v := r.CreateViolation(ctx.RelPath, line, "Map of mutexes by key guards database operations — the lock holds in this process only, another instance or a worker runs the same operation at once")
		v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
		v.WithSuggestion("Lock in the database the processes share: SELECT ... FOR UPDATE on the entity's row, or pg_advisory_xact_lock on its key")
		violations = append(violations, v)
		return true
	})
	return append(violations, r.structMutexes(ctx)...)
}

// mutexHolder is a struct type of the file with mutex fields.
type mutexHolder struct {
	mutexes map[string]bool
	// state are the fields holding data of the value itself: maps, slices,
	// numbers, strings — what a mutex is there to guard.
	state map[string]bool
	// store: the type holds a repository or a database handle.
	store bool
}

// mutexKey is one mutex field of one type.
type mutexKey struct {
	typeName, mutex string
}

var storeFieldName = regexp.MustCompile(`(?i)repo|store|dao|\bdb\b|^db|database`)

// structMutexes reports a service's mutex field that guards none of the
// service's own data, only operations that write to a database:
//
//	type TransactionService struct {
//	    txRepo *repository.TransactionRepository
//	    syncMu sync.Mutex
//	}
//
//	func (s *TransactionService) SyncWallet(ctx context.Context, wallet string) error {
//	    s.syncMu.Lock()
//	    defer s.syncMu.Unlock()
//	    ... s.txRepo.UpsertBatch(ctx, rows)
//
// It serializes the operation inside one process: a second instance, a
// worker or an overlapping deploy runs it at the same time against the same
// rows. Not reported: a mutex any locking method reads or writes data of the
// value under (a cache, a counter), or one handed on as a value.
func (r *PerKeyMutexMapRule) structMutexes(ctx *core.FileContext) []*core.Violation {
	holders := mutexHolders(ctx.GoAST)
	if len(holders) == 0 {
		return nil
	}
	locks := make(map[mutexKey][]*ast.CallExpr)
	guards := make(map[mutexKey]bool)
	for _, decl := range ctx.GoAST.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || fn.Recv == nil || len(fn.Recv.List) != 1 || len(fn.Recv.List[0].Names) != 1 {
			continue
		}
		typeName := receiverTypeName(fn.Recv)
		holder := holders[typeName]
		if holder == nil {
			continue
		}
		recv := fn.Recv.List[0].Names[0].Name
		locked := mutexUses(fn.Body, typeName, recv, holder, locks, guards)
		if touchesHolderState(fn.Body, recv, holder) {
			for _, key := range locked {
				guards[key] = true
			}
		}
	}
	var violations []*core.Violation
	for key, calls := range locks {
		if guards[key] || !holders[key.typeName].store {
			continue
		}
		for _, call := range calls {
			line := ctx.LineFor(call)
			if ctx.IsSuppressed(line, r.Name()) {
				continue
			}
			v := r.CreateViolation(ctx.RelPath, line, key.typeName+"."+key.mutex+" guards no data of "+key.typeName+", only work on the database — the lock holds in this process only, another instance or a worker runs the same operation at once")
			v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
			v.WithSuggestion("Lock in the database the processes share: pg_advisory_xact_lock on the operation's key, or SELECT ... FOR UPDATE on its row")
			violations = append(violations, v)
		}
	}
	sort.Slice(violations, func(i, j int) bool { return violations[i].Line < violations[j].Line })
	return violations
}

// touchesHolderState reports a method body reading or writing a data field
// of its receiver.
func touchesHolderState(body *ast.BlockStmt, recv string, holder *mutexHolder) bool {
	touches := false
	ast.Inspect(body, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return !touches
		}
		if owner, ok := sel.X.(*ast.Ident); ok && owner.Name == recv && holder.state[sel.Sel.Name] {
			touches = true
		}
		return !touches
	})
	return touches
}

// mutexUses records the Lock calls on the receiver's mutexes into locks and
// marks as guards a mutex used otherwise (handed on, a TryLock); it returns
// the mutexes the body locks.
func mutexUses(body *ast.BlockStmt, typeName, recv string, holder *mutexHolder, locks map[mutexKey][]*ast.CallExpr, guards map[mutexKey]bool) []mutexKey {
	var locked []mutexKey
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CallExpr:
			method, ok := node.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			field, ok := method.X.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			owner, ok := field.X.(*ast.Ident)
			if !ok || owner.Name != recv || !holder.mutexes[field.Sel.Name] {
				return true
			}
			key := mutexKey{typeName, field.Sel.Name}
			switch method.Sel.Name {
			case "Lock", "RLock":
				locks[key] = append(locks[key], node)
				locked = append(locked, key)
			case "Unlock", "RUnlock":
			default:
				guards[key] = true
			}
			return false
		case *ast.UnaryExpr:
			// &s.mu handed on: what it guards is decided elsewhere.
			if field, ok := node.X.(*ast.SelectorExpr); ok && node.Op == token.AND {
				if owner, ok := field.X.(*ast.Ident); ok && owner.Name == recv && holder.mutexes[field.Sel.Name] {
					guards[mutexKey{typeName, field.Sel.Name}] = true
				}
			}
		}
		return true
	})
	return locked
}

// mutexHolders returns the struct types of a file with mutex fields.
func mutexHolders(file *ast.File) map[string]*mutexHolder {
	holders := make(map[string]*mutexHolder)
	ast.Inspect(file, func(n ast.Node) bool {
		spec, ok := n.(*ast.TypeSpec)
		if !ok {
			return true
		}
		st, ok := spec.Type.(*ast.StructType)
		if !ok {
			return false
		}
		holder := &mutexHolder{mutexes: make(map[string]bool), state: make(map[string]bool)}
		for _, field := range st.Fields.List {
			typeText := types.ExprString(field.Type)
			for _, name := range field.Names {
				switch {
				case isSyncMutexExpr(field.Type):
					holder.mutexes[name.Name] = true
				case holdsState(field.Type):
					holder.state[name.Name] = true
				}
				if storeFieldName.MatchString(name.Name) || storeFieldName.MatchString(typeText) {
					holder.store = true
				}
			}
		}
		if len(holder.mutexes) > 0 {
			holders[spec.Name.Name] = holder
		}
		return false
	})
	return holders
}

// holdsState reports a field type holding data of its own: a map, a slice
// or an array, a number, a string, a bool, a struct of the package. A
// pointer, an interface, a func or a channel, and a type of another package
// (a duration, a client) are dependencies and settings.
func holdsState(expr ast.Expr) bool {
	switch expr.(type) {
	case *ast.MapType, *ast.ArrayType, *ast.StructType, *ast.Ident:
		return true
	}
	return false
}

// isSyncMutexExpr reports sync.Mutex, sync.RWMutex or a pointer to one.
func isSyncMutexExpr(expr ast.Expr) bool {
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = star.X
	}
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "sync" && (sel.Sel.Name == "Mutex" || sel.Sel.Name == "RWMutex")
}

// queriesDatabase reports a file passing SQL text or calling a
// repository: the operations its locks guard reach a database.
func queriesDatabase(file *ast.File) bool {
	if len(sqlCalls(file)) > 0 {
		return true
	}
	found := false
	ast.Inspect(file, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return !found
		}
		if inner, ok := sel.X.(*ast.SelectorExpr); ok && strings.Contains(strings.ToLower(inner.Sel.Name), "repo") {
			found = true
		}
		return !found
	})
	return found
}
