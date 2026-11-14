package httprules

import (
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/tools/go/ssa"
)

// auditMethodHasActorDirect is auditMethodHasActor as a search over every
// function of the index per method, with no memo: the path the grouped and
// memoized one replaces.
func auditMethodHasActorDirect(root *ssa.Function, index *auditCallIndex) bool {
	if auditActorParameter(root) || auditFunctionHasHumanRoot(root) {
		return true
	}
	for _, function := range index.functions {
		if function != root && auditFunctionRoot(function) == root && auditFunctionHasHumanRoot(function) {
			return true
		}
	}
	return false
}

func TestAuditMethodHasActorMatchesDirectSearch(t *testing.T) {
	project := loadAuditProject(t, map[string]string{"service.go": `package audit
type Request struct { AdminID int; Note string }
type Service struct{}
func (s *Service) param(id string, actorUserID int) error { return nil }
func (s *Service) direct(req *Request) int { return req.AdminID }
func (s *Service) inClosure(req *Request) error {
	return run(func() error { _ = req.AdminID; return nil })
}
func (s *Service) nested(req *Request) error {
	return run(func() error {
		return run(func() error { _ = req.AdminID; return nil })
	})
}
func (s *Service) noActor(req *Request) error {
	return run(func() error { _ = req.Note; return nil })
}
func plain(id string) string { return id }
func run(fn func() error) error { return fn() }
`})
	index := buildAuditCallIndex(project.Program, project.FileSet)
	nested := auditNestedFunctions(index.functions)
	analyzer := &auditActorAnalyzer{humanRoots: make(map[*ssa.Function]bool)}
	got := map[string]bool{}
	for _, function := range index.functions {
		if auditFunctionRoot(function) != function || function.Pkg == nil || function.Pkg.Pkg.Path() != "example.com/audit" {
			continue
		}
		want := auditMethodHasActorDirect(function, index)
		assert.Equal(t, want, auditMethodHasActor(function, nested[function], analyzer.hasHumanRoot), function.String())
		got[function.Name()] = want
	}
	require.Contains(t, got, "nested")
	assert.True(t, got["param"], "a parameter named for the actor")
	assert.True(t, got["direct"], "the actor read in the method")
	assert.True(t, got["inClosure"], "the actor read in a closure")
	assert.True(t, got["nested"], "the actor read in a closure of a closure")
	assert.False(t, got["noActor"])
	assert.False(t, got["plain"])
	assert.Len(t, nested[findAuditFunction(t, index, "nested")], 2, "both closures of nested, the inner one too")
}

func findAuditFunction(t *testing.T, index *auditCallIndex, name string) *ssa.Function {
	t.Helper()
	for _, function := range index.functions {
		if function.Name() == name && function.Parent() == nil {
			return function
		}
	}
	t.Fatalf("no function %s", name)
	return nil
}

// The index sorts every function, then the targets of every call, with one
// set of names: the order is that of a sort by String alone.
func TestAuditCallIndexOrderMatchesSortByString(t *testing.T) {
	project := loadAuditProject(t, map[string]string{"service.go": `package audit
type Saver interface { Save(id string) error }
type A struct{}
type B struct{}
func (A) Save(id string) error { return nil }
func (B) Save(id string) error { return nil }
func store(s Saver, id string) error { return s.Save(id) }
func both(id string) error { _ = store(A{}, id); return store(B{}, id) }
`})
	index := buildAuditCallIndex(project.Program, project.FileSet)
	byString := func(functions []*ssa.Function) bool {
		return slices.IsSortedFunc(functions, func(a, b *ssa.Function) int { return strings.Compare(a.String(), b.String()) })
	}
	assert.True(t, byString(index.functions))
	multiple := 0
	for call, targets := range index.targets {
		assert.True(t, byString(targets), call.String())
		if len(targets) > 1 {
			multiple++
		}
	}
	assert.Positive(t, multiple, "an interface call with two implementations has its targets sorted")
}

// A status write in a deferred closure gets no human context from its method:
// the actor the method has - a parameter named for it, or one it reads - is
// what makes the write without the sibling's audit a finding.
func TestAuditActorPropagationRule_ClosureStatusWriteUsesMethodActor(t *testing.T) {
	for name, method := range map[string]string{
		"actor parameter": `func (s *Service) approve(id string, adminID int) error {
	defer func() { _ = s.repo.UpdateRecordStatus(id, 1) }()
	return nil
}`,
		"actor read": `func (s *Service) approve(id string, req *Request) error {
	if req.AdminID == 0 { return nil }
	defer func() { _ = s.repo.UpdateRecordStatus(id, 1) }()
	return nil
}`,
	} {
		t.Run(name, func(t *testing.T) {
			violations := analyzeAuditModule(t, map[string]string{"service.go": `package audit
type Repo struct{}
func (*Repo) UpdateRecordStatus(id string, status int) error { return nil }
type Request struct { AdminID int }
type Service struct { repo *Repo }
` + method + `
func (s *Service) complete(id string, actorUserID int) error {
	return runInTx(func() error {
		bindStatusActor(actorUserID)
		if err := s.repo.UpdateRecordStatus(id, 2); err != nil { return err }
		return writeAuditEntry(actorUserID, id)
	})
}
func runInTx(fn func() error) error { return fn() }
func bindStatusActor(int) {}
func writeAuditEntry(int, string) error { return nil }
`})
			require.Len(t, violations, 1)
			assert.Equal(t, "status_without_sibling_audit", violations[0].Context["pattern"])
		})
	}
}
