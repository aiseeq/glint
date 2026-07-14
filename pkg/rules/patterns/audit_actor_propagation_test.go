package patterns

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const auditSinkDefinition = `
type Repo struct{}

func (r *Repo) RecordStatusHistory(txnID string, source string, actorUserID int) {}
`

func TestAuditActorPropagationRule_Metadata(t *testing.T) {
	rule := NewAuditActorPropagationRule()

	assert.Equal(t, "audit-actor-propagation", rule.Name())
	assert.Equal(t, "patterns", rule.Category())
	assert.Equal(t, core.SeverityHigh, rule.DefaultSeverity())
	assert.True(t, rule.RequiresSSA())
	assert.True(t, rules.HonorsSuppression(rule))
	assert.Empty(t, rule.AnalyzeFile(&core.FileContext{}))
	assert.Equal(t, auditSinkSet(defaultAuditActorSinks), rule.sinks)
	registered, ok := rules.Get("audit-actor-propagation")
	assert.True(t, ok)
	assert.IsType(t, rule, registered)
}

func TestAuditActorPropagationRule_DirectActorParameterIsSafe(t *testing.T) {
	violations := analyzeAuditModule(t, map[string]string{
		"audit.go": `package audit
` + auditSinkDefinition + `
func update(repo *Repo, actorUserID int) {
	repo.RecordStatusHistory("txn", "admin:update", actorUserID)
}
`,
	})

	assert.Empty(t, violations)
}

func TestAuditActorPropagationRule_DetectsReplacedSourceParameter(t *testing.T) {
	violations := analyzeAuditModule(t, map[string]string{
		"audit.go": `package audit
` + auditSinkDefinition + `
func update(repo *Repo, source string, actorUserID int) {
	repo.RecordStatusHistory("txn", "api", actorUserID)
}
`,
	})

	require.Len(t, violations, 1)
	assert.Equal(t, "source_loss", violations[0].Context["pattern"])
}

func TestAuditActorPropagationRule_ForwardsRenamedValuesThroughThreeWrappers(t *testing.T) {
	violations := analyzeAuditModule(t, map[string]string{
		"audit.go": `package audit
` + auditSinkDefinition + `
func entry(repo *Repo, source string, actorUserID int) { first(repo, source, actorUserID) }
func first(repo *Repo, origin string, uid int) { second(repo, origin, uid) }
func second(repo *Repo, auditOrigin string, adminID int) { third(repo, auditOrigin, adminID) }
func third(repo *Repo, propagatedSource string, propagatedActor int) {
	repo.RecordStatusHistory("txn", propagatedSource, propagatedActor)
}
`,
	})

	assert.Empty(t, violations)
}

func TestAuditActorPropagationRule_DetectsCurrentUserActorDroppedByWrapper(t *testing.T) {
	violations := analyzeAuditModule(t, map[string]string{
		"audit.go": `package audit
` + auditSinkDefinition + `
type User struct { ID int }
func currentUser(request any) *User { return &User{ID: 42} }
func admin(request any, repo *Repo) {
	user := currentUser(request)
	dropped(repo, user.ID)
}
func dropped(repo *Repo, ignoredUserID int) {
	repo.RecordStatusHistory("txn", "api", 0)
}
`,
	})

	require.Len(t, violations, 1)
	assert.Equal(t, "actor_loss", violations[0].Context["pattern"])
	assert.Equal(t, "RecordStatusHistory", violations[0].Context["sink"])
}

func TestAuditActorPropagationRule_DetectsAdminLiteralWithZeroActor(t *testing.T) {
	violations := analyzeAuditModule(t, map[string]string{
		"audit.go": `package audit
` + auditSinkDefinition + `
func requote(repo *Repo) {
	repo.RecordStatusHistory("txn", "admin:requote", 0)
}
`,
	})

	require.Len(t, violations, 1)
	assert.Equal(t, "actor_loss", violations[0].Context["pattern"])
}

func TestAuditActorPropagationRule_APIActorZeroIsSafe(t *testing.T) {
	violations := analyzeAuditModule(t, map[string]string{
		"audit.go": `package audit
` + auditSinkDefinition + `
func receive(repo *Repo) {
	repo.RecordStatusHistory("txn", "api", 0)
}
`,
	})

	assert.Empty(t, violations)
}

func TestAuditActorPropagationRule_SystemCallerActorZeroIsSafe(t *testing.T) {
	violations := analyzeAuditModule(t, map[string]string{
		"audit.go": `package audit
` + auditSinkDefinition + `
func reconcile(repo *Repo) { recordReconciliation(repo, 0) }
func recordReconciliation(repo *Repo, actorUserID int) {
	repo.RecordStatusHistory("txn", "system/reconciler", actorUserID)
}
`,
	})

	assert.Empty(t, violations)
}

func TestAuditActorPropagationRule_SystemSourceWithHumanActorIsSafe(t *testing.T) {
	violations := analyzeAuditModule(t, map[string]string{
		"audit.go": `package audit
` + auditSinkDefinition + `
func reconcile(repo *Repo, approverUserID int) {
	repo.RecordStatusHistory("txn", "system/reconciler", approverUserID)
}
`,
	})

	assert.Empty(t, violations)
}

func TestAuditActorPropagationRule_ActorLikeFieldIsSafe(t *testing.T) {
	violations := analyzeAuditModule(t, map[string]string{
		"audit.go": `package audit
` + auditSinkDefinition + `
type input struct { submittedByUserID int }
func submit(repo *Repo, value input) {
	repo.RecordStatusHistory("txn", "admin", value.submittedByUserID)
}
`,
	})

	assert.Empty(t, violations)
}

func TestAuditActorPropagationRule_CancelPrefixPreservesSourceTaint(t *testing.T) {
	violations := analyzeAuditModule(t, map[string]string{
		"audit.go": `package audit
` + auditSinkDefinition + `
func cancel(repo *Repo, source string, operatorUserID int) {
	repo.RecordStatusHistory("txn", "cancel_intent:" + source, operatorUserID)
}
`,
	})

	assert.Empty(t, violations)
}

func TestAuditActorPropagationRule_AliasAndPhiPreserveTaint(t *testing.T) {
	violations := analyzeAuditModule(t, map[string]string{
		"audit.go": `package audit
` + auditSinkDefinition + `
func update(repo *Repo, source string, actorUserID int, choose bool) {
	actor := actorUserID
	origin := source
	if choose {
		actor = actorUserID
		origin = source
	}
	repo.RecordStatusHistory("txn", origin, actor)
}
`,
	})

	assert.Empty(t, violations)
}

func TestAuditActorPropagationRule_InterfaceCallsUseAllImplementations(t *testing.T) {
	t.Run("forwarding implementation", func(t *testing.T) {
		violations := analyzeAuditModule(t, map[string]string{
			"audit.go": `package audit
` + auditSinkDefinition + `
type Writer interface { Write(txnID string, source string, actorUserID int) }
type Forwarding struct { repo *Repo }
func (w *Forwarding) Write(txnID string, source string, actorUserID int) {
	w.repo.RecordStatusHistory(txnID, source, actorUserID)
}
func dispatch(writer Writer, source string, actorUserID int) {
	writer.Write("txn", source, actorUserID)
}
`,
		})

		assert.Empty(t, violations)
	})

	t.Run("one implementation drops actor", func(t *testing.T) {
		violations := analyzeAuditModule(t, map[string]string{
			"audit.go": `package audit
` + auditSinkDefinition + `
type Writer interface { Write(txnID string, source string, actorUserID int) }
type Forwarding struct { repo *Repo }
func (w *Forwarding) Write(txnID string, source string, actorUserID int) {
	w.repo.RecordStatusHistory(txnID, source, actorUserID)
}
type Dropping struct { repo *Repo }
func (w *Dropping) Write(txnID string, source string, actorUserID int) {
	w.repo.RecordStatusHistory(txnID, source, 0)
}
func dispatch(writer Writer, source string, actorUserID int) {
	writer.Write("txn", source, actorUserID)
}
`,
		})

		require.Len(t, violations, 1)
		assert.Equal(t, "actor_loss", violations[0].Context["pattern"])
	})
}

func TestAuditActorPropagationRule_ClosureCapturesPreserveTaint(t *testing.T) {
	violations := analyzeAuditModule(t, map[string]string{
		"audit.go": `package audit
` + auditSinkDefinition + `
func update(repo *Repo, source string, actorUserID int) {
	forward := func() { repo.RecordStatusHistory("safe", source, actorUserID) }
	forward()
	drop := func() { repo.RecordStatusHistory("loss", source, 0) }
	drop()
}
`,
	})

	require.Len(t, violations, 1)
	assert.Equal(t, "actor_loss", violations[0].Context["pattern"])
}

func TestAuditActorPropagationRule_GoAndDeferDoNotReceiveAmbientHumanContext(t *testing.T) {
	violations := analyzeAuditModule(t, map[string]string{
		"audit.go": `package audit
` + auditSinkDefinition + `
type User struct { ID int }
func authenticatedUser(request any) *User { return &User{ID: 42} }
func background(repo *Repo) { repo.RecordStatusHistory("background", "api", 0) }
func attributed(repo *Repo, userID int) { repo.RecordStatusHistory("attributed", "api", userID) }
func handle(request any, repo *Repo) {
	actor := authenticatedUser(request).ID
	go background(repo)
	defer background(repo)
	go attributed(repo, actor)
	defer attributed(repo, actor)
}
`,
	})

	assert.Empty(t, violations)
}

func TestAuditActorPropagationRule_GoAndDeferClosureCaptureIsNotExplicitActorParameter(t *testing.T) {
	violations := analyzeAuditModule(t, map[string]string{
		"audit.go": `package audit
` + auditSinkDefinition + `
type User struct { ID int }
func currentAdmin(request any) *User { return &User{ID: 42} }
func handle(request any, repo *Repo) {
	actor := currentAdmin(request).ID
	go func() {
		_ = actor
		repo.RecordStatusHistory("go", "api", 0)
	}()
	defer func() {
		_ = actor
		repo.RecordStatusHistory("defer", "api", 0)
	}()
}
`,
	})

	assert.Empty(t, violations)
}

func TestAuditActorPropagationRule_DoesNotTaintUnrelatedEntityValues(t *testing.T) {
	violations := analyzeAuditModule(t, map[string]string{
		"audit.go": `package audit
` + auditSinkDefinition + `
func update(repo *Repo, txnID int, actorUserID int) {
	repo.RecordStatusHistory("txn", "api", txnID)
}
`,
	})

	require.Len(t, violations, 1)
	assert.Equal(t, "actor_loss", violations[0].Context["pattern"])
}

func TestAuditActorPropagationRule_TestPackagesAreNotAnalyzed(t *testing.T) {
	violations := analyzeAuditModule(t, map[string]string{
		"audit.go": `package audit
` + auditSinkDefinition,
		"audit_test.go": `package audit
func badFixture(repo *Repo) {
	repo.RecordStatusHistory("txn", "admin:test", 0)
}
`,
	})

	assert.Empty(t, violations)
}

func TestAuditActorPropagationRule_SinkRolesComeFromFormalParameterNames(t *testing.T) {
	violations := analyzeAuditModule(t, map[string]string{
		"audit.go": `package audit
type Repo struct{}
func (r *Repo) ApplyQuote(actorUserID int, entity string, source string) {}
func quote(repo *Repo, source string, createdByUserID int) {
	repo.ApplyQuote(createdByUserID, "txn", source)
}
`,
	})

	assert.Empty(t, violations)
}

func TestAuditActorPropagationRule_ConfiguredSinksReplaceDefaults(t *testing.T) {
	rule := NewAuditActorPropagationRule()
	require.NoError(t, rule.Configure(map[string]any{"sinks": []string{"WriteAudit"}}))
	violations := analyzeAuditModuleWithRule(t, rule, map[string]string{
		"audit.go": `package audit
type Repo struct{}
func (r *Repo) WriteAudit(source string, userID int) {}
func (r *Repo) RecordStatusHistory(source string, actorUserID int) {}
func update(repo *Repo) {
	repo.WriteAudit("admin:write", 0)
	repo.RecordStatusHistory("admin:default", 0)
}
`,
	})

	require.Len(t, violations, 1)
	assert.Equal(t, "WriteAudit", violations[0].Context["sink"])
}

func TestAuditActorPropagationRule_RejectsMalformedSinkRoles(t *testing.T) {
	_, err := analyzeAuditModuleError(t, NewAuditActorPropagationRule(), map[string]string{
		"audit.go": `package audit
type Repo struct{}
func (r *Repo) RecordStatusHistory(source string, actorUserID int, operatorUserID int) {}
func update(repo *Repo, actorUserID int) {
	repo.RecordStatusHistory("api", actorUserID, actorUserID)
}
`,
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "malformed")
}

func TestAuditActorPropagationRule_RejectsMalformedSinkRoleTypes(t *testing.T) {
	_, err := analyzeAuditModuleError(t, NewAuditActorPropagationRule(), map[string]string{
		"audit.go": `package audit
type Repo struct{}
func (r *Repo) RecordStatusHistory(source int, actorUserID string) {}
func update(repo *Repo) {
	repo.RecordStatusHistory(1, "admin")
}
`,
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "role types")
}

func TestAuditActorPropagationRule_RejectsUnmappableSourceSinkPosition(t *testing.T) {
	root, contexts := writeAuditModule(t, map[string]string{
		"audit.go": `package audit
` + auditSinkDefinition + `
func update(repo *Repo) { repo.RecordStatusHistory("txn", "admin:update", 0) }
`,
	})
	project, err := core.LoadGoProject(root, contexts, true)
	require.NoError(t, err)
	project.FileSet = nil

	_, err = NewAuditActorPropagationRule().AnalyzeGoProject(project)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "position")
}

func TestAuditActorPropagationRule_SuppressionIsLeftToStandardEngine(t *testing.T) {
	root, contexts := writeAuditModule(t, map[string]string{
		"audit.go": `package audit
` + auditSinkDefinition + `
func update(repo *Repo) {
	//nolint:audit-actor-propagation // trusted administrative migration
	repo.RecordStatusHistory("txn", "admin:migration", 0)
}
`,
	})
	project, err := core.LoadGoProject(root, contexts, true)
	require.NoError(t, err)
	violations, err := NewAuditActorPropagationRule().AnalyzeGoProject(project)
	require.NoError(t, err)
	require.Len(t, violations, 1, "project rules return raw findings for engine-level suppression")
	file, err := project.File(violations[0].File)
	require.NoError(t, err)
	assert.True(t, file.IsSuppressed(violations[0].Line, "audit-actor-propagation"))
}

func analyzeAuditModule(t *testing.T, files map[string]string) []*core.Violation {
	t.Helper()
	return analyzeAuditModuleWithRule(t, NewAuditActorPropagationRule(), files)
}

func analyzeAuditModuleWithRule(t *testing.T, rule *AuditActorPropagationRule, files map[string]string) []*core.Violation {
	t.Helper()
	violations, err := analyzeAuditModuleError(t, rule, files)
	require.NoError(t, err)
	return violations
}

func analyzeAuditModuleError(t *testing.T, rule *AuditActorPropagationRule, files map[string]string) ([]*core.Violation, error) {
	t.Helper()
	root, contexts := writeAuditModule(t, files)
	project, err := core.LoadGoProject(root, contexts, true)
	if err != nil {
		return nil, err
	}
	violations, err := rule.AnalyzeGoProject(project)
	sort.Slice(violations, func(i, j int) bool {
		if violations[i].File != violations[j].File {
			return violations[i].File < violations[j].File
		}
		if violations[i].Line != violations[j].Line {
			return violations[i].Line < violations[j].Line
		}
		return violations[i].Context["pattern"].(string) < violations[j].Context["pattern"].(string)
	})
	return violations, err
}

func writeAuditModule(t *testing.T, files map[string]string) (string, []*core.FileContext) {
	t.Helper()
	root := t.TempDir()
	moduleFiles := make(map[string]string, len(files)+1)
	moduleFiles["go.mod"] = "module example.com/audit\n\ngo 1.24\n"
	for name, content := range files {
		moduleFiles[name] = content
	}
	for name, content := range moduleFiles {
		path := filepath.Join(root, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0644))
	}

	var contexts []*core.FileContext
	for name, content := range moduleFiles {
		if !strings.HasSuffix(name, ".go") {
			continue
		}
		ctx, err := core.NewFileContextChecked(filepath.Join(root, name), root, []byte(content), core.DefaultConfig())
		require.NoError(t, err)
		contexts = append(contexts, ctx)
	}
	return root, contexts
}
