package patterns

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// storeDefinition — минимальное хранилище. Без типов правило не отличит репозиторий
// от логгера, поэтому образцы всегда компилируются целиком.
const storeDefinition = `
type Repo struct{}

func (r *Repo) CreateThing(ctx context.Context) error { return nil }
func (r *Repo) UpdateThing(ctx context.Context) error { return nil }
func (r *Repo) DeleteThing(ctx context.Context) error { return nil }
func (r *Repo) GetThing(ctx context.Context) error    { return nil }

func (r *Repo) SetEnvironment(env string)                                        {}
func (r *Repo) RunInTx(ctx context.Context, fn func(context.Context) error) error { return fn(ctx) }

type Service struct{ repo *Repo }
`

func TestMultiWriteNoTransactionRule_Metadata(t *testing.T) {
	rule := NewMultiWriteNoTransactionRule()

	assert.Equal(t, "multi-write-no-transaction", rule.Name())
	assert.Equal(t, "patterns", rule.Category())
	assert.Equal(t, core.SeverityHigh, rule.DefaultSeverity())
	assert.False(t, rule.RequiresSSA(), "правилу хватает типизированных пакетов")
	assert.Empty(t, rule.AnalyzeFile(&core.FileContext{}))

	registered, ok := rules.Get("multi-write-no-transaction")
	require.True(t, ok)
	assert.IsType(t, rule, registered)
}

// Две разные записи подряд — ровно тот случай, ради которого правило написано.
func TestMultiWriteNoTransactionRule_ReportsSequentialWrites(t *testing.T) {
	violations := analyzeStoreModule(t, `
func (s *Service) Complete(ctx context.Context) error {
	if err := s.repo.UpdateThing(ctx); err != nil {
		return err
	}
	return s.repo.CreateThing(ctx)
}
`)
	require.Len(t, violations, 1)
	assert.Contains(t, violations[0].Message, "Complete")
	assert.Equal(t, core.SeverityHigh, violations[0].Severity)
}

// Конфиг умеет исключать находку по имени функции, но только если правило кладёт
// это имя в контекст. Без него `function:` в .glint.yaml молча не срабатывает, и
// осознанно разделённую пару записей приходится глушить по всему файлу.
func TestMultiWriteNoTransactionRule_ReportsFunctionInContext(t *testing.T) {
	violations := analyzeStoreModule(t, `
func (s *Service) Complete(ctx context.Context) error {
	if err := s.repo.UpdateThing(ctx); err != nil {
		return err
	}
	return s.repo.CreateThing(ctx)
}
`)
	require.Len(t, violations, 1)
	require.NotNil(t, violations[0].Context)
	assert.Equal(t, "Complete", violations[0].Context["function"])
}

// Транзакция вокруг записей снимает вопрос.
func TestMultiWriteNoTransactionRule_SilentUnderTransaction(t *testing.T) {
	violations := analyzeStoreModule(t, `
func (s *Service) Complete(ctx context.Context) error {
	return s.repo.RunInTx(ctx, func(ctx context.Context) error {
		if err := s.repo.UpdateThing(ctx); err != nil {
			return err
		}
		return s.repo.CreateThing(ctx)
	})
}
`)
	assert.Empty(t, violations)
}

// Записи разнесены по хелперам — самый частый вид. Метод выглядит коротким,
// а операция всё равно рвётся посередине.
func TestMultiWriteNoTransactionRule_SeesWritesThroughHelpers(t *testing.T) {
	violations := analyzeStoreModule(t, `
func (s *Service) markDone(ctx context.Context) error { return s.repo.UpdateThing(ctx) }
func (s *Service) addEntry(ctx context.Context) error { return s.repo.CreateThing(ctx) }

func (s *Service) Complete(ctx context.Context) error {
	if err := s.markDone(ctx); err != nil {
		return err
	}
	return s.addEntry(ctx)
}
`)
	require.Len(t, violations, 1, "сообщать надо один раз — о функции, где записи встречаются")
	assert.Contains(t, violations[0].Message, "Complete")
}

// Обёртка не обязана лежать в одной функции с записями.
func TestMultiWriteNoTransactionRule_HelperWrappedByCaller(t *testing.T) {
	violations := analyzeStoreModule(t, `
func (s *Service) writes(ctx context.Context) error {
	if err := s.repo.UpdateThing(ctx); err != nil {
		return err
	}
	return s.repo.CreateThing(ctx)
}

func (s *Service) Complete(ctx context.Context) error {
	return s.repo.RunInTx(ctx, func(ctx context.Context) error {
		return s.writes(ctx)
	})
}
`)
	assert.Empty(t, violations)
}

// Хелпер, достижимый и из транзакции, и напрямую, транзакцией не покрыт: голый
// вызов исполняет обе записи без неё. Исключение — только для функций, достижимых
// ТОЛЬКО из транзакции.
func TestMultiWriteNoTransactionRule_HelperAlsoCalledOutsideTransaction(t *testing.T) {
	violations := analyzeStoreModule(t, `
func (s *Service) writePair(ctx context.Context) error {
	if err := s.repo.UpdateThing(ctx); err != nil {
		return err
	}
	return s.repo.CreateThing(ctx)
}

func (s *Service) Complete(ctx context.Context) error {
	return s.repo.RunInTx(ctx, func(ctx context.Context) error {
		return s.writePair(ctx)
	})
}

func (s *Service) Fast(ctx context.Context) error {
	return s.writePair(ctx)
}
`)
	require.Len(t, violations, 1)
	assert.Contains(t, violations[0].Message, "writePair")
}

// Ветка с return исключает то, что идёт после неё: выполняется ровно одна запись.
func TestMultiWriteNoTransactionRule_ExclusiveBranches(t *testing.T) {
	violations := analyzeStoreModule(t, `
func (s *Service) Save(ctx context.Context, exists bool) error {
	if exists {
		return s.repo.UpdateThing(ctx)
	}
	return s.repo.CreateThing(ctx)
}
`)
	assert.Empty(t, violations)
}

// Разные плечи одного if тоже исключают друг друга.
func TestMultiWriteNoTransactionRule_ExclusiveIfElse(t *testing.T) {
	violations := analyzeStoreModule(t, `
func (s *Service) Save(ctx context.Context, exists bool) error {
	if exists {
		return s.repo.UpdateThing(ctx)
	} else {
		return s.repo.CreateThing(ctx)
	}
}
`)
	assert.Empty(t, violations)
}

// Чтение рядом с записью — не повод для находки.
func TestMultiWriteNoTransactionRule_ReadsAreNotWrites(t *testing.T) {
	violations := analyzeStoreModule(t, `
func (s *Service) Load(ctx context.Context) error {
	if err := s.repo.GetThing(ctx); err != nil {
		return err
	}
	return s.repo.CreateThing(ctx)
}
`)
	assert.Empty(t, violations)
}

// Запись в фоновой горутине — отдельная единица работы: она переживает возврат из
// функции и в её транзакцию попасть не может даже теоретически.
func TestMultiWriteNoTransactionRule_GoroutineWriteIsSeparateUnit(t *testing.T) {
	violations := analyzeStoreModule(t, `
func (s *Service) refreshAsync(ctx context.Context) {
	go func() {
		_ = s.repo.UpdateThing(ctx)
	}()
}

func (s *Service) Save(ctx context.Context) error {
	if err := s.repo.CreateThing(ctx); err != nil {
		return err
	}
	s.refreshAsync(ctx)
	return nil
}
`)
	assert.Empty(t, violations)
}

// Повтор той же записи — ретрай, а не две операции.
func TestMultiWriteNoTransactionRule_RetryIsOneWrite(t *testing.T) {
	violations := analyzeStoreModule(t, `
func (s *Service) Save(ctx context.Context) error {
	if err := s.repo.CreateThing(ctx); err != nil {
		return s.repo.CreateThing(ctx)
	}
	return nil
}
`)
	assert.Empty(t, violations)
}

// Делегирующая обёртка не считается второй записью поверх той же самой.
func TestMultiWriteNoTransactionRule_DelegationIsOneWrite(t *testing.T) {
	violations := analyzeStoreModule(t, `
func (r *Repo) CreateThingWithDefaults(ctx context.Context) error { return r.CreateThing(ctx) }

func (s *Service) Save(ctx context.Context) error {
	return s.repo.CreateThingWithDefaults(ctx)
}
`)
	assert.Empty(t, violations)
}

func TestMultiWriteNoTransactionRule_ConfigureRejectsBadSettings(t *testing.T) {
	rule := NewMultiWriteNoTransactionRule()

	require.Error(t, rule.Configure(map[string]any{"store_types": 42}))
	require.Error(t, rule.Configure(map[string]any{"store_types": "("}))
	require.Error(t, rule.Configure(map[string]any{"transaction_functions": "RunInTx"}))
	require.Error(t, rule.Configure(map[string]any{"transaction_functions": []any{" "}}))
	require.NoError(t, rule.Configure(map[string]any{"transaction_functions": []any{"Atomically"}}))

	require.Error(t, rule.Configure(map[string]any{"independent_calls": "Go"}))
	require.Error(t, rule.Configure(map[string]any{"independent_calls": []any{7}}))
	require.Error(t, rule.Configure(map[string]any{"independent_calls": []any{" "}}))
	require.NoError(t, rule.Configure(map[string]any{"independent_calls": []any{"Go"}}))
}

// Запускалка фоновой задачи и телеметрия объявляются в конфиге: их записи принадлежат
// другой единице работы и в транзакцию вызывающего попасть не могут.
func TestMultiWriteNoTransactionRule_IndependentCallsAreNotCounted(t *testing.T) {
	rule := NewMultiWriteNoTransactionRule()
	require.NoError(t, rule.Configure(map[string]any{"independent_calls": []any{"Spawn"}}))

	source := `
func Spawn(fn func()) { go fn() }

func (s *Service) refresh(ctx context.Context) { _ = s.repo.UpdateThing(ctx) }

func (s *Service) Save(ctx context.Context) error {
	if err := s.repo.CreateThing(ctx); err != nil {
		return err
	}
	Spawn(func() { s.refresh(ctx) })
	return nil
}
`
	assert.Empty(t, analyzeStoreModuleWithRule(t, rule, source))
	// Без настройки та же запускалка неотличима от обычного вызова.
	assert.Len(t, analyzeStoreModule(t, source), 1)
}

// Переопределённое имя раннера транзакций признаётся вместо встроенного списка.
func TestMultiWriteNoTransactionRule_ConfiguredRunnerIsHonoured(t *testing.T) {
	rule := NewMultiWriteNoTransactionRule()
	require.NoError(t, rule.Configure(map[string]any{"transaction_functions": []any{"RunInTx"}}))

	violations := analyzeStoreModuleWithRule(t, rule, `
func (s *Service) Complete(ctx context.Context) error {
	return s.repo.RunInTx(ctx, func(ctx context.Context) error {
		if err := s.repo.UpdateThing(ctx); err != nil {
			return err
		}
		return s.repo.CreateThing(ctx)
	})
}
`)
	assert.Empty(t, violations)
}

func analyzeStoreModule(t *testing.T, body string) []*core.Violation {
	t.Helper()
	return analyzeStoreModuleWithRule(t, NewMultiWriteNoTransactionRule(), body)
}

func analyzeStoreModuleWithRule(t *testing.T, rule *MultiWriteNoTransactionRule, body string) []*core.Violation {
	t.Helper()
	source := "package sample\n\nimport \"context\"\n" + storeDefinition + body
	root, contexts := writeStoreModule(t, map[string]string{"sample.go": source})

	project, err := core.LoadGoProject(root, contexts, core.GoProjectOptions{})
	require.NoError(t, err)

	violations, err := rule.AnalyzeGoProject(project)
	require.NoError(t, err)
	sort.Slice(violations, func(i, j int) bool { return violations[i].Line < violations[j].Line })
	return violations
}

func writeStoreModule(t *testing.T, files map[string]string) (string, []*core.FileContext) {
	t.Helper()
	root := t.TempDir()
	all := map[string]string{"go.mod": "module example.com/store\n\ngo 1.24\n"}
	for name, content := range files {
		all[name] = content
	}
	for name, content := range all {
		path := filepath.Join(root, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0644))
	}

	var contexts []*core.FileContext
	for name, content := range all {
		if !strings.HasSuffix(name, ".go") {
			continue
		}
		ctx, err := core.NewFileContextChecked(filepath.Join(root, name), root, []byte(content), core.DefaultConfig())
		require.NoError(t, err)
		contexts = append(contexts, ctx)
	}
	return root, contexts
}

// Настройка самого репозитория не является записью: она идёт без контекста и ничего
// не сохраняет.
func TestMultiWriteNoTransactionRule_SetterWithoutContextIsNotWrite(t *testing.T) {
	violations := analyzeStoreModule(t, `
func (s *Service) Boot(ctx context.Context) error {
	s.repo.SetEnvironment("production")
	return s.repo.CreateThing(ctx)
}
`)
	assert.Empty(t, violations)
}

// Writes are paired along control-flow paths: what matters is whether both
// can run in one pass, not how the arms of the enclosing branches look.
func TestMultiWriteNoTransactionRule_PathSensitivity(t *testing.T) {
	tests := []struct {
		name   string
		source string
		want   int
	}{
		{
			// The first write is unconditional; the returning arm adds the second.
			name: "write before a returning arm that writes",
			source: `
func (s *Service) Pay(ctx context.Context, x bool) error {
	if err := s.repo.UpdateThing(ctx); err != nil {
		return err
	}
	if x {
		_ = s.repo.CreateThing(ctx)
		return nil
	}
	return nil
}
`,
			want: 1,
		},
		{
			// break leaves the loop, not the function: the write after the loop runs.
			name: "break out of a loop that wrote",
			source: `
func (s *Service) Brk(ctx context.Context, ids []string) error {
	for _, id := range ids {
		if id == "x" {
			_ = s.repo.UpdateThing(ctx)
			break
		}
	}
	return s.repo.CreateThing(ctx)
}
`,
			want: 1,
		},
		{
			name: "labeled break out of an infinite loop",
			source: `
func (s *Service) Loop(ctx context.Context, ch chan int) error {
outer:
	for {
		select {
		case <-ch:
			_ = s.repo.UpdateThing(ctx)
			break outer
		}
	}
	return s.repo.CreateThing(ctx)
}
`,
			want: 1,
		},
		{
			// Only one select clause runs.
			name: "writes in different select clauses",
			source: `
func (s *Service) Sel(ctx context.Context, a, b chan int) {
	select {
	case <-a:
		_ = s.repo.UpdateThing(ctx)
	case <-b:
		_ = s.repo.CreateThing(ctx)
	}
}
`,
			want: 0,
		},
		{
			name: "writes in different arms of a closure",
			source: `
func (s *Service) Pick(ctx context.Context, x bool) func() {
	return func() {
		if x {
			_ = s.repo.UpdateThing(ctx)
			return
		}
		_ = s.repo.CreateThing(ctx)
	}
}
`,
			want: 0,
		},
		{
			// The helper writes one thing or the other; the caller wrote before.
			name: "helper with exclusive writes after a caller write",
			source: `
func (s *Service) either(ctx context.Context, x bool) error {
	if x {
		return s.repo.UpdateThing(ctx)
	}
	return s.repo.DeleteThing(ctx)
}

func (s *Service) Run(ctx context.Context, x bool) error {
	if err := s.repo.CreateThing(ctx); err != nil {
		return err
	}
	return s.either(ctx, x)
}
`,
			want: 1,
		},
		{
			// Each exit of the helper leaves one write; the caller adds none.
			name: "helper with exclusive writes alone",
			source: `
func (s *Service) either(ctx context.Context, x bool) error {
	if x {
		return s.repo.UpdateThing(ctx)
	}
	return s.repo.DeleteThing(ctx)
}

func (s *Service) Run(ctx context.Context, x bool) error {
	return s.either(ctx, x)
}
`,
			want: 0,
		},
		{
			name: "log.Fatal ends the path of the first write",
			source: `
func (s *Service) Stop(ctx context.Context, x bool) error {
	if x {
		_ = s.repo.UpdateThing(ctx)
		log.Fatal("stop")
	}
	return s.repo.CreateThing(ctx)
}
`,
			want: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			imports := ""
			if strings.Contains(tt.source, "log.") {
				imports = `"log"`
			}
			assert.Len(t, analyzeStoreModuleImports(t, NewMultiWriteNoTransactionRule(), imports, tt.source), tt.want)
		})
	}
}

// A chain of helpers that each call the next from both arms of an if used to
// be re-expanded for every path: depth 16 cost 18 s, depth 18 almost three
// minutes. Every function is summarised once.
func TestMultiWriteNoTransactionRule_DeepHelperChainIsLinear(t *testing.T) {
	const depth = 40
	var source strings.Builder
	fmt.Fprintf(&source, "func (s *Service) f%d(ctx context.Context) { _ = s.repo.UpdateThing(ctx) }\n", depth)
	for i := depth - 1; i >= 0; i-- {
		fmt.Fprintf(&source, "func (s *Service) f%d(ctx context.Context, b bool) {\n\tif b {\n\t\ts.f%d(ctx%s)\n\t} else {\n\t\ts.f%d(ctx%s)\n\t}\n}\n",
			i, i+1, chainArg(i+1, depth), i+1, chainArg(i+1, depth))
	}
	source.WriteString("func (s *Service) Top(ctx context.Context) error {\n\ts.f0(ctx, true)\n\treturn s.repo.CreateThing(ctx)\n}\n")

	done := make(chan []*core.Violation, 1)
	go func() { done <- analyzeStoreModule(t, source.String()) }()
	select {
	case violations := <-done:
		require.Len(t, violations, 1)
		assert.Contains(t, violations[0].Message, "Top")
		assert.Contains(t, violations[0].Message, "f0 → f1")
	case <-time.After(20 * time.Second):
		t.Fatal("the helper chain is expanded per path instead of once per function")
	}
}

func chainArg(i, depth int) string {
	if i == depth {
		return ""
	}
	return ", b"
}

func analyzeStoreModuleImports(t *testing.T, rule *MultiWriteNoTransactionRule, imports, body string) []*core.Violation {
	t.Helper()
	source := "package sample\n\nimport (\n\t\"context\"\n\t" + imports + "\n)\n" + storeDefinition + body
	root, contexts := writeStoreModule(t, map[string]string{"sample.go": source})
	project, err := core.LoadGoProject(root, contexts, core.GoProjectOptions{})
	require.NoError(t, err)
	violations, err := rule.AnalyzeGoProject(project)
	require.NoError(t, err)
	return violations
}
