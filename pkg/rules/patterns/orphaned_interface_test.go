package patterns

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// runOrphanedInterface runs the rule the way the check flow does: a project
// rule gets the loaded project, a file rule gets every file in turn.
func runOrphanedInterface(t *testing.T, project *core.GoProjectContext) []*core.Violation {
	t.Helper()
	var rule rules.Rule = NewOrphanedInterfaceRule()
	if projectRule, ok := rule.(rules.GoProjectRule); ok {
		violations, err := projectRule.AnalyzeGoProject(project)
		require.NoError(t, err)
		return violations
	}
	var violations []*core.Violation
	for _, fileCtx := range project.Files {
		violations = append(violations, rule.AnalyzeFile(fileCtx)...)
	}
	return violations
}

func orphanedInterfaceProject(t *testing.T, files map[string]string) []*core.Violation {
	t.Helper()
	return runOrphanedInterface(t, rulestest.Project(t, files))
}

func TestOrphanedInterfaceSkipsRuleCapabilityInterface(t *testing.T) {
	violations := orphanedInterfaceProject(t, map[string]string{
		"rules/rule.go": "package rules\n\ntype ProjectRule interface { AnalyzeProject() error }\n",
	})
	require.Empty(t, violations)
}

// Интерфейс, используемый только как generic-констрейнт, — не сирота.
func TestOrphanedInterfaceGenericConstraintIsUsage(t *testing.T) {
	violations := orphanedInterfaceProject(t, map[string]string{
		"sample/sum.go": `package sample

type Number interface{ Value() int }

func Sum[T Number](items []T) int {
	total := 0
	for _, item := range items {
		total += item.Value()
	}
	return total
}
`,
	})
	require.Empty(t, violations)
}

// Метод generic-типа (Buffer[T]) — реализация: интерфейс не сирота.
func TestOrphanedInterfaceGenericReceiverImplements(t *testing.T) {
	violations := orphanedInterfaceProject(t, map[string]string{
		"sample/buffer.go": `package sample

type Flusher interface{ FlushIt() error }

type Buffer[T any] struct{ items []T }

func (b *Buffer[T]) FlushIt() error {
	b.items = nil
	return nil
}
`,
	})
	require.Empty(t, violations)
}

// Интерфейс, встроенный в другой интерфейс (type B interface { A }), используется.
func TestOrphanedInterfaceEmbeddingIsUsage(t *testing.T) {
	violations := orphanedInterfaceProject(t, map[string]string{
		"sample/resource.go": `package sample

type Closable interface{ CloseIt() error }

type Resource interface {
	Closable
	Open() error
}

func Handle(res Resource) { _ = res }
`,
	})
	require.Empty(t, violations)
}

// Интерфейс объявлен в одном файле пакета, а используется как тип поля и
// параметра в другом: область поиска — пакет, а не файл объявления.
func TestOrphanedInterfaceUsedInSiblingFile(t *testing.T) {
	violations := orphanedInterfaceProject(t, map[string]string{
		"engine/types.go": `package engine

type Notifier interface{ Notify(msg string) }
`,
		"engine/engine.go": `package engine

type Engine struct{ notifier Notifier }

func New(n Notifier) *Engine { return &Engine{notifier: n} }

func (e *Engine) Run() { e.notifier.Notify("run") }
`,
	})
	require.Empty(t, violations)
}

// Реализация в соседнем файле пакета спасает интерфейс и без явных использований.
func TestOrphanedInterfaceImplementedInSiblingFile(t *testing.T) {
	violations := orphanedInterfaceProject(t, map[string]string{
		"engine/types.go": `package engine

type Stepper interface {
	Step() error
	Done() bool
}
`,
		"engine/walker.go": `package engine

type walker struct{ left int }

func (w *walker) Step() error { w.left--; return nil }

func (w *walker) Done() bool { return w.left == 0 }

func Walk(n int) bool {
	w := &walker{left: n}
	for !w.Done() {
		_ = w.Step()
	}
	return true
}
`,
	})
	require.Empty(t, violations)
}

// Экспортированный интерфейс, используемый из другого пакета модуля, — не сирота.
func TestOrphanedInterfaceUsedFromOtherPackage(t *testing.T) {
	violations := orphanedInterfaceProject(t, map[string]string{
		"api/api.go": `package api

type Emitter interface{ Emit(event string) }
`,
		"app/app.go": `package app

import "example.com/rulestest/api"

func Fire(e api.Emitter) { e.Emit("start") }
`,
	})
	require.Empty(t, violations)
}

// Настоящая сирота в многофайловом пакете по-прежнему находится: тип в соседнем
// файле закрывает лишь часть методов, ссылка на себя в собственной сигнатуре
// использованием не считается.
func TestOrphanedInterfaceReportsOrphanInMultiFilePackage(t *testing.T) {
	violations := orphanedInterfaceProject(t, map[string]string{
		"engine/types.go": `package engine

type Stepper interface {
	Step() error
	Done() bool
}

type Chain interface{ NextLink() Chain }
`,
		"engine/walker.go": `package engine

type walker struct{ left int }

func (w *walker) Step() error { w.left--; return nil }

func Walk(n int) { _ = (&walker{left: n}).Step() }
`,
	})
	require.Len(t, violations, 2)
	require.Equal(t, 3, violations[0].Line)
	require.Contains(t, violations[0].Message, "'Stepper'")
	require.Equal(t, 8, violations[1].Line)
	require.Contains(t, violations[1].Message, "'Chain'")
	for _, v := range violations {
		require.Equal(t, "engine/types.go", v.File)
	}
}

// Пакет, который не проходит проверку типов (режим --tolerant), разбирается по
// синтаксису всех своих файлов: использование в соседнем файле засчитывается,
// сирота находится.
func TestOrphanedInterfaceUntypedPackageUsesAllFiles(t *testing.T) {
	root, contexts := rulestest.Module(t, map[string]string{
		"broken/types.go": `package broken

type Notifier interface{ Notify(msg string) }

type Lonely interface{ Alone() }
`,
		"broken/use.go": `package broken

type Engine struct{ notifier Notifier }

func Broken() int { return "not an int" }
`,
	})
	project, err := core.LoadGoProject(root, contexts, core.GoProjectOptions{TolerateBrokenPackages: true})
	require.NoError(t, err)
	require.NotEmpty(t, project.SkippedPackages)

	violations := runOrphanedInterface(t, project)
	require.Len(t, violations, 1)
	require.Contains(t, violations[0].Message, "'Lonely'")
	require.Equal(t, "broken/types.go", violations[0].File)
	require.Equal(t, 5, violations[0].Line)
}
