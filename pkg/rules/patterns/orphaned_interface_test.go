package patterns

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/stretchr/testify/require"
)

func TestOrphanedInterfaceSkipsRuleCapabilityInterface(t *testing.T) {
	ctx, err := core.NewFileContextChecked(
		"rule.go",
		".",
		[]byte("package rules\n\ntype ProjectRule interface { AnalyzeProject() error }\n"),
		core.DefaultConfig(),
	)
	require.NoError(t, err)
	fset, file, err := core.NewParser().ParseGoFile(ctx.Path, ctx.Content)
	require.NoError(t, err)
	ctx.SetGoAST(fset, file)

	require.Empty(t, NewOrphanedInterfaceRule().AnalyzeFile(ctx))
}

// Интерфейс, используемый только как generic-констрейнт, — не сирота.
func TestOrphanedInterfaceGenericConstraintIsUsage(t *testing.T) {
	src := `package sample

type Number interface{ Value() int }

func Sum[T Number](items []T) int {
	total := 0
	for _, item := range items {
		total += item.Value()
	}
	return total
}
`
	ctx, err := core.NewFileContextChecked("sum.go", ".", []byte(src), core.DefaultConfig())
	require.NoError(t, err)
	fset, file, err := core.NewParser().ParseGoFile(ctx.Path, ctx.Content)
	require.NoError(t, err)
	ctx.SetGoAST(fset, file)

	require.Empty(t, NewOrphanedInterfaceRule().AnalyzeFile(ctx))
}

// Метод generic-типа (Buffer[T]) — реализация: интерфейс не сирота.
func TestOrphanedInterfaceGenericReceiverImplements(t *testing.T) {
	src := `package sample

type Flusher interface{ FlushIt() error }

type Buffer[T any] struct{ items []T }

func (b *Buffer[T]) FlushIt() error {
	b.items = nil
	return nil
}
`
	ctx, err := core.NewFileContextChecked("buffer.go", ".", []byte(src), core.DefaultConfig())
	require.NoError(t, err)
	fset, file, err := core.NewParser().ParseGoFile(ctx.Path, ctx.Content)
	require.NoError(t, err)
	ctx.SetGoAST(fset, file)

	require.Empty(t, NewOrphanedInterfaceRule().AnalyzeFile(ctx))
}

// Интерфейс, встроенный в другой интерфейс (type B interface { A }), используется.
func TestOrphanedInterfaceEmbeddingIsUsage(t *testing.T) {
	src := `package sample

type Closable interface{ CloseIt() error }

type Resource interface {
	Closable
	Open() error
}

func handle(res Resource) { _ = res }
`
	ctx, err := core.NewFileContextChecked("resource.go", ".", []byte(src), core.DefaultConfig())
	require.NoError(t, err)
	fset, file, err := core.NewParser().ParseGoFile(ctx.Path, ctx.Content)
	require.NoError(t, err)
	ctx.SetGoAST(fset, file)

	require.Empty(t, NewOrphanedInterfaceRule().AnalyzeFile(ctx))
}
