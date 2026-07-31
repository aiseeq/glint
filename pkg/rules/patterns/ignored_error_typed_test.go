package patterns

import (
	"testing"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func ignoredErrorMessages(t *testing.T, files map[string]string) []string {
	t.Helper()

	project := rulestest.Project(t, files)
	violations, err := NewIgnoredErrorRule().AnalyzeGoProject(project)
	require.NoError(t, err)

	out := make([]string, 0, len(violations))
	for _, v := range violations {
		out = append(out, v.Message)
	}
	return out
}

// Второй случай из REF-462: ошибка выброшена blank identifier'ом. Имя метода
// ничего не говорит о том, что он возвращает error, поэтому проверка по списку
// имён (Read/Parse/Query...) на нём молчала.
func TestIgnoredError_BlankFromDomainMethod(t *testing.T) {
	found := ignoredErrorMessages(t, map[string]string{"storage/storage.go": `package storage

type Repo struct{}

func (r *Repo) List(userID string) ([]int, error) { return nil, nil }

func Collect(r *Repo, userID string) []int {
	items, _ := r.List(userID)
	return items
}
`})
	require.Len(t, found, 1, "ошибка выброшена в blank identifier: %v", found)
	assert.Contains(t, found[0], "List")
}

// Присваивание в уже объявленные переменные — та же дыра, другой токен.
func TestIgnoredError_BlankInPlainAssign(t *testing.T) {
	found := ignoredErrorMessages(t, map[string]string{"storage/storage.go": `package storage

type Repo struct{}

func (r *Repo) List(userID string) ([]int, error) { return nil, nil }

func Collect(r *Repo, userID string) []int {
	var items []int
	items, _ = r.List(userID)
	return items
}
`})
	require.Len(t, found, 1, "ошибка выброшена при обычном присваивании: %v", found)
}

// Второе значение не error, а bool — правило не про comma-ok.
func TestIgnoredError_CommaOkIsFine(t *testing.T) {
	found := ignoredErrorMessages(t, map[string]string{"storage/storage.go": `package storage

func Value(m map[string]int, key string) int {
	value, _ := m[key]
	return value
}
`})
	assert.Empty(t, found, "comma-ok нарушением не является: %v", found)
}

// Ошибка получена в переменную и разобрана — нарушения нет.
func TestIgnoredError_HandledIsFine(t *testing.T) {
	found := ignoredErrorMessages(t, map[string]string{"storage/storage.go": `package storage

type Repo struct{}

func (r *Repo) List(userID string) ([]int, error) { return nil, nil }

func Collect(r *Repo, userID string) ([]int, error) {
	items, err := r.List(userID)
	if err != nil {
		return nil, err
	}
	return items, nil
}
`})
	assert.Empty(t, found, "ошибка обработана: %v", found)
}

// Закрытие ресурса в defer — признанное молчание, ошибку там всё равно некуда деть.
func TestIgnoredError_DeferredCloseIsFine(t *testing.T) {
	found := ignoredErrorMessages(t, map[string]string{"storage/storage.go": `package storage

type conn struct{}

func (c *conn) Close() error { return nil }

func use(c *conn) {
	defer func() { _ = c.Close() }()
}
`})
	assert.Empty(t, found, "Close в defer — признанное исключение: %v", found)
}

// Тестовые файлы правило не разбирает.
func TestIgnoredError_TestFileIsSkipped(t *testing.T) {
	found := ignoredErrorMessages(t, map[string]string{
		"storage/storage.go": `package storage

type Repo struct{}

func (r *Repo) List(userID string) ([]int, error) { return nil, nil }
`,
		"storage/storage_test.go": `package storage

import "testing"

func TestList(t *testing.T) {
	r := &Repo{}
	items, _ := r.List("u1")
	_ = items
}
`,
	})
	assert.Empty(t, found, "тесты правило не разбирает: %v", found)
}

// Стандартная библиотека: ошибку открытия файла и сериализации выбрасывать нельзя.
func TestIgnoredError_StdlibErrorsAreFlagged(t *testing.T) {
	found := ignoredErrorMessages(t, map[string]string{"storage/storage.go": `package storage

import (
	"encoding/json"
	"os"
)

func read(name string, v any) []byte {
	f, _ := os.Open(name)
	_ = f
	data, _ := json.Marshal(v)
	return data
}
`})
	assert.Len(t, found, 2, "os.Open и json.Marshal должны ловиться: %v", found)
}

// Печать в stdout: ошибку туда всё равно некуда деть.
func TestIgnoredError_PrintIsFine(t *testing.T) {
	found := ignoredErrorMessages(t, map[string]string{"storage/storage.go": `package storage

import "fmt"

func announce() int {
	n, _ := fmt.Println("hello")
	return n
}
`})
	assert.Empty(t, found, "печать — признанное исключение: %v", found)
}

// Явная пометка nolint комментарием над строкой — тоже пометка.
func TestIgnoredError_NolintAboveLineIsRespected(t *testing.T) {
	found := ignoredErrorMessages(t, map[string]string{"storage/storage.go": `package storage

type Repo struct{}

func (r *Repo) List(userID string) ([]int, error) { return nil, nil }

func Collect(r *Repo, userID string) []int {
	//nolint:errcheck // ответ уже отправлен, сообщать об ошибке некому
	items, _ := r.List(userID)
	return items
}
`})
	assert.Empty(t, found, "пометка над строкой должна учитываться: %v", found)
}

// Откат транзакции: ошибка отката идёт поверх уже случившейся ошибки.
func TestIgnoredError_RollbackIsFine(t *testing.T) {
	found := ignoredErrorMessages(t, map[string]string{"storage/storage.go": `package storage

type tx struct{}

func (t *tx) Rollback() error { return nil }

func abort(t *tx) {
	_ = t.Rollback()
}
`})
	assert.Empty(t, found, "Rollback — признанное исключение: %v", found)
}

// hash.Hash, strings.Builder и bytes.Buffer документируют, что их Write никогда
// не возвращает ошибку. Требовать её проверки — просить писать мёртвую ветку:
// в projectC из-за этого флагилось построение fnv-хеша (seedHash).
func TestIgnoredError_WritesThatCannotFail(t *testing.T) {
	found := ignoredErrorMessages(t, map[string]string{"mutator/mutator.go": `package mutator

import (
	"bytes"
	"hash/fnv"
	"strings"
)

func SeedHash(seed, salt string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(salt))
	_, _ = h.Write([]byte(seed))
	return h.Sum64()
}

func Join(parts []string) string {
	var b strings.Builder
	var buf bytes.Buffer
	for _, part := range parts {
		_, _ = b.WriteString(part)
		_, _ = buf.Write([]byte(part))
	}
	return b.String() + buf.String()
}
`})
	assert.Empty(t, found, "запись в хеш и в буфер не может провалиться: %v", found)
}
