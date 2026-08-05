package patterns

import (
	"testing"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// successGuardViolations отбирает находки только нового детектора, чтобы тест не
// зависел от остальных паттернов error-masking.
func successGuardViolations(t *testing.T, source string) []string {
	t.Helper()

	ctx := rulestest.GoFile(t, "dashboard/dashboard.go", source)
	var out []string
	for _, v := range NewErrorMaskingRule().AnalyzeFile(ctx) {
		if v.Context["pattern"] == "success_only_guard" {
			out = append(out, v.Message)
		}
	}
	return out
}

// Репро SI-461: сбор сегодняшних операций для карточки «Баланс». При ошибке
// репозитория разбивка оставалась нулевой, и вызывающий код не мог отличить
// «сегодня движений не было» от «запрос упал» — заголовок показывал вчерашний
// снапшот как актуальный.
func TestErrorMasking_SuccessOnlyGuardInline(t *testing.T) {
	found := successGuardViolations(t, `package dashboard

type breakdown struct {
	Deposits int
}

type repo interface {
	ListToday(userID string) ([]int, error)
}

func todayBreakdown(r repo, userID string) breakdown {
	var out breakdown
	if items, err := r.ListToday(userID); err == nil {
		out.Deposits = len(items)
	}
	return out
}
`)
	require.Len(t, found, 1, "успех присвоен, провал молча пропущен: %v", found)
}

// Та же дыра в две строки: ошибка получена в переменную и после проверки на
// успех больше нигде не используется.
func TestErrorMasking_SuccessOnlyGuardSeparateCheck(t *testing.T) {
	found := successGuardViolations(t, `package dashboard

type repo interface {
	Total(userID string) (int, error)
}

func totalOrZero(r repo, userID string) int {
	var total int
	value, err := r.Total(userID)
	if err == nil {
		total = value
	}
	return total
}
`)
	require.Len(t, found, 1, "ошибка получена и выброшена: %v", found)
}

// Ошибка уходит наверх возвратом — вызывающий отличит провал от пустоты, даже
// если внутри стоит проверка на успех.
func TestErrorMasking_SuccessGuardInErrorReturningFuncIsFine(t *testing.T) {
	found := successGuardViolations(t, `package dashboard

type repo interface {
	Total(userID string) (int, error)
}

func totalOrError(r repo, userID string) (int, error) {
	total := 0
	value, err := r.Total(userID)
	if err == nil {
		total = value
	}
	return total, err
}
`)
	assert.Empty(t, found, "функция отдаёт ошибку наверх: %v", found)
}

// Есть else — провал обработан явно, пусть даже логом.
func TestErrorMasking_SuccessGuardWithElseIsFine(t *testing.T) {
	found := successGuardViolations(t, `package dashboard

import "log"

type repo interface {
	Total(userID string) (int, error)
}

func totalWithLog(r repo, userID string) int {
	var total int
	value, err := r.Total(userID)
	if err == nil {
		total = value
	} else {
		log.Printf("total failed: %v", err)
	}
	return total
}
`)
	assert.Empty(t, found, "else разбирает провал: %v", found)
}

// Ошибка использована после блока — вызывающий её видит.
func TestErrorMasking_ErrUsedAfterGuardIsFine(t *testing.T) {
	found := successGuardViolations(t, `package dashboard

import "log"

type repo interface {
	Total(userID string) (int, error)
}

func totalLogged(r repo, userID string) int {
	var total int
	value, err := r.Total(userID)
	if err == nil {
		total = value
	}
	if err != nil {
		log.Printf("total failed: %v", err)
	}
	return total
}
`)
	assert.Empty(t, found, "ошибка разобрана ниже по коду: %v", found)
}

// Comma-ok: второе значение — bool, а не error.
func TestErrorMasking_CommaOkGuardIsFine(t *testing.T) {
	found := successGuardViolations(t, `package dashboard

func lookup(m map[string]int, key string) int {
	var out int
	if value, ok := m[key]; ok {
		out = value
	}
	return out
}
`)
	assert.Empty(t, found, "comma-ok нарушением не является: %v", found)
}

// Внутри блока успеха стоит return — это выход из функции, а не тихое
// присваивание наружу; такой код читается явно и ловится другими правилами.
func TestErrorMasking_ReturnInsideSuccessGuardIsFine(t *testing.T) {
	found := successGuardViolations(t, `package dashboard

type repo interface {
	Total(userID string) (int, error)
}

func totalOrDefault(r repo, userID string) int {
	if value, err := r.Total(userID); err == nil {
		return value
	}
	return -1
}
`)
	assert.Empty(t, found, "выход из функции — не молчаливое присваивание: %v", found)
}

// Уточнение уже осмысленного значения: host до проверки содержит вход, а
// SplitHostPort лишь отрезает порт, если он есть. Провал здесь означает «порта
// нет», значение по умолчанию видно в коде, потери данных нет.
func TestErrorMasking_RefinementOfExistingValueIsFine(t *testing.T) {
	found := successGuardViolations(t, `package dashboard

import (
	"net"
	"strings"
)

func normalizeHost(host string) string {
	host = strings.TrimSpace(host)
	if parsed, _, err := net.SplitHostPort(host); err == nil {
		host = parsed
	}
	return host
}
`)
	assert.Empty(t, found, "уточнение готового значения нарушением не является: %v", found)
}

// Параметр приходит со значением от вызывающего: guard лишь уточняет его, провал
// означает «оставить как передали». hasValueBefore обязан видеть fn.Type.Params,
// а не только присваивания в теле.
func TestErrorMasking_ParamRefinementIsFine(t *testing.T) {
	found := successGuardViolations(t, `package dashboard

import "strconv"

func ChooseLimit(raw string, limit int) int {
	if v, err := strconv.Atoi(raw); err == nil {
		limit = v
	}
	return limit
}
`)
	assert.Empty(t, found, "параметр уже имеет значение от вызывающего: %v", found)
}

// Receiver — тот же случай, что и параметр: значение приходит от вызывающего.
func TestErrorMasking_ReceiverRefinementIsFine(t *testing.T) {
	found := successGuardViolations(t, `package dashboard

import "strconv"

type cache struct {
	limit int
}

func (c *cache) refresh(raw string) {
	if v, err := strconv.Atoi(raw); err == nil {
		c.limit = v
	}
}
`)
	assert.Empty(t, found, "receiver уже имеет значение от вызывающего: %v", found)
}

// Накопление в срез: при провале элемент молча исчезает из результата, сколько бы
// значений там уже ни лежало.
func TestErrorMasking_AppendUnderGuardIsFlagged(t *testing.T) {
	found := successGuardViolations(t, `package dashboard

import "time"

func parseDates(keys []string) []time.Time {
	out := make([]time.Time, 0, len(keys))
	for _, key := range keys {
		if date, err := time.Parse("2006-01-02", key); err == nil {
			out = append(out, date)
		}
	}
	return out
}
`)
	require.Len(t, found, 1, "потерянный элемент среза — та же тишина: %v", found)
}

// Сигнатура с error сама по себе не спасает: если конкретная ошибка выброшена
// внутри guard'а, а функция возвращает nil, потеря та же.
func TestErrorMasking_ErrorReturningFuncStillDropsThisError(t *testing.T) {
	found := successGuardViolations(t, `package dashboard

type repo interface {
	Aggregates() (int, error)
}

func business(r repo) (int, error) {
	var total int
	if value, err := r.Aggregates(); err == nil {
		total = value
	}
	return total, nil
}
`)
	require.Len(t, found, 1, "ошибка выброшена внутри guard'а: %v", found)
}
