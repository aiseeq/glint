package patterns

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewUnfalsifiableTestCaseRule())
}

// UnfalsifiableTestCaseRule detects a browser/API test whose every assertion holds no matter
// what the code under test does.
//
// Родилось из разбора e2e-набора projectA (REF-410/REF-468). Два спека «проверяли» показ
// балансов так: мокали два адреса, которых на бэкенде не существует, шли на страницу,
// которой в приложении нет, и утверждали «URL содержит deposits, body виден, элементов
// больше нуля». Они годами проходили против страницы 404 и считались покрытием. Ещё
// несколько спеков писали expect([200, 404]).toContain(status) — при таком наборе
// одинаково засчитываются и рабочий эндпоинт, и удалённый.
//
// Каждое из таких утверждений по отдельности бывает уместно как разогрев. Признак
// проблемы в том, что в тесте нет ни одного другого: тогда тест не может упасть и
// сообщает только о том, что фронтенд отдал HTML.
//
// Правило работает по TypeScript и JavaScript тестам. Go-тесты закрывает
// tautological-assertion.
type UnfalsifiableTestCaseRule struct {
	*rules.BaseRule

	testStart      *regexp.Regexp
	assertionStart *regexp.Regexp
	assertion      *regexp.Regexp
	genericScope   *regexp.Regexp
	countFrom      *regexp.Regexp
	optionalGuard  *regexp.Regexp
}

// NewUnfalsifiableTestCaseRule creates the rule.
func NewUnfalsifiableTestCaseRule() *UnfalsifiableTestCaseRule {
	return &UnfalsifiableTestCaseRule{
		BaseRule: rules.NewBaseRule(
			"unfalsifiable-test-case",
			"patterns",
			"Detects a test whose every assertion holds regardless of the behaviour under test",
			core.SeverityHigh,
		),
		// describe/suite — это группа, а не тест: утверждения живут в отдельных test(...)
		testStart: regexp.MustCompile(`^\s*(?:it|test)(?:\.(?:only|skip|fixme|failing|concurrent|serial))?\s*\(\s*['"` + "`" + `](.+?)['"` + "`" + `]\s*,`),
		// начало проверки: expect(, но не expect.any/expect.objectContaining внутри матчера
		assertionStart: regexp.MustCompile(`\bexpect\s*\(`),
		// разбираемая целиком однострочная проверка; хвостовой комментарий не мешает
		assertion: regexp.MustCompile(`expect\s*\((.*)\)\s*\.\s*(?:resolves\s*\.\s*|rejects\s*\.\s*)?(?:not\s*\.\s*)?(\w+)\s*\((.*?)\)\s*;?\s*(?://.*)?$`),
		// body/html/div и звёздочка есть на любой отрисованной странице, включая 404
		genericScope: regexp.MustCompile(`locator\s*\(\s*['"` + "`" + `]\s*(?:body|html|div|\*|div,\s*body)\s*['"` + "`" + `]\s*\)|^\s*page\s*$`),
		countFrom:    regexp.MustCompile(`(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*await\s+([^\n;]*\.count\s*\(\s*\))`),
		// `if (resp.ok())`, `if (items.length > 0)` — условие ложно ровно тогда, когда
		// проверяемое поведение сломано, поэтому проверки внутри до дела не доходят.
		optionalGuard: regexp.MustCompile(`^\s*\}?\s*if\s*\(\s*[^)]*(?:\.ok\s*\(\s*\)|\.length\s*>\s*0|\.length\s*!==?\s*0|!==?\s*(?:null|undefined)|^\s*[A-Za-z_$][\w$.]*\s*)\)\s*\{`),
	}
}

// httpStatusSet parses `[200, 404]` and reports whether the set mixes success with failure:
// такой набор принимает и рабочий эндпоинт, и удалённый.
func httpStatusSet(arg string) bool {
	trimmed := strings.TrimSpace(arg)
	if !strings.HasPrefix(trimmed, "[") || !strings.HasSuffix(trimmed, "]") {
		return false
	}
	var hasOK, hasFail bool
	for _, part := range strings.Split(trimmed[1:len(trimmed)-1], ",") {
		part = strings.TrimSpace(part)
		// Нечисловой элемент означает, что это не набор кодов ответа, а какой-то другой
		// список: классификация, а не ошибка разбора, поэтому Atoi сюда не зовётся.
		if part == "" || strings.Trim(part, "0123456789") != "" {
			return false
		}
		code, _ := strconv.Atoi(part) // строка из одних цифр — ошибки быть не может
		switch {
		case code >= 200 && code < 300:
			hasOK = true
		case code >= 400:
			hasFail = true
		}
	}
	return hasOK && hasFail
}

// unfalsifiable reports whether a single assertion carries no information about behaviour.
func (r *UnfalsifiableTestCaseRule) unfalsifiable(subject, matcher, arg string, counters map[string]bool) bool {
	subject = strings.TrimSpace(subject)
	arg = strings.TrimSpace(arg)

	// expect([200, 404]).toContain(status) — принимается любой исход
	if matcher == "toContain" && httpStatusSet(subject) {
		return true
	}
	// expect(page.locator('body')).toBeVisible() — есть на любой странице
	if r.genericScope.MatchString(subject) {
		return true
	}
	// «элементов больше нуля» — на отрисованной странице всегда так
	if (matcher == "toBeGreaterThan" && arg == "0") || (matcher == "toBeTruthy" && arg == "") {
		if strings.Contains(subject, ".count()") || counters[subject] {
			return true
		}
	}
	return false
}

// AnalyzeFile walks each test body and reports the ones with no falsifiable assertion.
func (r *UnfalsifiableTestCaseRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsTestFile() || (!ctx.IsTypeScriptFile() && !ctx.IsJavaScriptFile()) {
		return nil
	}

	var violations []*core.Violation
	counters := map[string]bool{}
	for _, line := range ctx.Lines {
		if m := r.countFrom.FindStringSubmatch(line); m != nil {
			if r.genericScope.MatchString(m[2]) {
				counters[m[1]] = true
			}
		}
	}

	type openTest struct {
		name   string
		line   int
		depth  int
		total  int
		unfals int // не могут упасть сами по себе
		hidden int // спрятаны за условием, ложным ровно при поломке
	}
	var current *openTest
	depth := 0
	guardDepth := 0

	flush := func() {
		if current == nil {
			return
		}
		if current.total > 0 && current.total == current.unfals+current.hidden {
			reason := "every check holds on any rendered page or any HTTP status"
			if current.hidden > 0 && current.unfals == 0 {
				reason = "every check sits behind a condition that is false exactly when the feature is broken"
			} else if current.hidden > 0 {
				reason = "every check either holds unconditionally or sits behind a condition that is false exactly when the feature is broken"
			}
			v := r.CreateViolation(ctx.RelPath, current.line,
				"Test '"+current.name+"' has no assertion that could fail — "+reason)
			v.WithCode(strings.TrimSpace(ctx.GetLine(current.line)))
			v.WithSuggestion("Assert what the feature actually produces (a value, a specific element, a concrete status), or delete the test instead of claiming coverage")
			v.WithContext("pattern", "unfalsifiable_test_case")
			v.WithContext("assertions", strconv.Itoa(current.total))
			violations = append(violations, v)
		}
		current = nil
	}

	for i, line := range ctx.Lines {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "//") && !strings.HasPrefix(trimmed, "*") {
			if current == nil {
				if m := r.testStart.FindStringSubmatch(line); m != nil {
					current = &openTest{name: m[1], line: i + 1, depth: depth}
				}
			}
			if current != nil {
				if r.optionalGuard.MatchString(line) {
					guardDepth = depth + 1
				}
				if r.assertionStart.MatchString(trimmed) {
					current.total++
					m := r.assertion.FindStringSubmatch(trimmed)
					switch {
					// Спрятанность от матчера не зависит: до проверки внутри условия
					// дело не доходит, что бы она ни утверждала.
					case guardDepth > 0 && depth >= guardDepth:
						current.hidden++
					// Проверку, которую не удалось разобрать целиком (перенесена на
					// несколько строк), считаем содержательной: занижать здесь нельзя,
					// иначе правило обвинит тест, у которого проверка как раз есть.
					case m == nil:
					case r.unfalsifiable(m[1], m[2], m[3], counters):
						current.unfals++
					}
				}
			}
		}
		depth += strings.Count(line, "{") - strings.Count(line, "}")
		if guardDepth > 0 && depth < guardDepth {
			guardDepth = 0
		}
		if current != nil && depth <= current.depth && i > current.line-1 {
			guardDepth = 0
			flush()
		}
	}
	flush()

	return violations
}
