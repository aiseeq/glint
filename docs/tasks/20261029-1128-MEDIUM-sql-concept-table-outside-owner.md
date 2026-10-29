# SQL: таблица понятия читается вне владельца (R2)

Статус: в работе
Исполнитель: glint-master

## Вход
- Проблема:
- Метод:
- Дешевле:
- Инструмент:
- Цена:
- Если не делать:

## Что сделать
- R2 из запроса 29.10 (см. sql-predicate-copies-constant): новое правило `sql-concept-table-outside-owner`. Настройка правила `concepts`: список {name, table, where (необязательный фрагмент условия), files (globs владельцев)}. Находка — SQL-литерал вне files, читающий table через FROM, INNER JOIN, EXISTS или IN-подзапрос (и, если задан where, с конъюнктом, равным where по нормализации общего модуля). LEFT/RIGHT/FULL JOIN таблицы, чьи колонки WHERE не проверяет на NULL, — не находка (добавляет колонки, а не решает членство). Без настройки правило молчит.
- Зависит от общего модуля (тикет sql-predicate-copies-constant).

## Приёмка
- Тесты брифа, `graft all`, self-check; формат настройки — в doc правила; прогон по потребителям (без настройки — 0).

## Журнал
- 2026-10-29 11:28 открыт — glint-master
- 2026-10-29 14:24 в работе — glint-master
- 2026-10-29 14:24 note — glint-master: Боец 1029-1424-sql-concept-owner (luna, escalate terra), бриф brief-sql-concept-owner.md, приёмка accept-sql-concept-owner.sh (гейт, 6 обязательных тестов, go test, self-check 0).
- 2026-10-29 14:42 note — glint-master: Боец сдал (приёмка ok). Проба на копии потребителя с двумя понятиями: 1 находка в dev-утилите cmd/ — ожидаемая (исключить cmd/** настройкой), LEFT JOIN ради колонки — не находка. Раунд 1: glob ядра (filepath.Match не понимает **), where по всему запросу через Conjuncts (убрать whereConjuncts и фолбек-строку), формат настройки categories.patterns.rules. review-sql-concept-owner-1.md.
- 2026-10-29 15:44 note — glint-master: Раунд 1 принят: проба на копии потребителя с владельцем cmd/** — 0 находок. Влито ab43475; мастер убрал алиас matchGlobPattern (единая core.MatchGlob).
- 2026-10-29 15:51 note — glint-master: graft all rc=0, self-check 0. Прогон трёх правил по потребителям бинарём main: 10 находок у 4 потребителей, все верные (scratchpad consumer-findings.tsv); R2 без настройки — 0. Дальше install и письма агентам.
- 2026-10-29 15:53 note — glint-master: Установлено 2a1de99 (v1.83.7-91). Письма агентам потребителей В, Б, Г и заказчику (формат R2). Независимая проверка — боец Terra 1029-1553-review-sql-rules (brief-review-sql-rules.md).
- 2026-10-29 15:57 note — glint-master: Проверка Terra: приёмка да, но 5 дефектов (регистр литералов в Norm; R2 схема и CTE; R3 схема; параметр в IN; дубль AND). Раунд правок — боец Luna sql-rules-fixes, brief-sql-rules-fixes.md.
- 2026-10-29 16:08 note — glint-master: Дефекты проверки Terra исправлены (f73a3f2, тесты на каждый): graft all rc=0, self-check 0, прогон по потребителям — только 2 верные находки потребителя А (ещё не исправлены у него).
