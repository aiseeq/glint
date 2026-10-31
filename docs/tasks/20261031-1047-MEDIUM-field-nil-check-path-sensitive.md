# field-nil-check-inconsistent: a nil check counts only on the path it guards

Статус: открыт

## Вход
- Проверка opus-check 31.10 тикета field-nil-check-inconsistent: fieldNilCheckPrecedes (pkg/rules/patterns/gorules/field_nil_check_inconsistent.go:321) считает защитой любое более раннее по тексту сравнение поля с nil. Проба `if r.portfolio != nil { println() }; v, _ := r.portfolio.Valuation(ctx)` — 0 находок, хотя после if поле не проверено. falseGuard ищется по всему телу предиката (не пробовано).
- Слабости записаны в журнале field-nil-check-inconsistent 29.10 23:34, своего тикета не было.

## Что сделать
1. TDD: красный тест на пробу выше; отрицательные — разыменование внутри `if f != nil {}`, после `if f == nil { return }`.
2. Защиту считать по пути: patternkit.FlowWalker (CLAUDE.md, path-sensitive правила), пути — JoinFlowPaths.
3. Прогон по потребителям до установки.

## Приёмка
- Проба даёт находку, прежние тесты TestFieldNilCheckInconsistent* зелёные, bin/consumers разобран.

## Журнал
- 2026-10-31 10:47 открыт — glint-master
