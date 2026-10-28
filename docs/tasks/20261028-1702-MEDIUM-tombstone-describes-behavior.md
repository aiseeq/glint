# tombstone-comment: комментарий о поведении («a trim removed») — не надгробие

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
- tombstone-comment: ложное срабатывание на doc-комментарий к типу, описывающий поведение: `// Result counts the entries a trim removed, or would remove, and kept.` над `type Result struct { Removed, Kept int; RemovedBytes, KeptBytes int64 }` (сообщение graft-master, graft d64fbd1, internal/gocache/gocache.go:24).
- TDD: красный тест с синтетикой → фикс правила.

## Приёмка
- `go test ./pkg/rules/patterns/gorules/ -run Tombstone` зелёный, старые позитивы на месте.
- `graft self-check`, прогон `bin/glint check -r tombstone-comment` по потребителям: новых находок нет, исчезли только ложные.

## Журнал
- 2026-10-28 17:02 открыт — glint-master
- 2026-10-28 17:07 в работе — glint-master
- 2026-10-28 17:07 note — glint-master: Фикс: первое предложение godoc, открытое именем объявления ниже, не надгробие (godocFirstSentence/describesDeclaration). Тест TestTombstoneComment_GodocSentenceDescribesTheName красный→зелёный; исходный файл graft d64fbd1: старый бинарь — строка 24, новый — нет; потребители: 0 находок до и после; graft all зелёный.
