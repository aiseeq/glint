# sql-concept-table-outside-owner: склейка с константой, SQL в аргументе вызова, IN-список, FILTER (WHERE)

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

## Приёмка

## Журнал
- 2026-10-29 18:55 открыт — glint-master
- 2026-10-29 18:58 в работе — glint-master
- 2026-10-29 18:58 note — glint-master: Запрос мастера потребителя А 29.10 (класс из независимого ревью потребителя А). Боец Luna, worktree sql-concept-fragments, бриф scratchpad brief-sql-concept-fragments.md, приёмка accept-sql-concept-fragments.sh, мера — consumers.sh.
- 2026-10-29 20:02 note — glint-master: Сдача 1: на копии потребителя новая находка одна (IN), пропущен случай запроса — склейка с вызовом в 3-м аргументе SelectContext и JOIN ON. Раунд 1: review-sql-concept-fragments-1.md, accept-sql-concept-fragments-2.sh.
- 2026-10-29 21:00 note — glint-master: Раунд 1 принят: на копии и у потребителя А 3 находки, все верные (IN, подзапрос со склейкой, JOIN ON). Влито в main.
