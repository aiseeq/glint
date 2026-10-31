# sql-injection: any one-argument bool predicate in a rejecting if counts as a whitelist

Статус: открыт

## Что сделать
- Находка F2 критика ТЗ «как сделано» (тикет spec-as-built, /home/aisee/.claude/tools/glint/critic.md, раздел «F2»): pkg/rules/security/sql_query_taint.go:223,544 — любая функция с одним аргументом и bool/error-результатом считается валидатором; чёрный список (isBlocked) освобождает инъекцию.
- TDD-репро по общей пробе /home/aisee/.cache/worktrees/glint-measure/spec/critic-probe (main.go, client.js); затем фикс правила.

## Приёмка
- `glint check -C /home/aisee/.cache/worktrees/glint-measure/spec/critic-probe -r sql-injection --no-cache ./...`: есть main.go:23 (wrongCheck), настоящий белый список по-прежнему освобождает
- Прогон bin/consumers по правилу до установки, каждая новая находка разобрана; graft all зелёный.

## Журнал
- 2026-10-31 17:44 открыт — glint-master
