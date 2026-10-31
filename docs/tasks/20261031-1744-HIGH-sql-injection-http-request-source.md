# sql-injection: a value from the HTTP request is not a taint source

Статус: открыт

## Что сделать
- Находка F3 критика ТЗ «как сделано» (тикет spec-as-built, /home/aisee/.claude/tools/glint/critic.md, раздел «F3»): pkg/rules/security/sql_query_taint.go:403,413 — результат вызова не прослеживается; r.URL.Query().Get, FormValue, PathValue и т. п. не источник.
- TDD-репро по общей пробе /home/aisee/.cache/worktrees/glint-measure/spec/critic-probe (main.go, client.js); затем фикс правила.

## Приёмка
- `glint check -C /home/aisee/.cache/worktrees/glint-measure/spec/critic-probe -r sql-injection --no-cache ./...`: есть main.go:11 (handler), main.go:10 остаётся
- Прогон bin/consumers по правилу до установки, каждая новая находка разобрана; graft all зелёный.

## Журнал
- 2026-10-31 17:44 открыт — glint-master
