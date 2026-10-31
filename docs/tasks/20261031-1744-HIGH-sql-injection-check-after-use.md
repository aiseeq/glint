# sql-injection: a check after the query clears the parameter before it

Статус: открыт

## Что сделать
- Находка F1 критика ТЗ «как сделано» (тикет spec-as-built, /home/aisee/.claude/tools/glint/critic.md, раздел «F1»): проверки параметра собираются по всему файлу (pkg/rules/security/sql_query_taint.go:97,126) без порядка относительно запроса; проверка после db.Query снимает находку.
- TDD-репро по общей пробе /home/aisee/.cache/worktrees/glint-measure/spec/critic-probe (main.go, client.js); затем фикс правила.

## Приёмка
- `glint check -C /home/aisee/.cache/worktrees/glint-measure/spec/critic-probe -r sql-injection --no-cache ./...`: есть main.go:13 (late), проверка до запроса по-прежнему освобождает
- Прогон bin/consumers по правилу до установки, каждая новая находка разобрана; graft all зелёный.

## Журнал
- 2026-10-31 17:44 открыт — glint-master
