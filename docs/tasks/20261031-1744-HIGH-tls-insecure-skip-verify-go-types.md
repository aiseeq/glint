# tls-verification-disabled (Go): assignment missed, a foreign struct field reported

Статус: открыт

## Что сделать
- Находка F4 критика ТЗ «как сделано» (тикет spec-as-built, /home/aisee/.claude/tools/glint/critic.md, раздел «F4»): pkg/rules/security/tls_verification_disabled.go:57 смотрит только ключи литералов по имени без типа: c.InsecureSkipVerify = true пропущено, Options{InsecureSkipVerify: true} — ложная HIGH.
- TDD-репро по общей пробе /home/aisee/.cache/worktrees/glint-measure/spec/critic-probe (main.go, client.js); затем фикс правила.

## Приёмка
- `glint check -C /home/aisee/.cache/worktrees/glint-measure/spec/critic-probe -r tls-verification-disabled --no-cache ./...`: есть main.go:6, нет main.go:8, литерал tls.Config ловится
- Прогон bin/consumers по правилу до установки, каждая новая находка разобрана; graft all зелёный.

## Журнал
- 2026-10-31 17:44 открыт — glint-master
