# tls-verification-disabled (JS/TS): quoted key missed, a string value reported

Статус: открыт

## Что сделать
- Находка F5 критика ТЗ «как сделано» (тикет spec-as-built, /home/aisee/.claude/tools/glint/critic.md, раздел «F5»): pkg/rules/security/tls_verification_disabled.go:44,74 — регулярка по тексту: ключ "rejectUnauthorized" в кавычках пропущен, строка "rejectUnauthorized: false" — ложная HIGH.
- TDD-репро по общей пробе /home/aisee/.cache/worktrees/glint-measure/spec/critic-probe (main.go, client.js); затем фикс правила.

## Приёмка
- `glint check -C /home/aisee/.cache/worktrees/glint-measure/spec/critic-probe -r tls-verification-disabled --no-cache ./...`: есть client.js:1 и 2, нет client.js:3
- Прогон bin/consumers по правилу до установки, каждая новая находка разобрана; graft all зелёный.

## Журнал
- 2026-10-31 17:44 открыт — glint-master
