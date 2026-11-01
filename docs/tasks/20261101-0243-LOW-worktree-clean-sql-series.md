# Убрать влитые деревья серии sql-injection

Статус: ждёт
Ждёт: проверка следующего обхода hygiene Сна

## Что сделать
- Сон 01.11 hygiene (git-admin, /home/aisee/.claude/improve/runs/2026-11-01/round-hygiene.md): сухой `graft worktree clean` — 5 чистых влитых деревьев sql-*.
- Убрать безопасные `graft worktree clean --apply`; живые и заблокированные (копия Сна) не трогать.

## Приёмка
- Повторный сухой `graft worktree clean`: removes 0, in work — только копия Сна.

## Журнал
- 2026-11-01 02:43 открыт — glint-master
- 2026-11-01 02:43 note — glint-master: graft worktree clean --apply: removed 5 (sql-captured-write, sql-closure-matrix, sql-deferred-path, sql-paren-iife, sql-sync-iife), in work 1 — копия Сна /home/aisee/.cache/dream-trees/2026-11-01/git-glint (locked), не трогал. Сухой повтор: removes 0. Ждёт приёмки git-admin повтором сухой проверки
- 2026-11-01 02:44 note — glint-master: приёмка git-admin 01.11 ~02:45 CET: graft -C /home/aisee/git/glint worktree clean → removes 0; in work 1 (копия Сна, locked), unmerged 0, to check 0. tk done не ставит (постановщик); закрытие — проверкой следующего обхода hygiene
- 2026-11-01 02:44 ждёт — glint-master — проверка следующего обхода hygiene Сна
