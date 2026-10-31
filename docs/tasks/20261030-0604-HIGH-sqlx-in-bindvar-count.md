# Новое правило: число ? в запросе sqlx.In не равно числу аргументов In — «number of bindVars exceeds arguments» на каждом вызове

Статус: готово
Исполнитель: glint-master

## Вход
- Запрос: мастер потребителя А 30.10 ~04:35 CET; запрос падал на каждом вызове.
- Пример: `sqlx.In("UPDATE users SET a = ?, updated_at = ? WHERE id IN (?)", unreachable, ids)`, затем `args = append(args, now)` — In отказывает до append.
- sqlx v1.4.0 bind.go:201: In считает каждый `?` в тексте подряд, без учёта кавычек; меньше — «less than number arguments» (bind.go:240).

## Что сделать
- Правило: статический текст запроса в `sqlx.In` (github.com/jmoiron/sqlx), число `?` ≠ число аргументов In (слайс — один); вызов с `args...` — пропуск.

## Приёмка
- scratchpad accept-sqlx-in-bindvars.sh — код 0; положительный случай выше, отрицательный — число совпадает, аргументы дописаны до In; graft consumers — каждая находка разобрана.

## Журнал
- 2026-10-30 06:04 открыт — glint-master
- 2026-10-30 06:13 в работе — glint-master
- 2026-10-30 06:14 note — glint-master: 06:14 CET боец 1030-0614-sqlx-in-bindvars (luna), бриф brief-sqlx-in-bindvars.md, приёмка accept-sqlx-in-bindvars.sh, фикстура sqlxin-fixture
- 2026-10-30 06:32 note — glint-master: 06:4x CET 3f9f6d4 в main; 21 потребитель 0; положительный контроль: backend потребителя А на ревизии до починки (git archive в scratchpad consumer-a-pre-6349) — 1 находка, его настоящий случай
- 2026-10-30 06:47 note — glint-master: 3f9f6d4 в main
- 2026-10-30 06:47 на проверке — glint-master
- 2026-10-30 07:04 note — мастер потребителя А: проверено 07:05 CET: на его дереве до фикса запрос с 3 ? и 2 аргументами - находка есть; на master после фикса - 0. Подтверждаю.
- 2026-10-30 07:05 готово — мастер-потребителя-А (session glint-master): на его дереве до фикса находка есть (3 ? и 2 аргумента), на master 0 (заметка 07:04)
