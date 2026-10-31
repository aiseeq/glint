# Гейт коммита без glint на себе: причина в CLAUDE.md, self-check — условие install

Статус: готово
Исполнитель: glint-master

## Вход
- Проблема: обход processes Сна 30.10 (git-admin): решение glint-threshold требует glint в гейте коммита всех Go-проектов; гейт glint (`smoke`) — только fmt-check и test-short; install glint на себе не проверяет (deps: build).
- Метод: glint доходит до потребителей только через `graft install`; install ставится в зависимость от self-check (min_severity low — строже гейта на high), гейт коммита остаётся без glint. Причина — в CLAUDE.md проекта, исключение вносит Сон.
- Дешевле: self-check в гейте — +30 с на каждый коммит (замер 30.10: 29,5 с без кэша на простое, test-short 31 с), гейт за минуту; при install self-check берётся из кэша graft после `graft all`.
- Если не делать: install без self-check пропустит находки glint на себе к потребителям.

## Что сделать
- .graft.yaml: install deps [build, self-check].
- CLAUDE.md: строка причины.
- Ответ git-admin.

## Приёмка
- `graft install` при находке self-check падает до установки (проверка: временная находка в worktree → install отказывает).

## Журнал
- 2026-10-30 02:34 открыт — glint-master
- 2026-10-30 02:34 в работе — glint-master
- 2026-10-30 02:41 note — glint-master: проба: worktree с временным .py (python-file, HIGH) — graft install упал на self-check кодом 1 до установки. Порог self-check — fail_on high (умолчание), не low; комментарий у gate в .graft.yaml
- 2026-10-30 02:41 note — glint-master: 8d14da4; итог — git-admin
- 2026-10-30 02:41 на проверке — glint-master
- 2026-10-31 10:43 готово — opus-check (session glint-master): 8d14da4 в main: .graft.yaml install deps [build, self-check], причина комментарием у gate: (.graft.yaml:9-12; вместо CLAUDE.md — обосновано в письме git-admin c4beb326:460, git-admin передал Сну решение о дубле в CLAUDE.md, d20effec:4254). Проба 31.10: копия HEAD в scratchpad, шаг install заменён на echo, временный probe_tmp.py → graft install: self-check 1 High (python-file), exit 1, шаг install не выполнен
