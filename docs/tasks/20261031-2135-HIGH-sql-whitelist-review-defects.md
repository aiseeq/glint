# sql-injection: whitelist defects after 2da8913

Статус: в работе
Исполнитель: glint-master

## Что сделать
- Дефекты коммита 2da8913 (белые списки sql-injection), найденные независимой проверкой (Terra 1031-2128-glint) на синтетической пробе probe-verify-sql/probe.go:
  - :108 `if x != "a" && x != "b" { return }` — ложная находка, регресс против 2da8913^: цепочка && из != с непустыми константами отклоняет всё вне конечного набора.
  - :38 проверка до сразу вызываемой closure, запрос внутри неё — ложная находка, регресс.
  - :114 литеральная map, затем запись `allowed[input] = true` — пропуск: map с записью после литерала не конечный набор.
  - :119 `map[string]bool{input: true}` — пропуск: ключи литерала должны быть константами.
  - :123 `if err := validate(x); err == nil { return }` — пропуск: валидатор с ошибкой засчитывается только при отклонении по `err != nil`.
- Вне охвата: якорный регексп с широким классом (`^.*$`, :100).
- После влития sec-http (тот же файл sql_query_taint.go).

## Приёмка
- Проба probe-verify-sql: находки 13 34 43 47 51 71 88 92 96 114 119 123 126 131; нет находок 18 22 26 30 38 55 60 65 75 84 104 108.
- probe, probe-sql2, probe-http — как в accept-http.sh; self-check pkg/rules/security чист; потребители без новых находок или каждая разобрана.

## Журнал
- 2026-10-31 21:35 открыт — glint-master
- 2026-10-31 21:41 в работе — glint-master
- 2026-10-31 21:41 note — glint-master: боец Luna: бриф /home/aisee/.cache/worktrees/glint-measure/security/brief-sql-review.md, приёмка accept-sql-review.sh, дерево /home/aisee/.cache/worktrees/glint/sql-review
