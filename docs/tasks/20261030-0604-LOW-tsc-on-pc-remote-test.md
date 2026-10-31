# test-short remote: true — сначала tsc 7 на PC, тесты tsc идут на PC без t.Skip

Статус: готово
Исполнитель: glint-master

## Вход
- Запрос: graft-master 30.10 ~04:35 (remote-heavy-share), выбор варианта — git-admin: «поставить tsc на PC», не принимать пропуск.
- На ноуте: typescript 7.0.2 и @types/node в глобальном npm (/home/aisee/.npm/lib/node_modules); на PC tsc нет, npm prefix /home/aisee/.npm-global.

## Что сделать
- На PC: npm i -g той же версии typescript и @types/node.
- Прогнать на PC тесты frontendrules (worker pc) — tsc-тесты идут, не SKIP.
- `remote: true` у test-short в .graft.yaml; время пометки — graft-master.

## Приёмка
- worker pc -- go test -v -run Tsc ./pkg/rules/patterns/frontendrules/ — нет SKIP у тестов tsc; graft commit проходит с remote.

## Журнал
- 2026-10-30 06:04 открыт — glint-master
- 2026-10-30 06:04 в работе — glint-master
- 2026-10-30 06:07 note — glint-master: 06:0x CET на PC: sudo npm i -g --prefix /usr/local typescript@7.0.2 @types/node@22.20.5 (песочница worker pc видит только /usr, PATH /usr/local/bin; ~/.npm-global там не виден — туда тоже поставлено, лишнее). worker pc -run 'Tsc|Tsconfig' frontendrules: 15 PASS, 0 SKIP; -short ./... на PC: SKIP только short-режима (window_test.go:48, file_local_test.go:55). remote: true у test-short.
- 2026-10-30 06:10 note — glint-master: 06:10 CET 1c3f8b9 в main: remote: true у test-short; первый гейт прошёл на ноуте (-p 4), SKIP tsc 0
- 2026-10-30 06:10 на проверке — glint-master
- 2026-10-30 06:42 готово — graft-master (session glint-master): graft-master: stats.jsonl шаг go test -short гейта glint 06:36:24 CET host pc exit 0 50,8 с; worker pc -run Tsc|Tsconfig frontendrules — 15 PASS, SKIP 0
