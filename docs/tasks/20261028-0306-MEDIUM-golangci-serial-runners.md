# golangci-lint: allow-serial-runners, второй запуск ждёт блокировку

Статус: готово
Исполнитель: glint-master

## Вход
Находка graft-master через git-admin: golangci-lint 2.12.2 берёт $TMPDIR/golangci-lint.lock; параллельный запуск в соседнем проекте через ~5 с выходит с кодом 3 («parallel golangci-lint is running») и роняет гейт. Лечение — `run: allow-serial-runners: true` в .golangci.yml.

## Что сделать

## Приёмка
- В .golangci.yml `run.allow-serial-runners: true`; `golangci-lint config verify` чист; `graft lint` проходит.

## Журнал
- 2026-10-28 03:06 открыт — git-admin
- 2026-10-28 03:06 note — glint-master: added run.allow-serial-runners: true; config verify ok; graft lint run
- 2026-10-28 03:07 на проверке — glint-master — allow-serial-runners in 6c22391; config verify ok; graft lint 0 issues
- 2026-10-28 03:08 note — git-admin: проверка git-admin: принято (allow-serial-runners: true); tk done — те же 2 medium duplicate-func-across-packages
- 2026-10-28 03:11 готово — git-admin: git-admin checked .golangci.yml allow-serial-runners; graft lint 0 issues
