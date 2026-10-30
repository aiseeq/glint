# tsc: попадание в кэш без запусков tsc

Статус: на проверке
Исполнитель: glint-master

## Вход
- Проблема: задание Сна, обход tests 30.10 02:40 (dream-master): гейт потребитель Б 70–89 с при пределе 60, glint в нём 25 с. Замер мастера 30.10 ~02:50: потребитель Б, все 1089 файлов из кэша — analyze 11,5 с, из них tsc 10,8 с. На попадании в кэш правило всё равно запускает tsc три раза на программу (`--version`, `--showConfig`, `--listFilesOnly`) — runTscProgram, pkg/rules/patterns/frontendrules/tsc.go:473.
- Метод: отпечаток по stat прошлого прогона (файлы программы, их каталоги, цепочка tsconfig, сам tsc) → без запусков, если ничего не сдвинулось; иначе — как сейчас.
- Если не делать: каждый гейт TS-потребителя платит ~10 с за неизменное дерево.

## Что сделать
- Бриф: /home/aisee/.cache/claude-tmp/claude-1000/-home-aisee-git-glint/24c34360-b66d-4f12-b9dd-7328b412e44a/scratchpad/brief-tsc-stat-cache.md

## Приёмка
- accept-tsc-stat-cache.sh — код 0; потребитель Б: второй прогон подряд — tsc TOTAL ≤ 1 с.

## Журнал
- 2026-10-30 02:44 открыт — glint-master
- 2026-10-30 02:45 в работе — glint-master
- 2026-10-30 03:16 note — glint-master: сдача 1: tsc TOTAL 10,8 с → 27 мс; ревью 1 — две цепочки extends (массив роняет правило), гонка stat/ключа; раунд 2 — review-tsc-stat-1.md
- 2026-10-30 03:38 note — glint-master: 03:38 CET раунд 2 (общая tsconfigChain, stat до чтения, 21 потребитель 0 различий, tsc TOTAL 30 мс) принят по сути; раунд 3 бойцу 1030-0245: окно правки во время --listFilesOnly (racy mtime), каталоги node_modules вне каталога tsconfig. Бриф scratchpad review-tsc-stat-2.md
- 2026-10-30 04:07 note — glint-master: 04:07 CET раунд 3 принят (racy mtime, node_modules вне каталога tsconfig, typeRoots): abcb83d в main, graft all rc=0; tsc TOTAL второго прогона 10,8 с → 23–28 мс, 21 потребитель 0 различий
- 2026-10-30 04:07 на проверке — glint-master
