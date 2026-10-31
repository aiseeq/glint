# value-set-drift: SQL IN-список литералов повторяет Go-группу (case классификатора, ключи map групп)

Статус: готово
Исполнитель: glint-master

## Вход
- Проблема:
- Метод:
- Дешевле:
- Инструмент:
- Цена:
- Если не делать:

## Что сделать

## Приёмка
(перенесено проверяющим из приёмки мастера accept-sql-in-list-group-3.sh; 29.10)
- Тесты `TestValueSetDriftSQL{ListCopiesGoClassifierCase,ListCopiesGoListVar,ListNotGroupCopy,ListConcatenated,ConstantPredicateReused}` есть и зелёные; self-check glint — 0.
- Копия потребителя А `-r value-set-drift` — находка в репозитории подарочных кодов (строка 196); у потребителя Б нет находки на константе-предикате очереди вебхуков.

## Журнал
- 2026-10-29 18:55 открыт — glint-master
- 2026-10-29 18:58 в работе — glint-master
- 2026-10-29 18:58 note — glint-master: Запрос мастера потребителя А 29.10 (класс из независимого ревью потребителя А). Боец Luna, worktree sql-in-list-group, бриф scratchpad brief-sql-in-list-group.md, приёмка accept-sql-in-list-group.sh, мера — consumers.sh.
- 2026-10-29 19:29 note — glint-master: Сдача 1: синтетика ловится; реальный случай потребителя А (481a8e588, запрос в переменной со склейкой константы) — нет. Раунд 1: review-sql-in-list-group-1.md.
- 2026-10-29 20:08 note — glint-master: Сдача 2: обязательная находка есть; регресс — константа-предикат, подклеенная в 3 запроса, стала «written by hand» у потребителя Б (боец не указал). Раунд 2: review-sql-in-list-group-2.md, accept-sql-in-list-group-3.sh.
- 2026-10-29 20:53 note — glint-master: Раунд 2 принят: ложная на константе-предикате ушла, новая находка одна — обязательная репозиторий подарочных кодов. Влито в main.
- 2026-10-31 10:47 готово — opus-check (session glint-master): main 615802f: e070d4f в main; 5 тестов (ClassifierCase, ListVar, NotGroupCopy, Concatenated, ConstantPredicateReused) есть, go test ./pkg/valueset ./pkg/rules/patterns/dbrules -count=1 ok; копия потребителя А -r value-set-drift: gift_code_repository.go:196 есть; потребитель Б -r value-set-drift: 0 находок, webhook_repo.go с константой-предикатом не находка; self-check 0.
