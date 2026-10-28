# Пропуски правил, найденные потребителями при починке находок раунда истории

Статус: в работе
Исполнитель: glint-master

## Вход
Пропуски правил, о которых сообщили агенты двух потребителей после починки находок раунда истории (28.10). Конкретные места — в их сообщениях glint-master (транскрипт сессии 28.10 01:4x); в тикет только синтетика.

## Что сделать
- upstream-failure-answered-as-bad-request: не ловит middleware проверки токена, который отвечает 401 на любую ошибку валидатора (валидатор ходит в хранилище), и ручку обновления токенов с той же схемой (сбой проверки активности сессии или чтения пользователя → 401).
- Тот же класс внутри сервиса, не на границе HTTP: функция отвечает «пользователь не найден» на любую ошибку чтения пользователя, в том числе сбой базы.
- unused-field: поймано одно поле запроса, которое заполняется пустой строкой и не читается, а соседнее с той же судьбой не поймано.
- Экспортированный метод хранилища без вызовов во всём модуле (ни в коде, ни в тестах) не пойман.
- Каждый пункт: синтетическое TDD-репро → правка → прогон по потребителям до установки.

## Приёмка
- Красный тест на каждый пункт до правки, зелёный после; `graft test`, `graft self-check`; `bin/consumers -new bin/glint -r <правило>` — разбор каждой новой находки.

## Журнал
- 2026-10-28 01:52 открыт — glint-master
- 2026-10-28 01:57 в работе — glint-master
- 2026-10-28 01:57 note — glint-master: бойцы Luna g1–g4 запущены; задачи и записи вне репо: ~/.local/share/glint-history/gaps-20261028/
- 2026-10-28 02:05 note — glint-master: g3 возвращён: request-поля без эвристики упоминаний дают ложную на исходящем запросе, сериализуемом через body any; верные — фильтр списка и поля, читаемые только %+v тестов
- 2026-10-28 02:08 note — glint-master: g1 возвращён: 9 ложных у потребителей (классификация в switch не засчитана, 5xx через свои функции не распознан)
- 2026-10-28 02:10 note — glint-master: g4 возвращён: 507 новых у потребителей (методы stdlib-интерфейсов, «только тесты»); сужение до метода без ссылок и вне любых интерфейсов
- 2026-10-28 02:22 note — glint-master: g1 reviewed: master narrowed err-helper heuristic (400 helper with err stays reportable) + test; consumers 1 diff = real (catch-all 400 after not-found split, storage failure answered 400); merging, then the consumer agent
- 2026-10-28 02:27 note — glint-master: g4 r2 cmp: consumer-C 7, consumer-B 7, consumer-A 155; consumer-A sample true; consumer-C/consumer-B mostly FP — methods called from templates on nested values; sent round 3 (template selector names)
- 2026-10-28 02:29 note — glint-master: g2 r1 cmp: 6 new, all FP (non-error results traced, code-field classification, err passed to fallback, earlier error returned); sent round 2
- 2026-10-28 02:31 note — glint-master: g3 r3 cmp: consumer-E MoneyRequest.Part/Rank only (true, expected); test helper renamed (leak); merging
- 2026-10-28 02:33 note — glint-master: g5 candidate: decimal.NewFromFloat on sheet floats (consumer-C collect). Noise only for formula results; no sheets/v4 type to anchor on. Asked consumer-C-master for data evidence before a rule. g1 dbb6c73 and g3 0e0898f merged; g2 round 2, g4 round 3 running
- 2026-10-28 02:37 note — glint-master: g4 r3 cmp: consumer-B 5 (all true, grep), consumer-A 155 (sample 11 true); test type renamed (leak); merging; findings to both agents before install
- 2026-10-28 02:39 note — glint-master: g5 opened: consumer-C data evidence (259 noisy values, formula cells via NewFromFloat); manifest introduced a808d32 collector.go:349, totals.go:497 — red on main (misses 2/2); launching Luna
- 2026-10-28 02:41 note — glint-master: g2 r2 cmp: 0 diffs; historical defect hit; merging
- 2026-10-28 02:55 note — glint-master: installed v1.83.7-47-g8943942 with g1-g4; waiting: g5 worker, consumer-A 155 removals
- 2026-10-28 02:57 note — glint-master: g5 cmp: consumer-C 5 new, exactly the sites with noisy data (constant and rounded sites silent); sent to its agent; merging + install
- 2026-10-28 03:02 note — glint-master: consumer-C FP after its fix: rounding moved to a shared helper of another package; rule now counts a package calling a 15-digit rounding function as rounding; verify t22 0/1, g5 0/2; consumers: only that FP gone; consumer-A 155 (+22) removed b62f8df12, 0 FP
