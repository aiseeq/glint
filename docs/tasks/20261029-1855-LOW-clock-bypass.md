# time.Now() в пакете, где время берут из часов проекта

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
- TestClockBypass* зелёные; синтетика: time.Now() в пакете, читающем часы проекта, — находка; замер длительности и пакет часов — 0 (accept-clock-bypass.sh).

## Журнал
- 2026-10-29 18:55 открыт — glint-master
- 2026-10-29 18:58 в работе — glint-master
- 2026-10-29 18:58 note — glint-master: Запрос мастера потребителя А 29.10 (класс из независимого ревью потребителя А). Боец Luna, worktree clock-bypass, бриф scratchpad brief-clock-bypass.md, приёмка accept-clock-bypass.sh, мера — consumers.sh.
- 2026-10-29 20:00 note — glint-master: Сдача 1 принята: обязательная находка на копии потребителя есть (превью доходности по дате), выборка 12 из 125 — верные по критерию; сообщение укорочено мастером до 3 файлов. Влито в main.
- 2026-10-31 10:46 note — opus-check: Проверка пройдена, done не ставится: tk отказывает на пустой Приёмке (заполнить из accept-clock-bypass.sh и закрыть). Доказательства: main 615802f (72c1bb1 в main); TestClockBypass, TestClockBypassNegatives зелёные; синтетика: пакет с 2 вызовами clock.Now() — находка на time.Now().Add(-24h), замер start/time.Since и пакет часов — 0; graft all (с self-check) — код 0; расширения — в тикетах clock-bypass-module-clock, -composed-sql, -main-packages.
- 2026-10-31 10:47 готово — opus-check (session glint-master): TestClockBypass, TestClockBypassNegatives зелёные; синтетика: находка на time.Now() в пакете с clock.Now(), замер и пакет часов — 0; graft all 0; main 615802f (72c1bb1)
