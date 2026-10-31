# запасной 0 у метрики ответа (*Count/*Total/*Usd ?? 0)

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
- TestMetricFallbackZero* зелёные; синтетика ?? 0 и || 0 на метрике ответа — находка, сравнения и .length — 0; обязательная находка на копии потребителя А (accept-metric-fallback-2.sh).

## Журнал
- 2026-10-29 18:55 открыт — glint-master
- 2026-10-29 18:58 в работе — glint-master
- 2026-10-29 18:58 note — glint-master: Запрос мастера потребителя А 29.10 (класс из независимого ревью потребителя А). Боец Luna, worktree metric-fallback, бриф scratchpad brief-metric-fallback.md, приёмка accept-metric-fallback.sh, мера — consumers.sh.
- 2026-10-29 20:04 note — glint-master: Сдача 1: 46 новых находок, обязательная (счётчик депозитов) есть; ложные — сравнение `(x ?? 0) > 0` вне if. Раунд 1: review-metric-fallback-1.md, accept-metric-fallback-2.sh.
- 2026-10-29 20:21 note — glint-master: Раунд 1 принят: сравнения вне if сняты, 46 находок у потребителей (544/890 — несравниваемые операнды). Влито в main.
- 2026-10-31 10:46 note — opus-check: Проверка пройдена, done не ставится: tk отказывает на пустой Приёмке (заполнить из accept-metric-fallback-2.sh и закрыть). Доказательства: main 615802f (bcca31e в main; сделано в missing-amount-coerced-to-zero, настройка metric_words); TestMetricFallbackZero, ...Negatives, ...ComparisonAnywhere зелёные; синтетика: previous?.depositsCount ?? 0 и stats?.totalUsers || 0 — 2 находки, (x || 0) >= 1, (x ?? 0) > 0, .length ?? 0 — 0; копия потребителя А ветка-481 — обязательная AnalyticsMetricsDashboard.tsx:245 есть; graft all — код 0.
- 2026-10-31 10:47 готово — opus-check (session glint-master): TestMetricFallbackZero* зелёные (в missing-amount-coerced-to-zero, metric_words); синтетика ?? 0 / || 0 — находки, сравнения и .length — 0; обязательная AnalyticsMetricsDashboard.tsx:245 на копии потребителя А; main 615802f (bcca31e)
