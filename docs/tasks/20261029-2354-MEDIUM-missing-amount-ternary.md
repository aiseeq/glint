# missing-amount-coerced-to-zero: тернарник и парсер с нулём

Статус: открыт

## Вход
- Проблема:
- Метод:
- Дешевле:
- Инструмент:
- Цена:
- Если не делать:

## Что сделать
- missing-amount-coerced-to-zero пропускает ноль метрики через тернарник (`r ? r.failedCount : 0`) и после парсера (`(num(x.sharePct) ?? 0)`, `parse(x.pct) ?? '0'`). Источник — потребитель (сообщение 29.10 23:53), формы до исправления.
- Бриф: /home/aisee/.cache/claude-tmp/claude-1000/-home-aisee-git-glint/24c34360-b66d-4f12-b9dd-7328b412e44a/scratchpad/brief-missing-amount-ternary.md

## Приёмка
- /home/aisee/.cache/claude-tmp/claude-1000/-home-aisee-git-glint/24c34360-b66d-4f12-b9dd-7328b412e44a/scratchpad/accept-missing-amount-ternary.sh — код 0; TestMetricFallbackZeroTernary и TestMetricFallbackZeroAfterParser красные до фикса.
- consumers.sh: каждая новая находка разобрана по коду.

## Журнал
- 2026-10-29 23:54 открыт — glint-master
- 2026-10-29 23:54 note — glint-master: боец 1029-2354-missing-amount-ternary (luna, --escalate terra), дерево /home/aisee/.cache/worktrees/glint/missing-amount-ternary
