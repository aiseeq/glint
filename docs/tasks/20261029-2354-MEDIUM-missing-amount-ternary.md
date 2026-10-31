# missing-amount-coerced-to-zero: тернарник и парсер с нулём

Статус: готово
Исполнитель: luna

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
- 2026-10-30 00:19 note — glint-master: влито 974fa94, установлено v1.83.7-129-g0cd35a2; consumers.sh 040300d против установленного: +1 у потребителя-заказчика (vault-report page.tsx:462 тернарник присутствия — та же форма, что ?? 0), отдано его мастеру
- 2026-10-30 00:19 готово — glint-master: мастер: TestMetricFallbackZeroTernary/AfterParser зелёные, graft all 0 на d703ec6; consumers diff разобран (1 верная по контракту правила)
