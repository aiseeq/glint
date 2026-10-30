# sql-interval-param-untyped: интервал-параметр ($M::interval) и SET в UPDATE не типизирует WHERE

Статус: открыт

## Вход
- Запрос: мастер потребителя А 30.10 ~04:35 CET, вторая перепроверка; запрос падал на каждом вызове, починено у потребителя.
- Пропуск: `col < $5 - $4::interval` — правило видит только `INTERVAL '…'` и `'…'::interval`.
- `SET closed_at = $5` раньше в том же UPDATE не выводит тип $5 для WHERE: PREPARE падает «timestamptz < interval» (замер потребителя). Postgres разбирает WHERE (и FROM) UPDATE раньше SET (transformUpdateStmt), так что «первое появление по тексту» неверно для UPDATE.

## Что сделать
- Операнд-интервал: также `$M::interval`, `CAST($M AS interval)`, `CAST('…' AS interval)`.
- Порядок разбора: в UPDATE — FROM, WHERE, затем SET, затем RETURNING; первое использование — по этому порядку.

## Приёмка
- scratchpad accept-interval-operand.sh — код 0; положительный `col < $5 - $4::interval` (и с SET col = $5 раньше), отрицательный `$5::timestamptz - $4::interval`; graft consumers — каждая находка разобрана.

## Журнал
- 2026-10-30 06:04 открыт — glint-master
