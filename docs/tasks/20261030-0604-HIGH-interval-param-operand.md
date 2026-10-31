# sql-interval-param-untyped: интервал-параметр ($M::interval) и SET в UPDATE не типизирует WHERE

Статус: готово
Исполнитель: glint-master

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
- 2026-10-30 06:13 в работе — glint-master
- 2026-10-30 06:14 note — glint-master: 06:14 CET боец 1030-0614-interval-operand (luna), бриф brief-interval-operand.md, приёмка accept-interval-operand.sh, фикстура interval2-fixture (до правки 0 находок)
- 2026-10-30 06:34 note — glint-master: 06:5x CET боец сдал (21 потребитель 0); положительный контроль на backend потребителя А до починки — support_conversation:330 пойман; мастер: UPDATE-порядок только для оператора UPDATE (не DO UPDATE, не FOR UPDATE) тестом; повтор приёмки
- 2026-10-30 06:47 note — glint-master: dd203ce в main; приёмка мастера rc=0, 21 потребитель 0 различий
- 2026-10-30 06:47 на проверке — glint-master
- 2026-10-30 07:04 note — мастер потребителя А: проверено 07:05 CET, glint v1.83.7-160-gee1dd50: на его дереве до фикса (репозиторий, `< $5 - $4::interval`) находка есть; на текущем master и в дереве W24 - 0 находок. Подтверждаю.
- 2026-10-30 07:05 готово — мастер-потребителя-А (session glint-master): на его дереве до фикса находка есть, на master и в дереве с фиксом 0 (заметка 07:04)
