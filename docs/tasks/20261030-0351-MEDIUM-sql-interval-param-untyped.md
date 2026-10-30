# Параметр SQL, тип которого Postgres выводит из арифметики с INTERVAL ($N - INTERVAL) — interval, падение на выполнении

Статус: в работе
Исполнитель: glint-master

## Вход
- Запрос: мастер потребителя А 30.10 ~03:55 CET (ревью), по glint-gap.
- Класс: `$N [+-] INTERVAL '…'` без `::тип` у `$N` — Postgres выводит неизвестный параметр как тип второго операнда (interval); `col < $2 - INTERVAL '30 days'` падает «operator does not exist: timestamp with time zone < interval». Компиляция и vet не видят.
- Как появляется: clock-bypass с clock_package велит заменить NOW() параметром; механическая замена `NOW() - INTERVAL` → `$2 - INTERVAL`. У потребителя А исправлено `$2::timestamptz`.
- Отрицательные: `$N::timestamptz - INTERVAL`; `col - INTERVAL`; `$N` раньше в том же запросе уже типизирован (сравнение или арифметика с колонкой, `$N::type`) — тип берётся из первого появления (проверено PREPARE на PG по словам мастера потребителя А).

## Что сделать
- Новое правило в dbrules + подсказка clock-bypass (SQL-находка): `$N::timestamptz`, если параметр встретится с INTERVAL.

## Приёмка
- scratchpad accept-sql-interval-param.sh — код 0: тесты правила, CLI на фикстуре, self-check, `graft consumers -- -r sql-interval-param-untyped` — каждая находка разобрана.

## Журнал
- 2026-10-30 03:51 открыт — glint-master
- 2026-10-30 03:51 в работе — glint-master
- 2026-10-30 03:52 note — glint-master: 03:52 CET боец 1030-0352-sql-interval-param (luna, glint-правило, escalate terra), бриф brief-sql-interval-param.md, приёмка accept-sql-interval-param.sh, фикстура interval-fixture
