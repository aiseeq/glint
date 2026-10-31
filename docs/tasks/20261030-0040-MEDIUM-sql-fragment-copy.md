# sql-literal-copies-constant: префикс алиаса и %d-константа, var из склейки, выражение суммы, порог литералом

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
- TestSQLLiteralCopies* зелёные; синтетика брифа — 5 ожидаемых находок, отрицательные — 0; у потребителя А находки разобраны.

## Журнал
- 2026-10-30 00:40 открыт — glint-master
- 2026-10-30 00:40 в работе — glint-master
- 2026-10-30 00:40 note — glint-master: Запрос мастера потребителя А 30.10 00:40 (перепроверка двойного счёта; цель пользователя — один способ посчитать). Боец Luna, worktree /home/aisee/.cache/worktrees/glint/sql-fragment-copy, бриф /home/aisee/.cache/claude-tmp/claude-1000/-home-aisee-git-glint/24c34360-b66d-4f12-b9dd-7328b412e44a/scratchpad/brief-sql-fragment-copy.md, приёмка /home/aisee/.cache/claude-tmp/claude-1000/-home-aisee-git-glint/24c34360-b66d-4f12-b9dd-7328b412e44a/scratchpad/accept-sql-fragment-copy.sh, мера — consumers.sh.
- 2026-10-30 01:34 note — glint-master: влито da9c5b7, установлено; проба потребителя: 8 находок, все ожидаемые (G2, G2b, G2c, G7, G9 новые); у потребителя А +1 верная (выражение суммы вывода)
- 2026-10-30 01:34 на проверке — glint-master — проверка: подтверждение мастера потребителя
- 2026-10-31 10:48 note — opus-check: Проверка opus-check 31.10 на main 354ae10 — работа выполнена, tk done отказал: пустой раздел «Приёмка» (нужно перенести меру из брифа и закрыть). Доказательства: da9c5b7 в main; go test ./pkg/rules/patterns/dbrules -run TestSQLLiteralCopies -count=1 — 21 PASS (AliasPrefixClause, VarConcatenation, AmountExpression(+Switch), ThresholdLiteral); синтетика из брифа — 5 находок, негативы (balance<50, attempts<100, LIMIT 100, network_id>0, склейка вызовом) без находок; потребитель А сейчас — 0 находок sql-literal-copies-constant; graft all EXIT 0
- 2026-10-31 10:48 готово — opus-check (session glint-master): 21 тест TestSQLLiteralCopies* зелёные, синтетика брифа — 5 ожидаемых находок, отрицательные молчат; потребитель А — 0 находок; graft all 0; main 354ae10 (da9c5b7)
