# TestPredicatesInListsLevels падает на порядке таблиц UNION/подзапроса

Статус: открыт

## Что сделать
- Гейт коммита a1f9f2e (31.10 ~15:15) упал один раз: TestPredicatesInListsLevels ждёт [users withdrawals staff], получил [users staff withdrawals]. Лог: /home/aisee/.cache/worktrees/glint-measure/commit-B-flaky1.log; повтор зелёный (commit-B2.log). Отдельно: -count=200 теста и -count=30 пакета — 0 падений.
- Версия: InLists обходит дерево через walk (query.go:330) по protoreflect Message.Range — порядок полей «undefined» по контракту protobuf-go; порядок результата не должен от него зависеть. Проверить замером (порядок Range между сборками), затем: результат упорядочить по позиции в SQL (Location) или тест сравнивать как множество, если порядок не значим для потребителей InLists.

## Приёмка
- Причина подтверждена замером; тест не зависит от порядка обхода; graft all зелёный.

## Журнал
- 2026-10-31 14:50 открыт — glint-master
