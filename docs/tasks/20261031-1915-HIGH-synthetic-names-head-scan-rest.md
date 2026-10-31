# Three more copied names in HEAD found by a leak scan of the HEAD tree

Статус: открыт

## Что сделать
- Сообщение git-admin 31.10 ~19:30 (задание synthetic-names-head через graft-master; приёмка — скан дерева HEAD): 3 имени вне списка graft-master (193), без graft:leak-ok и не из logic-names.txt — NoDuplicates (pkg/rules/duplication/duplicate_block_test.go:57), CollectLive (pkg/rules/patterns/qarules/test_external_service_test.go:188,213), PanicDoesNotEscapeGoroutine (pkg/rules/patterns/qarules/test_without_assertion_test.go:114).
- Заменить выдуманными (до замены проверить grep объявлений func/type в рабочих и частных деревьях); поведение тестов не меняется.

## Приёмка
- Скан дерева HEAD: `git commit-tree 'HEAD^{tree}' -m x` → `graft leaks <sha>` — только 7 имён из logic-names.txt (до 02.11, тикет synthetic-names-reserved-residue).
- Тесты затронутых пакетов зелёные; graft commit прошёл leak-проверку.

## Журнал
- 2026-10-31 19:15 открыт — glint-master
- 2026-10-31 19:20 note — glint-master: переименованы a677985: TestDuplicateBlockRule_DistinctBlocksPass, TestVaultSnapshot_GatherFresh (2), TestGo_GoroutinePanicStaysContained; новые имена не встречаются в рабочих и частных деревьях; тесты duplication, qarules ok. Скан дерева (commit-tree HEAD^{tree} → graft leaks): 83 находки, только 7 имён logic-names.txt. Проверка — повторный скан git-admin
