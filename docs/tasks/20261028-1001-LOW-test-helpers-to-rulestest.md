# Свести хелперы тестов правил в rulestest

Статус: открыт

## Вход
- Проблема:
- Метод:
- Дешевле:
- Инструмент:
- Цена:
- Если не делать:

## Что сделать

## Приёмка
- Число локальных хелперов с этими сигнатурами в pkg/rules/*/*_test.go — 0 или с причиной; graft all зелёный; число тестов (go test -list) то же.

## Что
- Из разбора тестов 28.10 (тикет tests-review-20261028): в тестах pkg/rules/*/ 96 локальных хелперов «прогнать правило → строки/находки», из них по одной сигнатуре: 16 × (t, files map[string]string) []string, 7 × (t, path, source string) []int, 6 × (t, source string) []int, 10 × (s string) []string.
- Свести в общие хелперы pkg/rules/rulestest (после влития patterns-split, тесты переедут по подпакетам).


## Журнал
- 2026-10-28 10:01 открыт — glint-master
- 2026-10-28 14:20 note — glint-master: 14:22 бриф и мера готовы (~/.local/share/glint-history/test-helpers/: brief.md, accept.sh, count.sh — 55 хелперов, тестов 2116), worktree test-helpers. Бойца не запускаю: graft gate в glint падает, когда test-short уходит на PC (нет ~/.config/models/approved, $GOROOT not set в /.worker-pc-stage) — сообщено graft-master.
- 2026-10-28 14:52 note — glint-master: боец: ACCEPT OK, 55→12 копий, -379 строк; закоммичено 804c614 в ветку. Ревью: в patterntest остались копии rulestest (Split*Lines x3, ViolationLines, FileRuleLines, AppRuleLines, обёртки RunRuleOn*), rulestest.RunGoProjectRule дублирует RunRuleOnFiles → раунд 2 (round2.md, accept2.sh)
- 2026-10-28 15:07 note — glint-master: раунд 2 принят, закоммичен 15d9f03 (−11 копий, patterntest 820→699 строк). Ревью: 4 копии Create*Context → раунд 3 (round3.md, accept3.sh)
