# Паника подготовки индекса правила не изолирована

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
- Паника правила в UseProjectFiles, RestoreProjectFiles и CacheProjectFiles выходила из analyzeProjectContained мимо обработчика паник (ревью релиза f9b8d6c..19cbf16, гипотеза 2).
- Ждём: паника — именованная ошибка правила, его файловый проход не идёт, находки остальных правил остаются; запись проекта в кэш не идёт.

## Приёмка
- TestAnalyzeKeepsTheOtherFindingsWhenIndexingPanics и TestProjectFilesCachePanicIsNotCached: до фикса паника роняет тест, после — зелёные.

## Журнал
- 2026-10-29 23:52 открыт — glint-master
- 2026-10-29 23:53 note — glint-master: фикс: indexProjectFiles и cachedProjectFilesState под recover; правило с паникой индекса выпадает из файлового прохода; паника кэша индекса — запись проекта не идёт. Оба теста зелёные, graft all 0.
- 2026-11-01 02:39 note — glint-master: Сон 01.11: независимая проверка — боец Terra 1101-0239-glint, бриф /home/aisee/.cache/worktrees/glint-measure/security/verify-index-panic-brief.md, вердикт → verdict-index-panic.md
- 2026-11-01 02:40 note — glint-master: проверка Terra 1101-0239-glint: ВЕРДИКТ вернуть — (1) паника CacheProjectFiles: правило остаётся в fileRules и идёт файловым проходом; (2) при непустом excludedInstructions readers собираются из enabledRules без фильтра по panics. Возврат в работу, фикс — glint-master
- 2026-11-01 02:42 note — glint-master: фикс по возврату: паника CacheProjectFiles убирает правило из файлового прохода; readers исключённых инструкций без правил с паникой индекса (rulePanics.lostIndex). Тесты TestIndexPanicSkipsTheExcludedInstructionFiles и дополненный TestProjectFilesCachePanicIsNotCached: красные до, зелёные после; self-check cmd/glint 0
- 2026-11-01 02:57 готово — terra-1101-0239-glint (session glint-master): verdict-index-panic.md: ВЕРДИКТ готово на 80edb8e; целевые тесты зелёные, без non-test части 80edb8e оба падают; go test ./cmd/glint/... зелёный
