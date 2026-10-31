# Паника подготовки индекса правила не изолирована

Статус: открыт

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
