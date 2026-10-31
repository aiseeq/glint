# Тесты не читают ~/.config/models/approved

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
- Тесты задают model-not-approved свой approved_file (testdata) через конфиг, как model_not_approved_test.go; поведение правила не меняется.
- Убрать `~/.config/models/approved` из cache.files в .graft.yaml.

## Приёмка
- `HOME`-независимость: тесты зелёные при отсутствии ~/.config/models/approved (например, прогон на PC через graft после включения перелива или go test с approved_file недоступным); graft all зелёный.

## Что
- Тесты, которые гоняют все правила с настройками по умолчанию (cmd/glint TestAnalyzeFilesIsDeterministicAndRaceFree, TestProjectRulesAreDeterministicAndRaceFree, TestResultCacheRoundTripsEveryRule, TestMissingShellcheckFailsTheRun, TestAnalyzeProjectWithEveryPackageSkipped, TestPythonSourcesReachOnlyThePythonFileRule, TestSharedLoaderMatchesSeparateLoadsPerRoot), читают список моделей пользователя ~/.config/models/approved через model-not-approved (shellrules). Без файла правило по замыслу роняет прогон — тесты падают на машине без него (PC, 28.10), а их итог зависит от содержимого списка на машине.
- Из-за этого .graft.yaml держит `cache.files: ['~/.config/models/approved']`, и graft оставляет тесты glint на ноуте (graft-master 28.10: задача с cache.files не уходит на PC).


## Журнал
- 2026-10-28 14:32 открыт — glint-master
- 2026-10-28 14:47 note — glint-master: TestMain в cmd/glint настраивает model-not-approved на свой список; go test ./... зелёный с пустым HOME (32 пакета); строка ~/.config/models/approved убрана из cache.files
- 2026-10-28 14:53 на проверке — glint-master — коммит 5a4d290; проверка: graft test на PC (без ~/.config/models/approved) зелёный, задача test без cache.files
- 2026-10-28 15:37 готово — graft-master: graft-master: graft v2.49.0, glint 5a4d290, перелив через копию конфига: test-short и test — heavy, on pc, код 0, 25 с (без ~/.config/models/approved на PC)
