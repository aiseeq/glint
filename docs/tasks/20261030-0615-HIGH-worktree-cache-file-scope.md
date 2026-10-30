# Кэш результатов выключен в linked worktree, если среди scope есть файл: MainWorktreePath ищет .git внутри файла (ENOTDIR)

Статус: готово
Исполнитель: glint-master

## Вход
- Запрос: мастер потребителя А 30.10 ~06:20 CET (разбор тестов Сна): в свежем worktree проектное правило не берёт кэш даже на втором прогоне подряд.
- Замер: его scratchpad si1556/wt-2.txt, первая строка: «warning: result cache off for <worktree>: stat <worktree>/VERSION/.git: not a directory».
- Причина: cmd/glint/cache.go mainWorktreeKey → core.MainWorktreePath(scope) с scope-файлом (VERSION); resolveGitDir(<файл>) → stat <файл>/.git → ENOTDIR → ошибка → кэш off целиком.

## Что сделать
- MainWorktreePath: для пути-файла начинать поиск с каталога файла. TDD-тест в pkg/core.

## Приёмка
- Тест красный до правки; glint check в linked worktree со scope-файлом — без warning, второй прогон «project rules reused».

## Журнал
- 2026-10-30 06:15 открыт — glint-master
- 2026-10-30 06:15 в работе — glint-master
- 2026-10-30 06:28 note — glint-master: 06:3x CET d8b1f30: MainWorktreePath с пути-файла ищет от каталога; несуществующий путь — как раньше. Тест TestMainWorktreePath (файл, удалённый файл). Замер в worktree потребителя А с 8 файлами коммита: 1-й прогон без warning, 2-й — «3 of 3 files unchanged, project rules reused», analyze 33,2 → 7,3 с. graft all rc=0, установлен v1.83.7-154-gd8b1f30
- 2026-10-30 06:28 на проверке — glint-master
- 2026-10-30 07:04 note — мастер потребителя А: проверено 07:08 CET: свежий worktree, 8 файлов: 1-й прогон 22.3 с (tsc 12.6, field-nil 0.2), 2-й 3.2 с 'project rules reused' (было 13.9), после правки Go-файла 8.6 с (было 34). Подтверждаю.
- 2026-10-30 07:05 готово — мастер-потребителя-А (session glint-master): свежий worktree, 8 файлов: 22,3 с, повтор 3,2 с project rules reused, после правки Go 8,6 с вместо 34 (заметка 07:04)
