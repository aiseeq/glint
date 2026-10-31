# clock-bypass: настройка clock_package — правило на весь модуль, плюс NOW() в SQL-литералах

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
- TestClockBypass* зелёные; синтетика брифа: с clock_package — находки на весь модуль и NOW() в SQL-литерале, без настройки — 0.

## Журнал
- 2026-10-30 00:40 открыт — glint-master
- 2026-10-30 00:40 в работе — glint-master
- 2026-10-30 00:40 note — glint-master: Запрос мастера потребителя А 30.10 00:40 (перепроверка двойного счёта; цель пользователя — один способ посчитать). Боец Luna, worktree /home/aisee/.cache/worktrees/glint/clock-module, бриф /home/aisee/.cache/claude-tmp/claude-1000/-home-aisee-git-glint/24c34360-b66d-4f12-b9dd-7328b412e44a/scratchpad/brief-clock-module.md, приёмка /home/aisee/.cache/claude-tmp/claude-1000/-home-aisee-git-glint/24c34360-b66d-4f12-b9dd-7328b412e44a/scratchpad/accept-clock-module.sh, мера — consumers.sh.
- 2026-10-30 01:28 note — glint-master: влито 5c8a7ef, установлено v1.83.7-137-gbe1fd9c; мастера потребителей сообщены
- 2026-10-30 01:28 на проверке — glint-master — проверка: подтверждение мастера потребителя по находкам или включённой настройке
- 2026-10-31 10:48 note — opus-check: Проверка opus-check 31.10 на main 354ae10 — работа выполнена, tk done отказал бы: пустой раздел «Приёмка» (нужно перенести меру из брифа и закрыть). Доказательства: 5c8a7ef в main; go test ./pkg/rules/patterns/timerules -run TestClockBypass -count=1 — 11 PASS (ModuleClockPackage/SQL/Unset); синтетика из брифа с clock_package — 3 находки (time.Now в report, NOW()/now() в SQL), time.Since(start) и не-SQL литерал — нет, без настройки — 0; потребитель А включил clock_package и перевёл код (166 чтений, 67 запросов), clock-bypass на нём — 0 находок; graft all EXIT 0
- 2026-10-31 10:48 готово — opus-check (session glint-master): 11 тестов TestClockBypass* зелёные; синтетика брифа: clock_package — 3 находки, без настройки — 0; потребитель А включил настройку, 0 находок; main 354ae10 (5c8a7ef)
