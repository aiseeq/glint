# Новое правило: граница периода руками вне общего модуля периода (period_modules)

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
- Тесты TestTSPeriodBoundaryByHand* зелёные; синтетика с period_modules даёт находки на границе периода руками, модуль периода и прогон без настройки — 0 (accept-ts-period-by-hand.sh).

## Журнал
- 2026-10-30 00:40 открыт — glint-master
- 2026-10-30 00:40 в работе — glint-master
- 2026-10-30 00:40 note — glint-master: Запрос мастера потребителя А 30.10 00:40 (перепроверка двойного счёта; цель пользователя — один способ посчитать). Боец Luna, worktree /home/aisee/.cache/worktrees/glint/ts-period-by-hand, бриф /home/aisee/.cache/claude-tmp/claude-1000/-home-aisee-git-glint/24c34360-b66d-4f12-b9dd-7328b412e44a/scratchpad/brief-ts-period-by-hand.md, приёмка /home/aisee/.cache/claude-tmp/claude-1000/-home-aisee-git-glint/24c34360-b66d-4f12-b9dd-7328b412e44a/scratchpad/accept-ts-period-by-hand.sh, мера — consumers.sh.
- 2026-10-30 00:45 note — glint-master: Раунд 2 (после сдачи 1): разность дат в днях руками — Math.round/floor/ceil((a - b) / 86_400_000 | 864e5 | 86400000 | 24*60*60*1000) вне period_modules; три места у потребителя А (уведомления, вывод, текст операции). п.4 запроса снят потребителем; п.7 (money0 к целому) отклонён: 3 верных из ~45 вызовов, отличие — домен значения; предложен брендированный тип у потребителя.
- 2026-10-30 01:28 note — glint-master: влито 3a682ff, установлено v1.83.7-137-gbe1fd9c; мастера потребителей сообщены
- 2026-10-30 01:28 на проверке — glint-master — проверка: подтверждение мастера потребителя по находкам или включённой настройке
- 2026-10-31 10:46 note — opus-check: Проверка пройдена, done не ставится: tk отказывает на пустой Приёмке (заполнить из accept-ts-period-by-hand.sh и закрыть). Доказательства: main 615802f (3a682ff в main); 5 тестов TestTSPeriodBoundaryByHand* зелёные; синтетика с period_modules — 3 находки (setDate, дата из частей, разность дней /86400000), модуль периода, new Date(строка), Date.now()+мс и запуск без настройки — 0; потребитель А включил period_modules (его коммит aff8aef38 30.10), glint check -r на его дереве — 0; graft all (с self-check) — код 0.
- 2026-10-31 10:47 готово — opus-check (session glint-master): 5 тестов TestTSPeriodBoundaryByHand* зелёные, синтетика с period_modules — 3 находки, модуль периода и прогон без настройки — 0; потребитель А включил period_modules (aff8aef38), 0 находок; main 615802f (3a682ff)
