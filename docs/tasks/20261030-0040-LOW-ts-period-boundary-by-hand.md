# Новое правило: граница периода руками вне общего модуля периода (period_modules)

Статус: в работе
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

## Журнал
- 2026-10-30 00:40 открыт — glint-master
- 2026-10-30 00:40 в работе — glint-master
- 2026-10-30 00:40 note — glint-master: Запрос мастера потребителя А 30.10 00:40 (перепроверка двойного счёта; цель пользователя — один способ посчитать). Боец Luna, worktree /home/aisee/.cache/worktrees/glint/ts-period-by-hand, бриф /home/aisee/.cache/claude-tmp/claude-1000/-home-aisee-git-glint/24c34360-b66d-4f12-b9dd-7328b412e44a/scratchpad/brief-ts-period-by-hand.md, приёмка /home/aisee/.cache/claude-tmp/claude-1000/-home-aisee-git-glint/24c34360-b66d-4f12-b9dd-7328b412e44a/scratchpad/accept-ts-period-by-hand.sh, мера — consumers.sh.
- 2026-10-30 00:45 note — glint-master: Раунд 2 (после сдачи 1): разность дат в днях руками — Math.round/floor/ceil((a - b) / 86_400_000 | 864e5 | 86400000 | 24*60*60*1000) вне period_modules; три места у потребителя А (уведомления, вывод, текст операции). п.4 запроса снят потребителем; п.7 (money0 к целому) отклонён: 3 верных из ~45 вызовов, отличие — домен значения; предложен брендированный тип у потребителя.
