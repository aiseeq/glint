# error-cause-dropped и error-detail-in-5xx-response противоречат друг другу на 5xx

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
- Тест `TestErrorCauseDropped5xxLogged` → 0; 5xx без журнала → 1.
- `consumers.sh` по `error-cause-dropped` против установленного: ушедшие находки — только этого вида.

## Что
На одном `http.Error(w, …, 500)` выполнить оба правила нельзя (наблюдение агента сессии снов на своём сервере):

- текст с `err.Error()` → `error-detail-in-5xx-response` (совет: залогировать и отдать фиксированный текст);
- залогировать `err` и отдать фиксированный текст → `error-cause-dropped`.

Решение: `error-cause-dropped` не срабатывает на ответ 5xx с фиксированным текстом, если `err` в той же ветке ушёл в журнал (slog/log/logger с аргументом err). 5xx без журнала, `return errors.New(...)` и TS — как раньше.


## Журнал
- 2026-10-29 21:10 открыт — glint-master
- 2026-10-29 21:10 в работе — glint-master
- 2026-10-29 21:10 note — glint-master: Боец Luna 1029-2110-error-cause-5xx: brief-error-cause-5xx.md, accept-error-cause-5xx.sh.
- 2026-10-29 21:20 note — glint-master: Сдача 1: боец сверх брифа снял исключение самопоясняющего текста на 5xx (2 новые находки у потребителя А, тест validation перевёрнут 0→1); мастер вернул исключение и тест, текст примера заменён на не самопоясняющий. У потребителей 0 изменений. Влито eafaf46.
- 2026-10-31 10:47 готово — opus-check (session glint-master): main 615802f: eafaf46 в main; TestErrorCauseDropped5xxLogged проверяет 0 у error-cause-dropped и error-detail-in-5xx-response на варианте Б и 1 без slog; go test ./pkg/rules/patterns/errrules ./pkg/rules/security -count=1 ok; self-check 0; мера по потребителям — у мастера (журнал: 0 изменений).
