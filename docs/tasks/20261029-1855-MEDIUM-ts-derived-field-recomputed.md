# TS ветвится по полю ответа, рядом с которым бэкенд отдаёт производное *Group; комментарий «зеркало бэкенда»

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
(перенесено проверяющим из приёмки мастера accept-ts-derived-field-2.sh; 29.10)
- Тесты `TestTSDerivedFieldRecomputed{,Negatives,Structural}`, `TestMirrorCommentCopy{,Negatives,VerbInBlock,ValueFromSource,RuntimeCopy}` есть и зелёные; self-check glint — 0.
- Копия потребителя А: `ts-derived-field-recomputed` — в ключе статуса вывода (строки 18–30); `mirror-comment-copy` — на «Зеркалит» в модели переводов (строки 92–97); нет ложной на значении из источника в репозитории аналитики.

## Журнал
- 2026-10-29 18:55 открыт — glint-master
- 2026-10-29 18:58 в работе — glint-master
- 2026-10-29 18:58 note — glint-master: Запрос мастера потребителя А 29.10 (класс из независимого ревью потребителя А). Боец Luna, worktree ts-derived-field, бриф scratchpad brief-ts-derived-field.md, приёмка accept-ts-derived-field.sh, мера — consumers.sh.
- 2026-10-29 20:32 note — glint-master: Сдача 1: derived — 0 находок везде (реальный код без аннотации типом: литерал типа/имена параметров); mirror — пропуск «Зеркалит» в блоке, ложные: значение из источника, «копия» в рантайме. Раунд 1: review-ts-derived-field-1.md, accept-ts-derived-field-2.sh.
- 2026-10-29 21:09 note — glint-master: Раунд 1 принят: derived — 1 верная (ключ статуса вывода); функция статуса вывода для показа сравнивает status с одним литералом — не ловится. mirror — 8 находок, все — самоописанные копии. Влито в main.
- 2026-10-31 10:47 готово — opus-check (session glint-master): main 615802f: 24e8030 в main; 8 тестов брифа и раунда 1 есть, go test ./pkg/rules/patterns/frontendrules -count=1 ok; копия потребителя А: ts-derived-field-recomputed withdrawal-status.ts:23 (окно 18-30), mirror-comment-copy transfer-model.ts:97 (окно 92-97), ложной на analytics/repository.go нет; self-check 0. Функция с одним литералом — по ревью раунда 1 описать, не подгонять (журнал 21:09).
