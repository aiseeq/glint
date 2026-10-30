# zero-placeholders-passed-for-persisted-fields: read-only repository helper reported as a write

Статус: в работе
Исполнитель: glint-master

## Вход
- Мастер потребителя А, 30.10 ~14:50 CET: ложное срабатывание `zero-placeholders-passed-for-persisted-fields` на приватном хелпере репозитория, который только читает (SELECT SUM). Сигнатура `(window string, args []any)`: один вызов передаёт вычисленное окно периода, другой — `"", nil` («за всё время»). Строк не пишет, сообщение «the row written here lacks them» ложно.
- Потребитель обошёл это variadic-границами, живого примера в дереве нет.
- Причина: `persistenceMethod` (`pkg/rules/patterns/gorules/parallel_path_rules.go`) считает записью любой метод receiver'а-хранилища (`IsDataAccessReceiver`), не глядя в тело.

## Что сделать
- Метод, узнанный только по receiver'у, — не запись, если его тело загружено, читает (вызов по `patternkit.ReadMethod`) и не пишет: нет вызова с write-глаголом и SQL с INSERT/UPDATE/DELETE/MERGE/UPSERT.
- Метод с write-глаголом в имени и метод без загруженного тела — как раньше.

## Приёмка
- `TestZeroPlaceholdersPassedForPersistedFieldsSkipsReads`: хелпер суммы — без находки, тот же вид с UPDATE — находка.
- `graft all` 0, `graft consumers -- -r zero-placeholders-passed-for-persisted-fields`: только пропавшие находки, каждая разобрана.

## Журнал
- 2026-10-30 14:58 открыт — glint-master
- 2026-10-30 14:58 в работе — glint-master
- 2026-10-30 15:08 note — glint-master: фикс: persistenceMethod проверяет тело метода хранилища (onlyReads); тест зелёный, graft all 0, graft consumers 0 различий на 21 проекте
