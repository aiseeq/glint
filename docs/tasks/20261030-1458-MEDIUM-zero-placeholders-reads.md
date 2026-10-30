# zero-placeholders-passed-for-persisted-fields: read-only repository helper reported as a write

Статус: на проверке
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
- 2026-10-30 15:10 на проверке — glint-master — коммит 05e6601, установлено v1.83.7-175-g05e6601; проверка — суб-агент по тикету
- 2026-10-30 15:20 note — glint-master: проверка суб-агентом: тесты зелёные, проба (хелпер суммы без находки, UPDATE — находка) принята; найдены обходы правки 05e6601 — запись через свой метод, UPDATE…RETURNING в константе или переменной пакета молчат, SELECT…FOR UPDATE — ложная. Доводка: чтение подтверждает только видимый SELECT (литерал, строковая константа, пакетная тоже), вызов своего метода — запись, FOR UPDATE вырезается; кейсы в TestZeroPlaceholdersPassedForPersistedFieldsSkipsReads, проба проверяющего — все пять обходов снова находки, E2 без находки; graft all 0, graft consumers 0 различий
- 2026-10-30 15:36 note — glint-master: перепроверка 6bca8c8: прежние обходы закрыты; новые — G3 (флаг writes затирался соседним вызовом), E10 (ORM Updates), ложные F1 (литерал DELETE), F2 (update в тексте ошибки), F5 (ведущий SQL-комментарий). Доводка: флаг копится, глагол с окончанием s, в счёт идут только тексты, начинающие SQL-оператор, кавычки вырезаются, ведущие комментарии пропускаются; F3 (свой метод только для чтения) — осознанная цена. Тест — store/mixed.go; пробы проверяющего E8–E10, G1–G4 — находки, F1, F2, F4, F5 — нет; graft all 0, graft consumers 0 различий
- 2026-10-30 15:48 note — glint-master: третий раунд da763c7 принят; новое H1 — запись через метод другого хранилища без write-глагола (r.ledger.Add) молчала. Доводка: вызов метода типа-хранилища (IsDataAccessReceiver) с именем не по ReadMethod — запись. H2 (SELECT хранимой функции, которая пишет) статически не узнать — принято. Тест — store/mixed.go (ReportRepo); пробы проверяющего — 15 находок (прежние 14 + H1); graft all 0, consumers 0 различий
