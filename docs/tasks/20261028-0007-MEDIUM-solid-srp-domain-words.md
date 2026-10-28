# solid-srp: слова предметной области в именах методов считаются областями ответственности

Статус: в работе
Исполнитель: glint-master

## Постановка
Сообщение агента потребителя (28.10): ложная находка solid-srp на сервисе классификации со 114 методами — «4 business responsibility areas (max 3)», области database, export, http, transaction. transaction пришла от существительного Transaction (сущность предметной области, блокчейн-транзакция; Commit/Rollback/Begin нет ни в одном методе), http — от одного Endpoint (сторона моста). У потребителя подавление с разбором, снимут после фикса.

## Что сделать
- TDD-репро на синтетике: сервис с методами LabelTransaction, labelSwapTransaction, swapEndpointMatchesWallet + database и export → 0 находок.
- Фикс в `pkg/rules/architecture/solid_srp.go`: область, найденная только по существительным (transaction: Transaction; http: Endpoint, Request, Response), не считается без глагола своей области (Commit/Rollback/Begin; Handle/Serve/Route).
- Позитив остаётся: Begin/Commit + Transaction → transaction; HandleRequest → http.

## Чем проверить
- `graft test`, `graft self-check`.
- `graft consumers -r solid-srp`: каждая исчезнувшая находка разобрана (ложная/потерянная верная), новых нет.
- Ответ агенту потребителя после `graft install`.

## Журнал
- 2026-10-28 00:07 открыт — glint-master
- 2026-10-28 00:12 TDD: тест TestSolidSRPRule_DomainNounsAloneAreNoArea красный без фикса (4 области), зелёный с areaNouns; прогон по потребителям
- 2026-10-28 00:14 потребители: +0 −1 (у самого glint: помощник анализатора, область http только из-за слова Request — была ложной); у агента потребителя находка стоит под подавлением, разница не видна
- 2026-10-28 00:32 влито в main; агенту потребителя сообщено; ждёт graft install в конце раунда, затем — ответ о снятии подавления и done
