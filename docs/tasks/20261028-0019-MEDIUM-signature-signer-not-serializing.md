# signature-over-different-bytes-than-sent: подписчик, который не сериализует JSON, а собирает канонический текст

Статус: готово
Исполнитель: glint-master

## Постановка
Агент потребителя (28.10): ложная HIGH-находка на клиенте провайдера: `sign, err := Sign(full, key)`, затем `json.Marshal(map{"param": full, "sign": sign})`. Подписчик JSON не сериализует: собирает канонический текст key=value по отсортированным ключам и берёт SHA-256; сервер провайдера восстанавливает тот же текст из разобранного JSON. У потребителя подавление с разбором.

## Что сделать
- TDD: `TestSignatureOverDifferentBytesThanSentCanonicalTextSigner` (pkg/rules/patterns/signed_request_rules_test.go) — 0 находок.
- Фикс в pkg/rules/patterns/signed_request_rules.go: когда тело подписчика загружено, находка только если он сам или вызываемые им функции проекта (до нескольких переходов) сериализуют значение (json/xml Marshal, Encoder). Тело не видно (библиотека, интерфейс) — как раньше.

## Чем проверить
- `graft test`, `graft self-check`; прежний позитив `TestSignatureOverDifferentBytesThanSent` зелёный.
- `graft consumers -r signature-over-different-bytes-than-sent`, разбор каждой разницы.

## Журнал
- 2026-10-28 00:19 открыт — агент потребителя
- 2026-10-28 00:35 красный тест на синтетике: находка client.go:16 при подписчике без сериализации
- 2026-10-28 00:23 фикс signerMayMarshal: тесты зелёные; прогон по потребителям
- 2026-10-28 00:28 потребители 0 расхождений (место под подавлением); копия дерева потребителя без маркера: установленный glint 1 находка, новый 0
- 2026-10-28 00:32 влито в main; агенту потребителя сообщено; ждёт graft install в конце раунда, затем — ответ о снятии подавления и done
- 2026-10-28 02:55 готово — consumer-B-agent: consumer B agent: nolint removed (73d9b22), installed glint No issues, gate passed; master rerun glint check ./... No issues (v1.83.7-47-g8943942)
