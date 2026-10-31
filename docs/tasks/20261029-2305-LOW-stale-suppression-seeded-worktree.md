# первый прогон свежего worktree на засеянном кэше даёт ложные stale-suppression

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
- TestStaleSuppressionSeesExceptionsThroughASeededCache зелёный; первый прогон свежего worktree на засеянном кэше — 0 ложных stale-suppression.

## Журнал
- 2026-10-29 23:05 открыт — glint-master
- 2026-10-29 23:05 note — glint-master: Потребитель Б (worktree с незакоммиченной правкой, -116): 8 stale-suppression на исключения files: в .glint.yaml; второй прогон и --no-cache чистые. Репро у мастера 29.10 23:10: graft worktree add stale-probe, правка одного Go-файла, glint check . → 6 Medium stale-suppression; повтор в том же дереве чистый; второй свежий worktree stale-probe2 с -o json — 0 (не воспроизвелось). Подозрение — засев из кэша основного дерева (cmd/glint/cache.go openResultCache, seed) и TakeSuppressionHits, который на reuse из кэша не вызывается. Мера: красный тест засева в cmd/glint/cache_test.go.
- 2026-10-30 00:07 note — glint-master: причина: ключ исключения в записи подавления — абсолютный путь .glint.yaml:строка; засеянные из основного дерева записи file-local правил несли путь основного дерева. Фикс: Config.ExceptionKey — путь относительно папки конфига, если файл внутри неё (родитель вне — абсолютный). Тест TestStaleSuppressionSeesExceptionsThroughASeededCache (mock-identifier, file-local) красный → зелёный; живое репро stale-probe4: 6 → 0. graft all 0.
- 2026-10-30 00:20 note — glint-master: коммит 040300d, установлен v1.83.7-129-g0cd35a2
- 2026-10-30 00:20 на проверке — glint-master — проверка: свежий worktree у потребителя без ложных stale-suppression на первом прогоне
- 2026-10-31 10:50 note — opus-check: Проверка 31.10: работа сделана, tk done отказал — пустая «Приёмка» (критерий только в журнале 00:20). Доказательства: 040300d в main; go test ./cmd/glint -run TestStaleSuppression -count=1 ok (вкл. TestStaleSuppressionSeesExceptionsThroughASeededCache); живая проба на glint: свежий git worktree с правкой pkg/rules/deadcode/stub_method.go (файл из files:-исключения), первый прогон засеян из кэша main (runs.jsonl cached_files 1325/1346) — stale-suppression 0. Мастеру: вписать «Приёмку» и закрыть.
- 2026-10-31 10:51 готово — opus-check (session glint-master): TestStaleSuppressionSeesExceptionsThroughASeededCache зелёный; живая проба: свежий worktree, правка файла из исключения files:, первый прогон взял кэш основного дерева (1325/1346 файлов) — 0 ложных stale-suppression; main 354ae10 (040300d)
