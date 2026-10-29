# первый прогон свежего worktree на засеянном кэше даёт ложные stale-suppression

Статус: открыт

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
- 2026-10-29 23:05 открыт — glint-master
- 2026-10-29 23:05 note — glint-master: Потребитель Б (worktree с незакоммиченной правкой, -116): 8 stale-suppression на исключения files: в .glint.yaml; второй прогон и --no-cache чистые. Репро у мастера 29.10 23:10: graft worktree add stale-probe, правка одного Go-файла, glint check . → 6 Medium stale-suppression; повтор в том же дереве чистый; второй свежий worktree stale-probe2 с -o json — 0 (не воспроизвелось). Подозрение — засев из кэша основного дерева (cmd/glint/cache.go openResultCache, seed) и TakeSuppressionHits, который на reuse из кэша не вызывается. Мера: красный тест засева в cmd/glint/cache_test.go.
