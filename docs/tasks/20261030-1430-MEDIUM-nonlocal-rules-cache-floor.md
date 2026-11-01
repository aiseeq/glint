# нелокальные правила идут по всем файлам на каждом прогоне: 8 с на проекте без изменений

Статус: в работе
Исполнитель: glint-master

## Вход
- Мастер потребителя Б (perf-baseline, этап 1), 30.10 ~14:20 CET: glint в гейте — 19–23 с из ~60 с.
  - Гейт зовёт `glint check . -o summary` по всему проекту, 1093 файла.
  - Журнал graft (`~/.cache/graft/stats.jsonl`): за 26–30.10 медиана 19,2 с, максимум 81,9 с. После установки v1.83.7-171 — 54,4 с (первый прогон, кэш правил проекта завязан на версию glint) и 17,9 с.
- Мой замер 30.10 14:29 CET, master потребителя Б, ни один файл не менялся («1093 of 1093 files unchanged, project rules reused»):
  - wall 7,8–8,1 с;
  - CPU-профиль (scratchpad мастера `consumer-b-warm.prof`): 20,5 с CPU, из них `analyzeFilesContained` 7,7 с и `indexProjectFiles` 3,9 с.
  - Главные по CPU: ts-derived-field-recomputed 1,9 с, `patternkit.SqlTexts` 1,6 с (общий для SQL-правил), frontend-money-arithmetic 1,3 с, model-not-approved 0,7 с, js-test-external-service 0,7 с, sql-literal-copies-constant 0,7 с, value-set-drift (`UseProjectFiles`) 0,65 с, ts-path-not-routed 0,6 с.
- Причина: `rules.FileLocal` (`pkg/rules/rule.go:355`) — правило с `ReadsOtherFiles`, `StatefulRule` или правило проекта не локально. Кэш результатов (`cmd/glint/main.go:1217`, `reuse`) таким правилам не помогает: они идут по всем файлам на каждом прогоне. Индекс проекта восстанавливает из кэша 1 правило из 43 с `UseProjectFiles` (`CachedProjectFilesRule`).

## Что сделать

## Приёмка
- Повтор `glint check . --timing` на потребителе Б без изменений: analyze из 8 с уходит к ~1–2 с (вариант 1).
- Гейт с правкой 1–3 файлов: замер до и после (варианты 2–3).
- `graft consumers` — 0 различий.

## Варианты
1. **Полное попадание.** Находки нелокальных правил хранить в записи проекта и брать их, когда запись проекта совпала. Индекс проекта на этом пути не строить.
   - Цена: малая. Осторожно с `ReadsOtherFiles`, которые читают файлы вне дерева (model-not-approved — список моделей): их входы — в ключ записи или мимо этого пути.
   - Выигрыш: прогон без изменений (повтор, деплой после гейта) 8 с → ~1–2 с. Гейту с правками — ничего.
2. **Инкрементально.** Каждое правило с индексом проекта кладёт вклад файла в индекс по хэшу файла (как `CachedProjectFilesRule`). Находка файла переиспользуется, если не изменились ни файл, ни отпечаток индекса, который правило читает.
   - Цена: большая, по правилу на 43 правила, нужен общий механизм в patternkit.
   - Выигрыш: гейт с правкой нескольких файлов на весь проект — до ~8 с.
3. **Дешёвые правила.** Профилем ускорить первые по CPU (ts-derived-field-recomputed, frontend-money-arithmetic, `SqlTexts`) — независимо от 1 и 2.


## Журнал
- 2026-10-30 14:30 открыт — glint-master
- 2026-10-30 14:35 note — glint-master: вариант 1 почти ничего не даёт: задача glint у потребителя Б с cache (graft пропускает дерево, уже прошедшее проверку), повтор и деплой после гейта glint не зовут. Значим для гейта только floor с правками — варианты 2 и 3; ждёт решения по приоритету в perf-baseline (этап 1 — замер)
- 2026-11-01 08:44 note — glint-master: 01.11 akit-master: tk done (glint check . -s low -o json) после гейта (glint check .) ждёт полный прогон; приёмка akit-тикета /home/aisee/git/akit/docs/tasks/20261101-0256-LOW-tk-done-glint-reuse.md < 5 с. Пересмотр записи 30.10 14:35: повтор без изменений — это tk done после гейта, вариант 1 теперь нужен. Сделано сразу: (а) min_severity/fail_on/output вне штампа кэша (флаги -s/-o перебивали кэш друг друга), тест TestCacheStampIgnoresReportOnlySettings; (б) test-data-ignored-by-git обходил testdata на каждый тестовый файл (sc2go: 466 файлов, 7,1 с CPU) — память по каталогу на процесс, 66 мс, тест TestTestDataIgnoredWalksEachDirectoryOnce. sc2go полное попадание: 9,1 → 6,6 с wall; остаток — indexProjectFiles 2,3 с (последовательно, ~40 правил без CachedProjectFilesRule) и нелокальные правила по файлам 2,6 с CPU. Профиль /home/aisee/.cache/worktrees/glint-measure/sc2go-hit.pprof. Дальше — вариант 1 через противника замысла
- 2026-11-01 08:44 в работе — glint-master
