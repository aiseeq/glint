# поле проверено на nil в одном методе типа и разыменовано без проверки в другом

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
- TestFieldNilCheckInconsistent* зелёные; синтетика брифа — 1 находка; обязательная находка на копии потребителя А. Путевая чувствительность — отдельный тикет field-nil-check-path-sensitive.

## Журнал
- 2026-10-29 18:55 открыт — glint-master
- 2026-10-29 18:58 в работе — glint-master
- 2026-10-29 18:58 note — glint-master: Запрос мастера потребителя А 29.10 (класс из независимого ревью потребителя А). Боец Luna, worktree field-nil-check, бриф scratchpad brief-field-nil-check.md, приёмка accept-field-nil-check.sh, мера — consumers.sh.
- 2026-10-29 19:45 note — glint-master: Сдача 1: 744 находки без разбора; выборка — сторожа с ошибкой «not initialized» и метод-сторож. Боец правил чужие правила ради самопроверки. Раунд 1: review-field-nil-check-1.md (мягкая ветка nil как признак, метод-сторож, ≤80 с вердиктами).
- 2026-10-29 20:55 note — glint-master: Раунд 1 сдан: 43 находки — все от одной мягкой проверки у потребителя Б; пропущен случай запроса (soft-сторож принят за сторожа); правил md-list-after-label. Раунд 2: review-field-nil-check-2.md, accept-field-nil-check-3.sh.
- 2026-10-29 21:32 note — glint-master: Раунд 2 сдан: обязательная находка есть, 75 находок; выборка мастера 4 — 2 ложные: ветка nil — отказ без error (ok=false, ответ клиенту 500). Раунд 3: review-field-nil-check-3.md, accept-field-nil-check-4.sh (≤40, вердикт по чтению).
- 2026-10-29 21:58 note — glint-master: Раунд 3 сдан: 34 находки, ~1/5 — разыменование в неэкспортированном методе, защищённое отказом вызывающего (транзитивно). Раунд 4: review-field-nil-check-4.md.
- 2026-10-29 22:06 note — glint-master: Раунд 4 сдан: 20 находок, защита вызывающим работает; ложная — сторож-метод с отрицанием (!x.IsSet() → return). Раунд 5: review-field-nil-check-5.md.
- 2026-10-29 22:12 note — glint-master: Раунд 5 сдан: 19 находок, выборка мастера 3 — верные. Влито 4ce3240.
- 2026-10-29 23:34 note — glint-master: раунд 7 влит f547f87 (+ мой фикс QF1001): nil-safe метод, непустое присваивание до разыменования, сторож с return false, разыменование до проверки. Ушли sc2demu runtimemesh.go:203, crowd.go:103. Новая Medium graft internal/tasks/tasks.go:1274 (инвариант f.load только при Stats != nil) — верная по смыслу правила, Medium гейт не роняет. Слабости: falseGuard ищется по всему телу, не только в начале; fieldNilCheckPrecedes — по тексту, не по потоку. Двухрежимный тип (п.5) — остаётся находкой.
- 2026-10-31 10:46 note — opus-check: Не всё: слабости из записи 23:34 не вынесены в тикет. fieldNilCheckPrecedes (field_nil_check_inconsistent.go:321) глушит разыменование, если сравнение поля с nil стоит раньше по тексту, на любом пути: проба `if r.portfolio != nil { println() }; v, _ := r.portfolio.Valuation(ctx)` — 0 находок, хотя на пути после if поле не проверено (пропуск, CLAUDE.md: path-sensitive — через FlowWalker); falseGuard ищется по всему телу предиката. Остальное в порядке: main 354ae10 (4ce3240, f547f87 в main), 12 тестов TestFieldNilCheckInconsistent* зелёные, синтетика брифа — 1 находка на ReportOf, ветка-481 — обязательная admin_finance_reports_router.go:154 есть, graft all — код 0. Приёмка в тикете пустая — tk done откажет.
- 2026-10-31 10:48 готово — opus-check (session glint-master): 12 тестов TestFieldNilCheckInconsistent* зелёные, синтетика брифа — 1 находка, обязательная находка на копии потребителя А есть, graft all 0; main 354ae10 (4ce3240, f547f87); пропуск по пути вынесен в field-nil-check-path-sensitive
