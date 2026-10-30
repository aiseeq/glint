# Гейт потребителя: field-nil-check-inconsistent 9–13 с на весь Go-проект при правке любого файла; tsc 15 с на всю программу при правке одного tsx

Статус: в работе
Исполнитель: glint-master

## Вход
- Запрос: мастер потребителя А 30.10 ~06:20 CET, тикет Сна «гейт ≤ 60 с, lint-changed ~10 с». Замеры: его scratchpad si1556/ (timing-d6.txt, wt-1..3.txt, main-3.txt, glint-acef.prof).
- Свежий worktree с правкой 8 файлов: analyze 34,3 с, tsc 15,4 с (вся программа admin-app), field-nil-check-inconsistent 13,3 с. Главное дерево без правок: 2,6 с.
- Промах кэша в worktree — отдельный тикет worktree-cache-file-scope.

## Что сделать
1. field-nil-check-inconsistent: профиль, причина 9–13 с; дешевле или инкрементально.
2. tsc на изменённом файле: инкрементальный tsc (--incremental --tsBuildInfoFile в кэше glint, --noEmit) — замер выигрыша, корректность.

## Приёмка
- Замер на потребителе А до и после, тот же сценарий (правка 8 файлов в worktree); находки обоих правил на всех потребителях те же (graft consumers).

## Журнал
- 2026-10-30 06:15 открыт — glint-master
- 2026-10-30 06:34 в работе — glint-master
- 2026-10-30 06:47 note — glint-master: 07:0x CET п.1 сделан: 6260894 — fieldNilFieldOwner вынесен из цикла по методам (было O(M²) на поле); потребитель А --no-cache -r field-nil-check-inconsistent 8,4 с → 0,29 с, находки те же, graft consumers 0 различий. Промах кэша в worktree — d8b1f30 (worktree-cache-file-scope). п.2 (tsc инкрементально) — дальше
