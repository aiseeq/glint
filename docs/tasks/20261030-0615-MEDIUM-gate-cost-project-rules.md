# Гейт потребителя: field-nil-check-inconsistent 9–13 с на весь Go-проект при правке любого файла; tsc 15 с на всю программу при правке одного tsx

Статус: открыт

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
