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
- 2026-10-30 06:47 note — glint-master: п.1 сделан: 6260894 — fieldNilFieldOwner вынесен из цикла по методам (было O(M²) на поле); потребитель А --no-cache -r field-nil-check-inconsistent 8,4 с → 0,29 с, находки те же, graft consumers 0 различий. Промах кэша в worktree — d8b1f30 (worktree-cache-file-scope). п.2 (tsc инкрементально) — дальше
- 2026-10-30 06:58 note — glint-master: п.2: замер на копии фронтенда потребителя А из корня с его .glint.yaml — tsc TOTAL после правки одного tsx 13,4–18,1 с (listFilesOnly 2,5 с, полный tsc 5.9 11–13 с, tsc 7 1–2 с); tsc 5.9 --incremental после правки 3,6–3,8 с, ошибки те же. Боец Luna 1030-0658-tsc-incremental: бриф scratchpad brief-tsc-incremental.md, приёмка accept-tsc-incremental.sh (медиана трёх правок ≤ 7 с, находки = ~/bin/glint, graft consumers -r tsc 0 различий); сухой прогон приёмки на main — 12,2 с, rc=1, как и ждали
- 2026-10-30 07:21 note — glint-master: п.2: боец сдал (медиана 3,5 с, холодный 9,8 с, consumers 0 различий); ревью 1: --listFiles теряет .js при allowJs (быстрый путь отдаст старый ответ), каталог кэша — копия toolcache, лишние ключ и хэш в build info; worker continue с review-tsc-incremental-1.md
- 2026-10-30 07:37 note — glint-master: п.2 сделан: 3cda623 — tsc проекта и tsc 7 инкрементальные, build info в кэше glint (toolcache Dir), список файлов из --listFiles того же прогона (любые расширения, JS при allowJs тоже), --listFilesOnly убран. Копия фронтенда потребителя А: tsc TOTAL трёх правок 12–14 с → 3,2–3,7 с (медиана 3,4), холодный 14,7 → 10,2 с; graft consumers -r tsc 21 проект 0 различий. graft all: первый прогон упал в test, имя теста потеряно (graft обрезал вывод на 4 МБ), тихий go test и повтор graft all — зелёные
