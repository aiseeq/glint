# glint speed reference: glint.tsv and glint.md by the perf FORMAT

Статус: готово
Исполнитель: glint-master

## Вход
- git-admin 30.10 16:05 CET: задание лида perf-baseline-1030, этап 1 (/home/aisee/docs/tasks/20261030-1136-MEDIUM-perf-baseline-1030.md; тикет git-admin /home/aisee/git/docs/tasks/20261030-1137-HIGH-perf-baseline-git.md). akit и graft готовы, glint следующий.
- Слово пользователя: `user-word ~/.claude/projects/-home-aisee/d753e3a8-1750-4371-bdef-a4263a5bf0f7.jsonl 'собирать статистику работы всех'` (30.10 11:34 CET).
- Формат: /home/aisee/.claude/improve/state/perf/FORMAT.md (правка 16:05: `tl --all --codex`, `job:<утилита> <задача>`, мера `p95_s`). Образцы: akit.tsv|md, graft.tsv|md там же.
- Известно: потребитель Б — glint в гейте 19–23 с из ~60 с; прогон без правок 8 с, причина — нелокальные правила (тикет 20261030-1430-MEDIUM-nonlocal-rules-cache-floor). В пилоте akit `tk done` p95 15,7 с — `glint check` под давлением IO (akit.md, «Суточная мера»).
- Первые числа 30.10 16:10: `graft stats --all --task glint --since 24h` wall-p50 2,603 с, wall-p95 29,538 с; `tl --all --codex --since 24h --wait 'glint check' --q 95` 30754 мс.

## Что сделать
1. Пути glint, которые агенты и гейты зовут чаще и дольше ждут: `glint check` агентом, задача glint в гейтах потребителей (все и главные по отдельности), прогон без правок на фиксированном потребителе.
2. /home/aisee/.claude/improve/state/perf/glint.tsv и glint.md строго по FORMAT.md; кандидаты ×2 — только назвать с замером.
3. Коммит в claude-config, итог git-admin строкой: пути файлов, число путей и с командой, кандидаты ×2 с числами, что мешало.

## Приёмка
- Приёмка бойца — scratchpad мастера `accept-perf-baseline.sh`, код 0 (формат tsv, каждая команда ≤ 60 с: одно число и код 0 либо код 3; разделы .md).
- Независимая проверка — суб-агент по FORMAT.md: воспроизводит референсы.

## Журнал
- 2026-10-30 16:06 открыт — glint-master
- 2026-10-30 16:07 в работе — glint-master
- 2026-10-30 16:07 note — glint-master: боец Luna 1030-1607-perf-baseline (разбор-данных, --escalate terra): бриф /home/aisee/.cache/worktrees/glint-measure/brief-perf-baseline.md, приёмка /home/aisee/.cache/worktrees/glint-measure/accept-perf-baseline.sh, дерево /home/aisee/.cache/worktrees/glint/perf-baseline (только чтение)
- 2026-10-30 16:42 note — glint-master: боец принят приёмкой (11 путей, все с командой). Ревью 1 (/home/aisee/.cache/worktrees/glint-measure/review-perf-baseline-1.md): таймаут warm-скриптов давал код 3 и прятал регресс; job:glint gate потребитель А — на деле analyze (in=analyze); общие строки смешивают smoke/install/analyze; неверное время 18:20 в .md; худшие сутки до инкрементального tsc не отмечены. Отправлено worker continue
- 2026-10-30 16:50 note — glint-master: ревью 1 исправлено бойцом (warm по бюджету 45 с, коды 0/1 без Error:, пути task/gate/analyze по полю in, якорь 16:20, срезы после tsc), worker done влито. Мастер дописал в Пробелы потребитель А analyze ~61 с без профиля. Независимая проверка — Terra 1030-1650-perf-check, бриф /home/aisee/.cache/worktrees/glint-measure/brief-check-perf-baseline.md
- 2026-10-30 17:01 готово — terra-проверка (session glint-master): Terra 1030-1650-perf-check, два захода: семь окон tl для cli:glint check — 30754 мс (= tsv), общий p95 job:glint task p95 — 32,918 с (= tsv), warm-потребителя Б — 7223 мс против 7294 (шум); поля, команды (≤60 с, одно число) — приёмка accept-perf-baseline.sh код 0 после правок. Находки исправлены мастером: пути gate→task (graft stats без фильтра родителя), якорь job 16:20:53 CET, текст потребитель А (24 analyze + 1 без родителя), единицы мс, довод о читаемости. Окно потребителя Б: мастер пересчитал по profile/корню — худшее последнее окно, 25,925 с, n=23; у проверки 25,968 с в 28–29.10 при другом отборе (0,2 %). Спор: FORMAT требует 5+ прогонов, warm-скрипты делают до 5 в 45 с ради видимости регресса — вынесено git-admin. Коммит claude-config 043c0c4
- 2026-10-30 17:10 note — glint-master: возврат git-admin 17:0x: скрипты вне репо. Обёртки tl/graft stats убраны — прямые команды (код 3 и пустой stdout сами); warm-логика — tools/perf/warm-check.sh с тестами (fabf398), с правилом FORMAT 17:04 (прогон > 15 с — бюджет 60 − прогон); папка state/perf/glint-perf удалена; приёмка 11/11; claude-config a0ecce1
