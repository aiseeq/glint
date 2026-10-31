# Synthetic names in place of 207 names copied from closed projects (HEAD only)

Статус: в работе
Исполнитель: glint-master

## Что сделать
- Задание git-admin через graft-master 31.10 15:10; рамка сужена git-admin 31.10 15:10: только HEAD, историю не переписывать (CLAUDE.md glint, «Утечка в выпущенной истории»: имена функций — не утечка).
- Списки graft-master: /home/aisee/.cache/graft/leaks/glint-synthetic/ (README.md, first.tsv — 7 имён интеграций / 9 файлов, names-files.tsv — 207 имён × 157 файлов).
- Каждое имя заменить выдуманным нейтральным (projectA/payprov-стиль), согласованно во всех местах файла и пакета; поведение правил и тестов не меняется. Первыми — 7 интеграций.
- Партии бойцами Luna по папкам, файлы партий не пересекаются. Порядок влития: партия интеграций первой.

## Приёмка
- `git grep -nwF -f <207 имён> HEAD` = 0, кроме allow graft-master с причиной.
- graft all зелёный; коммиты прошли leak-проверку graft commit (новых частных имён нет).
- Итог git-admin с ключом тикета.

## Журнал
- 2026-10-31 15:12 открыт — glint-master
- 2026-10-31 15:14 в работе — glint-master
- 2026-10-31 15:14 note — glint-master: план: 6 партий бойцов Luna по папкам (files-N/names-N/brief-N в /home/aisee/.cache/worktrees/glint-measure/synth, приёмка accept.sh N: graft gate, только файлы партии, зарезервированные не тронуты, имена ушли или keep-N.tsv с причиной), деревья /home/aisee/.cache/worktrees/glint/synth-names-1..6. Зарезервировано себе (логика правил, списки по умолчанию): logic-names.txt — 11 имён в audit_actor_propagation.go, non_atomic_status_history.go, terminal_after_failed_checkpoint.go, stub_method.go, provider_outcome_rules.go; их переименование меняет находки потребителей — отдельно, с прогоном по потребителям
- 2026-10-31 15:17 note — glint-master: бойцы 1031-1514-synth-names-1..6 запущены (Luna, glint-рефакторинг). graft-master спрошен про allow: 4 общих имени из logic-names.txt (общие слова в списках по умолчанию). Словарь рабочего потребителя (7 имён: logic-names.txt без общих) — порядок: рабочий потребитель прописывает их в .glint.yaml (настройки правил audit-actor-propagation и non-atomic-status-history) → в glint по умолчанию нейтральные; агенты рабочих — пн 02.11
- 2026-10-31 15:24 note — glint-master: graft-master 15:3x: глобального allow нет; graft 9e1426b снял 14 имён по корпусу без регистра (names-files-after.tsv 193 имени, dropped-by-corpus.txt), из 4 общих одно среди ушедших. Остальные 3 общих — метка в конце строки '// graft:leak-ok общее имя, список по умолчанию правила'. 7 имён словаря рабочего потребителя — известный остаток до 02.11 (порядок потребитель → glint), не нарушение приёмки
- 2026-10-31 15:40 note — glint-master: партия 1 (интеграции) закоммичена 9aeb437 на ветке; ff в main не прошёл (ветка от старого main) — sync, влита как 75bd23a: 7 интеграций и ещё 9 имён заменены, leak-проверка graft commit прошла; AddressKey/NormalizeAddress оставлены (keep-1.tsv: слова правила), их же снял корпус graft 9e1426b
- 2026-10-31 15:49 note — glint-master: партия 3 закоммичена 836e7a8 (ветка); leak-проверка поймала новое имя бойца в silently_optional_dependency.go:352 (частное) — заменено на SetAlertSender. Урок: синтетика бойца может совпасть с частным именем, ловит graft commit при влитии. Партия 2 возвращена бойцу: 7 оставленных имён не привязаны к точному имени (правила ищут слова)
- 2026-10-31 15:56 note — glint-master: партия 3 влита a5d96b0 (worker done влито)
- 2026-10-31 16:24 note — glint-master: партия 5 влита 28076ce (36 имён, keep пусто)
- 2026-10-31 16:30 note — glint-master: партия 4 влита 3110b8a (41 имя; ещё одно новое имя бойца совпало с частным — заменено мастером)
