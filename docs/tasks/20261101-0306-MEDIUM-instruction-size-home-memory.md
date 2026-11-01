# glint check -r instruction-size on $HOME takes 14 GB and over 120 s

Статус: готово
Исполнитель: glint-master

## Вход
- aguard-master 01.11: `aguard memory report -since 168h` — пик ~15 ГБ у `glint check -r instruction-size` в сессии lead 29.10 02:32 CET (группа 19 ГБ, крупнейший за неделю).
- Источник команды: суб-агент lead «Сон: self-review» (tl a5ba8489:233): `cd ~; timeout 120 glint check -r instruction-size`.
- Замер 01.11 ~03:05 CET, glint 280d011: `cd ~ && /usr/bin/time timeout 120 glint check --no-cache -r instruction-size -o summary` — maxrss 14 052 728 КБ, выход 124 (не уложился в 120 с).

## Что сделать
- Найти, что держит память при одном правиле instruction-size на корне $HOME: обход читает и разбирает все файлы под корнем, хотя правилу нужны только файлы инструкций? (профиль heap на этом прогоне, go-performance).
- Ожидание: прогон с правилами, которым нужны только .md инструкций, не читает и не разбирает остальные файлы; на $HOME — секунды и сотни МБ.

## Приёмка
- Тот же замер на $HOME: maxrss и wall было → стало; находки instruction-size те же (сверка с прогоном на корнях ~/.claude, ~/work, ~/git).
- `graft test`, self-check.

## Журнал
- 2026-11-01 03:06 открыт — glint-master
- 2026-11-01 04:05 в работе — glint-master
- 2026-11-01 04:05 note — glint-master: причина: walker читает и разбирает каждый подходящий файл под корнем (isAnalyzableFile/processFile), в $HOME — кэш модулей и чужие репо; правилу нужны только файлы инструкций. План: необязательный предикат файлов у правила, обход читает только нужные, когда предикат есть у всех включённых. Боец Luna, бриф /home/aisee/.cache/worktrees/glint-measure/brief-instruction-size-home-memory.md, приёмка accept-instruction-size-home-memory.sh (maxrss < 1,5 ГБ на $HOME, те же находки на ~/.claude, ~/work, ~/git)
- 2026-11-01 05:43 note — glint-master: Luna: память решена (172 МБ на $HOME вместо 14 ГБ), но прогон не укладывается в 300 с. Профиль мастера (/home/aisee/go, 12,7 с): 67% — gitignoreIndex.ignored: один общий список шаблонов всех встреченных .gitignore, каждый каталог сверяется со всеми — квадратично. Заход 3 снят, продолжение с этой причиной: шаблоны по каталогу-домену, сверка только с предками. Приёмка исправлена мастером: на корне, где установленный glint падает (чужой Go-файл с ошибкой синтаксиса под ~/work), сравнивать нечего — новый должен отработать; прогон на $HOME обязан завершиться
- 2026-11-01 06:35 note — glint-master: итог Luna (5 заходов, 2 продолжения с профилем мастера): $HOME 105 с / 216 МБ (было 14 ГБ и таймаут), /home/aisee/go 13,7 → 3,1 с. graft consumers по всем правилам: 20 проектов, 0 различий. Коммит c211f14 в ветке. Проверка — Terra, бриф verify-walk-brief.md
- 2026-11-01 06:47 готово — terra-1101-0635-glint (session glint-master): verdict-walk.md: ВЕРДИКТ готово на c211f14; /home/aisee/go 82 с/12 ГБ (убит) → 4,05 с/47 МБ; $HOME 25,9 с/263 МБ с --tolerate-broken-packages, 193 находки (мастер); gitignore-фикстуры и WalkDir (симлинки, недоступный каталог) совпадают с main; кэш после -r не портит полный прогон; consumers по всем правилам 0 различий
