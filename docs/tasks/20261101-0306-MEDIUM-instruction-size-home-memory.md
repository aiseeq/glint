# glint check -r instruction-size on $HOME takes 14 GB and over 120 s

Статус: в работе
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
