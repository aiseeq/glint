# glint check -r instruction-size on $HOME takes 14 GB and over 120 s

Статус: открыт

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
