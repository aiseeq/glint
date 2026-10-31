# Parameter receives one constant at every call: the branch under it is dead

Статус: в работе
Исполнитель: glint-master

## Вход
- graft-master 31.10 ~10:40 CET, находка ревью дифа бойца (дерево /home/aisee/.cache/worktrees/graft/fix-gocache-trim-batches, internal/gocache/gocache.go): `func (r *Result) entry(sub string, e fs.DirEntry, cutoff time.Time, apply bool) error`, оба вызова `r.entry(…, false)`, ветка `if apply { … }` мертва. Удаление вынесли в новую функцию, старую оставили для подсчёта. glint промолчал (unused-param — только неиспользуемый параметр).
- Дерево бойца сейчас на доработке; живого примера после правки не будет — репро синтетикой.

## Что сделать

## Приёмка
- Синтетический аналог фрагмента выше даёт одну находку; `bin/consumers -r <rule>` разобран.

## Что сделать (скилл glint-gap)
1. Проверить `glint rules`: правила про параметр с одним значением во всех вызовах нет (unused-param, interface-param-ignored, memo-ignores-parameter — о другом).
2. TDD: неэкспортируемая функция/метод (или экспортируемая в package main/internal), все вызовы в модуле передают один и тот же литерал или константу в параметр, и параметр управляет ветвлением (`if p`, `switch p`) — находка на параметре: ветка под другим значением мертва. Отрицательные: функция-значение (передаётся как значение, реализует интерфейс), экспортируемая API библиотечного пакета, вызов один (?) — решить по прогону, тестовые вызовы.
3. Прогон по потребителям до установки, разбор каждой находки.


## Журнал
- 2026-10-31 10:38 открыт — glint-master
- 2026-10-31 10:43 в работе — glint-master
- 2026-10-31 10:43 note — glint-master: проба /home/aisee/.cache/worktrees/glint-measure/probe-const-param (синтетика фрагмента) — 0 находок на v1.83.7-189. Боец Luna 1031-1043-param-always-same-constant (glint-правило): бриф brief-param-always-same-constant.md, приёмка accept-param-always-same-constant.sh в /home/aisee/.cache/worktrees/glint-measure, дерево /home/aisee/.cache/worktrees/glint/param-always-same-constant
- 2026-10-31 11:04 note — glint-master: сдача 1 принята приёмкой; ревью: 3 находки у потребителей, верная 1 (sc2go walk eyes=true в обоих вызовах), ложные 2 (glint hist.Head n в len(r)<=n, graft envWith key в EqualFold — параметр в условии, но ветку не решает). Боец лишне правил SIGPIPE в glint rules — дефект был в приёмке мастера (grep -q под pipefail), приёмка поправлена. Ревью 1: brief-param-always-same-constant-2.md
