# Parameter receives one constant at every call: the branch under it is dead

Статус: готово
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
- 2026-10-31 11:53 note — glint-master: ревью 1 принято: параметр считается, только если константа делает условие постоянным; вариадический, spread и method expression исключены. Мастер: параметр, перезаписанный или с взятым адресом, не находка (тесты); self-check нашёл копию patternkit.IsObjectIdent — перенесена в helpers, 3 правила-вызывателя без разницы по потребителям; маскировка ошибки FileForPosition снята (загрузка Tests:false). Потребители: 1 находка, верная — sc2go walk(eyes=true), отправлено sc2go-master. Влито ec33025, 0ff7551; graft all 0; установлено v1.83.7-197-g0ff7551. На проверку
- 2026-10-31 11:53 на проверке — glint-master
- 2026-10-31 12:00 готово — opus-check (session glint-master): Независимая проверка 31.10 opus-check: установлен glint v1.83.7-197-g0ff7551, ec33025 и 0ff7551 — предки (merge-base --is-ancestor). Проба probe-const-param (копия во временной папке): glint check . -s low -r param-always-same-constant — 1 находка store/sweep.go:16 «Parameter apply of entry is false at every call». go test ./pkg/rules/deadcode/ -run ParamAlwaysSameConstant — ok (3 теста PASS). Синтетика (один модуль, каждая функция вызвана дважды одной константой): n в len(h.r) <= n — 0; key в strings.EqualFold(name, key) — 0; параметр перезаписан в теле — 0; адрес параметра взят — 0; вариадический ...bool — 0; контроль if dry {return nil} — 1 находка. sc2go cmd/exam-key: находка main.go:144 «eyes of walk is true at every call»; по коду оба вызова (main.go:114 и :118) передают true, других ссылок на walk в пакете нет, ветки if eyes на :162 и :180. glint rules param-always-same-constant — описание есть (deadcode, MEDIUM). glint check ./... -r param-always-same-constant на самом glint — 0; graft self-check — No issues found, код 0. bin/consumers по потребителям не перепрогонял — по журналу.
