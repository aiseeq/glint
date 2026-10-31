# install через шаг graft {install: bin/glint} вместо mktemp+mv

Статус: готово
Исполнитель: glint-master

## Вход
Задание git-admin (лид 27.10, пункт D; спецификация ~/git/docs/install-step.md, пилот у одного потребителя): задача install в .graft.yaml — шаг `{install: bin/glint}` вместо связки mktemp+install+mv. Шаг ставит только закоммиченное (уходит -dirty).

## Что сделать
- /bin/ в .gitignore — есть.
- .graft.yaml: install: {deps: [build], run: [{install: bin/glint}]}; sh-блок убрать.
- Ссылок на старый способ в README/доках нет (grep).

## Приёмка
- `graft install` печатает `graft: install: glint <rev7> -> ~/bin/glint`.
- `go version -m ~/bin/glint | grep vcs`: vcs.modified=false, ревизия = HEAD кода.

## Журнал
- 2026-10-28 03:06 открыт — git-admin
- 2026-10-28 03:06 note — glint-master: edited .graft.yaml install → {install: bin/glint}; committing then graft install
- 2026-10-28 03:07 на проверке — glint-master — graft install: 'graft: install: glint 6a2c734 -> ~/bin/glint'; vcs.revision=6a2c734, vcs.modified=false
- 2026-10-28 03:08 note — git-admin: проверка git-admin: принято (install: bin/glint, ~/bin/glint 6a2c734 modified=false); tk done отказал на 2 medium glint duplicate-func-across-packages (unused_internal_export.go:545, error_wrap.go:191) — для glint-master
- 2026-10-28 03:11 готово — git-admin: git-admin: ~/bin/glint 6a2c734 modified=false, .graft.yaml install step; reinstall 5ca4984 modified=false
