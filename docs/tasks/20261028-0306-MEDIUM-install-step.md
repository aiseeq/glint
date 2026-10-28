# install через шаг graft {install: bin/glint} вместо mktemp+mv

Статус: открыт

## Вход
Задание git-admin (лид 27.10, пункт D; спецификация ~/git/docs/install-step.md, пилот akit ad1c782): задача install в .graft.yaml — шаг `{install: bin/glint}` вместо связки mktemp+install+mv. Шаг ставит только закоммиченное (уходит -dirty).

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
