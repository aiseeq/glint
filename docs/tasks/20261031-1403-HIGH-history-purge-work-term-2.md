# Вычистить имя рабочего проекта из истории glint, второй проход (force-push)

Статус: в работе
Исполнитель: glint-master

## Что сделать
- Находка проверяющего 31.10: имя рабочего проекта в выпущенной истории — заголовок страницы в pkg/rules/patterns/unfalsifiable_test_case_test.go (с 29.09, 9 коммитов), журналы тикетов docs/tasks: perf-outlier-rule (30.10), metric-fallback-zero и field-nil-check-inconsistent (31.10, «<имя>-481»), mirror-comment-honest-penalty (31.10). Сообщения коммитов и тегов чисты. private-terms ловит имя только в контексте (master, gate…), поэтому гейт пропустил.
- Решение: CLAUDE.md проекта, «Утечка в выпущенной истории» (решение автора 28.10); порядок — тикет 20261029-0243-HIGH-history-purge-work-term.
- Шаги: дождаться независимой проверки трёх тикетов (не переписывать под проверяющим) → clone --mirror → filter-repo --replace-text (нейтральные замены) → сверка 0 вхождений, деревья тегов отличаются только чищеными файлами → ls-remote не сдвинулся → push --force heads+tags → локально fetch+reset → хеши в docs/tasks по commit-map → graft all, graft install → graft-master: пробел private-terms фактом.

## Приёмка
- Свежий клон с GitHub: `git log --all -p` и теги — 0 вхождений имени (без учёта регистра, целым словом).
- `graft all` зелёный, `glint --version` с новым хешем.

## Журнал
- 2026-10-31 14:03 открыт — glint-master
- 2026-10-31 14:03 в работе — glint-master
