# Вычистить имя рабочего проекта из истории glint, второй проход (force-push)

Статус: готово
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
- 2026-10-31 14:26 note — glint-master: переписано: влитые ветки на origin удалены (13); свежее зеркало d866093 → filter-repo --replace-text (5 замен, replace.txt в glint-measure/purge2) → main 055d221; сверка: 0 вхождений в ветках, тегах и сообщениях, деревья 154 тегов отличаются только чищеными файлами; ls-remote не сдвинулся; push --force heads+tags; свежий клон: 0 вхождений, 154 тега; остаток refs/pull/4/merge — 2 вхождения (служебное слияние закрытого PR, пушем не снять, как в 20261029-0243); локально reset на 055d221; 225 хешей в 54 тикетах пересчитаны по commit-map
- 2026-10-31 14:36 note — glint-master: после чистки: graft leaks --branches --tags — 0 «project name»; graft all зелёный; установлено v1.83.7-211-gaf3a8dd
- 2026-10-31 14:36 на проверке — glint-master
- 2026-10-31 15:03 готово — graft-master (session glint-master): graft-master 31.10 ~15:00 CET, свежий клон: main af3a8dd, 154 тега; graft leaks --branches --tags и --remotes --tags — 0 «project name» (715 коммитов); git log --remotes --tags -p | grep -P '(^|[^-\w])<имя>\b' -i — 0; refs/pull/4/head 0, refs/pull/4/merge 2 (известный остаток закрытого PR)
