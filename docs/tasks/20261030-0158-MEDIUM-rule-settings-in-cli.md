# glint rules показывает настройки правила с примером YAML

Статус: готово
Исполнитель: glint-master

## Вход
- Проблема: настройки правил (period_modules, clock_package, max_lines…) из CLI не найти; боец потребителя искал их rg по ~/go/pkg/mod и find по ~ — 10,8 ГБ чтения за 5 с, фриз машины 13,6 с (лид 30.10 01:56).
- Метод: правило объявляет свои настройки (ключ, тип, умолчание, описание, пример); `glint rules` перечисляет ключи, `glint rules <имя>` даёт карточку с готовым YAML; тест сверяет объявленные ключи с читаемыми в коде.
- Дешевле: README — вторичен и устаревает; тест-сверка держит объявление честным.
- Цена: день бойца.
- Если не делать: агенты потребителей и дальше ищут настройки обходом диска.

## Что сделать
- Бриф: /home/aisee/.cache/claude-tmp/claude-1000/-home-aisee-git-glint/24c34360-b66d-4f12-b9dd-7328b412e44a/scratchpad/brief-rule-settings-cli.md

## Приёмка
- /home/aisee/.cache/claude-tmp/claude-1000/-home-aisee-git-glint/24c34360-b66d-4f12-b9dd-7328b412e44a/scratchpad/accept-rule-settings-cli.sh — код 0.
- `glint rules ts-period-boundary-by-hand` печатает period_modules с YAML-примером по пути categories.<кат>.rules.<правило>.settings.

## Журнал
- 2026-10-30 01:58 открыт — glint-master
- 2026-10-30 01:59 в работе — glint-master
- 2026-10-30 01:59 note — glint-master: запрос лида 30.10 01:56 (фриз от поиска настроек обходом диска); боец Luna 1030-0159-rule-settings-cli, worktree rule-settings-cli; итог — git-admin
- 2026-10-30 02:22 note — glint-master: ревью 1: таблица настроек в rule.go вместо правил, умолчания выдуманы (long-function 50 против 100), сверка не видит NameSetSetting и хелперы (5 ключей из конфигов потребителей нет в карточках); раунд 2 — review-rule-settings-1.md
- 2026-10-30 03:10 note — glint-master: раунд 2 принят; doc-missing skip_trivial объявил мастер (запрет на doccheck был шаблонный); примеры без имён потребителей; влито 859ab8b
- 2026-10-30 03:10 на проверке — glint-master
- 2026-10-30 03:16 готово — git-admin (session glint-master): git-admin на установленном v1.83.7-146-gaebaba9: карточка ts-period-boundary-by-hand с period_modules и YAML; опечатка в имени — код 1 с подсказкой; 56 строк settings в glint rules. Сверку ключей .glint.yaml всех проектов выполнила приёмка accept-rule-settings-cli.sh (код 0)
