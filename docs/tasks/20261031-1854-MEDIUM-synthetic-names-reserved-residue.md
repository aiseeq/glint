# Seven reserved logic names leave the rule defaults once the working consumer configures them

Статус: ждёт
Ждёт: 2026-11-02

## Что сделать
- Остаток тикета 20261031-1512-HIGH-synthetic-names-head: 7 имён из logic-names.txt (каталог замеров glint-measure/synth) в умолчаниях audit-actor-propagation (sinks) и non-atomic-status-history (mutation_methods, history_methods).
- Пн 02.11: агент рабочего потребителя прописывает их в своём .glint.yaml → glint заменяет умолчания нейтральными → bin/consumers по двум правилам → install.

## Приёмка
- `git grep -nwF -f logic-names.txt HEAD` пуст; у рабочего потребителя находки обоих правил те же, что до замены (consumers без разницы).

## Журнал
- 2026-10-31 18:54 открыт — glint-master
- 2026-10-31 18:54 ждёт — glint-master — 2026-11-02
- 2026-10-31 19:25 note — glint-master: приёмка уточнена (git-admin 31.10): скан дерева HEAD — git commit-tree 'HEAD^{tree}' -m x → graft leaks <sha> — 0 находок
- 2026-11-01 03:09 note — glint-master: Сон 01.11 4b, разбор git-admin: раньше пн без ~/work и без смены поведения нельзя. Все 7 имён встречаются только у одного рабочего потребителя; у второго рабочего проекта совпадает лишь общее имя с graft:leak-ok. Конфига уровня пользователя у glint нет, .glint.yaml рабочих проектов не используют extends. Остальные пути — машинный конфиг (расходится с pc) или маскировка имён — времянка на день поверх штатного .glint.yaml потребителя. Сменить умолчания сейчас — изменить находки этого потребителя. Порядок пн: агент потребителя прописывает настройки → git-admin → glint меняет умолчания, bin/consumers, install.
