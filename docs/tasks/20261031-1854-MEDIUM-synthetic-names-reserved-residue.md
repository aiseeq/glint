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
