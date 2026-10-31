# mirror-comment-copy leaves a marked copy to the body rule even where the body rule does not index it

Статус: открыт

## Что сделать
- Остаток тикета 20261031-0303-MEDIUM-mirror-comment-honest-penalty (проверка Opus 19:40, не блокер): функция-кандидат правила по телу с пометкой «mirrors X» молчит, если duplicate-func-across-packages её не индексирует — пакет mock/fake/stub (testDoublePackage), другой модуль, правило выключено в конфиге.
- Цена: `-r mirror-comment-copy` в одиночку всегда грузит типы (NeedsTypedGoProject true): на крупном потребителе 0,5 → 1,6–1,9 с; на полном прогоне не видно.

## Приёмка
- Проба: пометка у копии в пакете mock и при выключенном duplicate-func-across-packages — находка mirror-comment-copy; честная обёртка — нет. consumers без новых ложных.

## Журнал
- 2026-10-31 19:54 открыт — glint-master
