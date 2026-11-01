# Walk residue: double error on an unreadable directory, ignored() allocations

Статус: открыт

## Вход
- Остаток проверки Terra 1101-0635-glint (/home/aisee/.cache/worktrees/glint-measure/verdict-walk.md, ## 5) после c211f14.

## Что сделать
- Недоступный каталог даёт две ошибки вместо одной: WalkDir вызывает обработчик каталога до чтения, addDir читает его .gitignore и получает permission denied; затем WalkDir повторно вызывает обработчик с ошибкой чтения каталога. Одна ошибка на каталог, без потери ошибки на нечитаемом .gitignore в читаемом каталоге.
- gitignoreIndex.ignored: Abs и разбиение пути при пустом индексе, новый срез и ключи предков на каждый путь — замерить на /home/aisee/go и большом потребителе; убрать, если заметно.
- Без --tolerate-broken-packages один недоступный каталог под корнем (на $HOME — .local/share/containers) отменяет весь прогон; поведение прежнее — решить, верно ли это для каталогов вне модулей Go.

## Приёмка
- Тест: недоступный каталог — одна ошибка; нечитаемый .gitignore в читаемом каталоге — ошибка.
- Замер до/после ignored на /home/aisee/go.

## Журнал
- 2026-11-01 06:47 открыт — glint-master
