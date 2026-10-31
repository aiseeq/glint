# Unexported function that only forwards its parameters to another package function: a second name for one logic

Статус: в работе
Исполнитель: glint-master

## Вход
- Ревью захода 4 mirror-comment-honest-penalty 31.10: боец Luna, сводя копии тел между пакетами, оставил 42 обёртки `func isIdentifierChar(c byte) bool { return helpers.IsIdentifierChar(c) }`. duplicate-func-across-packages пропускает делегирующие функции — находки ушли, а два имени одной логики остались. Тот же обход доступен любому агенту на любом потребителе.

## Что сделать

## Приёмка
- Синтетика пересылки — 1 находка, отрицательные — 0; bin/consumers разобран.

## Что сделать (glint-gap)
1. TDD: неэкспортируемая функция, тело — один `return pkg.F(p1, …, pn)` (или вызов без return), аргументы — её параметры в том же порядке без изменений, F из другого пакета модуля — находка «isX only forwards to pkg.F — call pkg.F directly».
2. Не находка: функция используется как значение (передана, присвоена — нужна своя сигнатура); аргументы меняются (константа, преобразование, переставлены); F из стандартной библиотеки или внешнего модуля (адаптер имени — допустимо? решить по прогону); метод (реализация интерфейса).
3. Прогон по потребителям до установки, разбор находок.


## Журнал
- 2026-10-31 10:58 открыт — glint-master
- 2026-10-31 11:56 в работе — glint-master
- 2026-10-31 11:56 note — glint-master: боец Luna 1031-1156-forwarding-wrapper-func (glint-правило): бриф /home/aisee/.cache/worktrees/glint-measure/brief-forwarding-wrapper-func.md, приёмка accept-forwarding-wrapper-func.sh там же, дерево /home/aisee/.cache/worktrees/glint/forwarding-wrapper-func
- 2026-10-31 13:03 note — glint-master: влито 8eac5d5 (мастер переименовал утёкшее имя в тесте), graft all зелёный, установлено v1.83.7-201; единственная находка потребителей (llmark/tool cmd/farm/pc.go:390) отправлена llmark-master; боец закрыт: влито
- 2026-10-31 13:03 на проверке — glint-master
- 2026-10-31 13:13 note — glint-master: проверка opus: вернуть — FuncValues (pkg/rules/helpers/func_values.go) собирает места вызова из одного файла, а Uses — по пакету: вызов из другого файла пакета считается значением функции, обёртка выпадает; второй файл в пробе → 0 находок. Тот же недосчёт у unused-param. llmark-master: находка верна, исправлено 9dfda1d
- 2026-10-31 13:13 в работе — glint-master
