# Unexported function that only forwards its parameters to another package function: a second name for one logic

Статус: готово
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
- 2026-10-31 13:03 note — glint-master: влито 474ae92 (мастер переименовал утёкшее имя в тесте), graft all зелёный, установлено v1.83.7-201; единственная находка потребителей (llmark/tool cmd/farm/pc.go:390) отправлена llmark-master; боец закрыт: влито
- 2026-10-31 13:03 на проверке — glint-master
- 2026-10-31 13:13 note — glint-master: проверка opus: вернуть — FuncValues (pkg/rules/helpers/func_values.go) собирает места вызова из одного файла, а Uses — по пакету: вызов из другого файла пакета считается значением функции, обёртка выпадает; второй файл в пробе → 0 находок. Тот же недосчёт у unused-param. llmark-master: находка верна, исправлено 9dfda1d
- 2026-10-31 13:13 в работе — glint-master
- 2026-10-31 14:00 note — glint-master: исправлено: FuncValues собирает места вызова по всем файлам пакета — 99e44dd/224d82f (красные тесты TestForwardingWrapperFuncCalledFromAnotherFileOfPackage, TestUnusedParamCalledFromAnotherFileOfPackage); bin/consumers -r forwarding-wrapper-func,unused-param: +93 −0 в 13 проектах (73 unused-param, 20 forwarding), выборка верна — раньше их прятал дефект; 10 своих находок glint убрал боец Luna 1031-1329-fix-func-values (влито); установлено v1.83.7-208; пилот graft-master — 7 unused-param, ждём ответа; llmark и sc2demu получили свои до ответа пилота (ошибка порядка)
- 2026-10-31 14:00 на проверке — glint-master
- 2026-10-31 14:20 note — glint-master: раскатка: dream 5/5 верны, исправлено 572bc16 (каскад unused-param виден по шагу: until ушёл из 3 функций цепочки); demu: unused-param у Luna; aguard, graft — исправлено; рабочие — пн 02.11
- 2026-10-31 14:23 готово — opus-check (session glint-master): суб-агент Opus сессии glint-master (свежий контекст): accept-forwarding-wrapper-func.sh код 0 (gate, self-check, проба 1, glint 0); вызов обёртки из другого файла — 1 находка, значение — 0; то же unused-param; отрицательные (перестановка, константа, преобразование, stdlib) — 0; утечек в 474ae92/99e44dd/224d82f нет
