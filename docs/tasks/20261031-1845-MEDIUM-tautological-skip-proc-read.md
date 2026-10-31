# tautological-assertion: t.Skip on a read of /proc or /sys is an environment check, not a failure of the code under test

Статус: открыт

## Что сделать
- Заявка akit-master 31.10 ~18:50: ложная HIGH skip_on_failure на `if n, err := os.ReadFile("/proc/sys/user/max_user_namespaces"); err != nil || … { t.Skip(…) }`. Случай с exec.LookPath уже не находка (environmentProbes).
- Чтение системного файла по литеральному пути (/proc/, /sys/, /dev/, /etc/) — проба среды: os.ReadFile, os.Open, os.Stat с таким аргументом. pkg/rules/patterns/qarules/tautological_assertion_go_guard.go fromEnvironmentProbe.

## Приёмка
- TDD-тест: skip по ошибке os.ReadFile("/proc/…") — без находки; skip по ошибке os.ReadFile(path) переменной или вызова кода под тестом — находка остаётся.
- bin/consumers по правилу: только ушедшие находки того же вида, каждая разобрана; graft all зелёный.

## Журнал
- 2026-10-31 18:45 открыт — glint-master
- 2026-10-31 19:25 note — glint-master: фикс f0a5be7 (TDD: TestTautologicalAssertion_GoSkipOnSystemFileRead красный до фикса): readsSystemFile — os.ReadFile/Open/ReadDir литерального пути /proc/ /sys/ /dev/ /etc/ — проба среды. consumers по правилу: 20 проектов, 0 разниц (glint-measure/consumers-taut-proc.txt). Установлено 0498d18. Проверка — Terra 1031-1925-glint (бриф taut-skip/verify-brief.md)
