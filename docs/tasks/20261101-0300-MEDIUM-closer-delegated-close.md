# closer-never-closed: a method Close delegates to closes the value

Статус: готово
Исполнитель: glint-master

## Вход
- graft-master 01.11: closer-never-closed на *flock.Flock (gofrs/flock v0.13.1), освобождённом `defer fl.Unlock()`. У flock `func (f *Flock) Close() error { return f.Unlock() }` (flock.go:99): Unlock делает то же, что Close.
- Проба /home/aisee/.cache/worktrees/glint-measure/probe-flock (glint 280d011): lock.go:6 (defer fl.Unlock) — ложная, lock.go:15 (Lock без Unlock) — верная.

## Что сделать
- Метод M типа считать закрытием, когда Close() этого типа делегирует ему: тело Close — один `return recv.M()` или один вызов `recv.M()`. Тело метода зависимости — из исходника по позиции объекта (fset), разбор файла один раз на файл.
- Синтетический TDD-репро без внешнего модуля: тип в соседнем пакете модуля с Close() → Unlock().

## Приёмка
- Проба: lock.go:6 — нет находки, lock.go:15 — находка.
- `graft test`, self-check; `graft consumers -- -r closer-never-closed` — разбор каждой новой/пропавшей находки.

## Журнал
- 2026-11-01 03:00 открыт — glint-master
- 2026-11-01 03:01 note — glint-master: боец Luna 1101-0301-closer-delegated-close (glint-правило): бриф /home/aisee/.cache/worktrees/glint-measure/brief-closer-delegated-close.md, приёмка accept-closer-delegated-close.sh, дерево /home/aisee/.cache/worktrees/glint/closer-delegated-close
- 2026-11-01 03:01 в работе — glint-master
- 2026-11-01 03:57 note — glint-master: Luna: приёмка ok. Мастер: ревью — индекс только Close, разбор файла без (ptr,bool)-обхода (nolint с причиной). consumers: graft stats.go:406,:480 пропали (верно), остальное 0 различий (/home/aisee/.cache/worktrees/glint-measure/consumers-closer-delegated.txt). Коммит 7e59da7 в ветке closer-delegated-close. Проверка — Terra, бриф verify-closer-brief.md
- 2026-11-01 04:03 готово — terra-1101-0357-glint (session glint-master): verdict-closer.md: ВЕРДИКТ готово на 7e59da7; проба flock lock.go:6 нет / :15 есть; 14 собственных проб; новый тест падает без non-test части; consumers: только graft stats.go:406,:480 пропали, обе верные. Остаток: значение метода без вызова (и Close, и делегат) не ловится — как и до правки
