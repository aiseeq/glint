# Правило: функция-копия, отличающаяся одним выражением

Статус: в работе
Исполнитель: glint-master

## Вход
- Проблема:
- Метод:
- Дешевле:
- Инструмент:
- Цена:
- Если не делать:

## Что сделать

## Приёмка
- Тест: положительный (синтетика по образцу), отрицательные — 2+ различия, мелкие функции, тесты, разные пакеты, разная структура.
- bin/glint check -r near-duplicate-func по всем потребителям, каждая находка разобрана; graft all зелёный.

## Что
- Источник: агент потребителя 28.10 ~11:00 — пропуск glint в ревью бойца: две функции одного файла по 16 строк, тела совпадают, кроме одного аргумента вызова (текст письма). Оригинал — ~/.local/share/glint-history/near-dup-func/owner.go.orig (notifyOwner / notifyAdmissionOwner).
- Почему не поймано: duplicate-block внутри файла — от 40 строк (defaultBlockSize); renamed-duplicate-block сравнивает только составные операторы на точное совпадение, if-guards отсекает по размеру.
- Класс: функция — копия другой функции того же пакета, тела отличаются одним выражением (его надо было сделать параметром).
- Намерение: новое правило duplication near-duplicate-func на нормализаторе renamed_block.go; TDD; прогон по потребителям; установка.


## Журнал
- 2026-10-28 10:56 открыт — glint-master
- 2026-10-28 10:56 в работе — glint-master
- 2026-10-28 10:56 note — glint-master: Боец Luna 1028-1056-near-dup-func, worktree near-dup-func, бриф ~/.local/share/glint-history/near-dup-func/brief.md. После: разбор таблицы находок по потребителям, ревью, влитие, install (после или вместе с patterns-split).
- 2026-10-28 11:52 note — glint-master: Раунд 1 (Luna, 54 мин): правило и тесты есть; потребители — 219 находок в 10 проектах, из них glint 180 (58 разных функций). Шум: находка на каждую пару. graft self-check с medium выходит с кодом 0 (182 MEDIUM на дереве). Раунд 2: одна находка на копию, коммит, лог потребителей в ~/.local/share/glint-history/near-dup-func/consumers-r2.log, поиск ложных. 58 функций glint чинить после влития patterns-split.
- 2026-10-28 12:13 note — glint-master: 12:14 ревью раунда 2: поведение принято (находки верные), раунд 3 бойцу — один парный обход вместо трёх, doc-комментарии, max→limit, описание с max_differences, замер на крупнейшем потребителе; бриф ~/.local/share/glint-history/near-dup-func/round3.md
- 2026-10-28 12:24 note — glint-master: 12:27 раунд 3 принят: один парный обход, doc, limit, описание; крупнейший потребитель 1.45 с против 1.39 у renamed-duplicate-block; находки glint 48, потребители 25 (3 пары с разными типами выражений отсеяны). Тест — синтетические имена вместо исходных. Коммит e340d03 в ветке near-dup-func; влить после patterns-split, затем исправить 48 находок glint, находки потребителей — их агентам, install.
- 2026-10-28 12:25 note — glint-master: 12:31 48 находок glint — одна форма: found := false; ast.Inspect(...; ok && pred(x) {found=true}; return !found) с разным предикатом (38 patterns, 2 security, остальное там же). Лечение: `helpers.Contains[T ast.Node](root, match func(T) bool)` в pkg/rules/helpers/ast.go, замена мест — бойцу Luna после влития patterns-split (файлы переезжают).
- 2026-10-28 13:51 note — glint-master: 13:58 ветка near-dup-func синхронизирована на main (30f9e7f). После разбиения находок на glint 17 (сравнение внутри пакета). Боец Luna: общий хелпер в helpers/ast.go и замена всех функций формы found+ast.Inspect по репо; бриф helper-brief.md, мера helper-accept.sh (0 находок, правила те же, graft all). Влитие в main — после, чтобы self-check/tk done glint не встал.
- 2026-10-28 14:04 note — glint-master: 14:08 боец хелпера раунд 1: helpers.ContainsNode[T] + 24 замены, приёмка OK. Ревью: мастер поправил отсечение обхода, откатил вне-задачную правку main.go (SIGPIPE — из-за моей меры grep -q под pipefail, мера исправлена); осталось 28 функций простой формы (simple-form.awk) — раунд 2 (round2.md), мера дополнена. Раунд 1 не закоммичен перед раундом 2 — повтор промаха patterns-split, дальше коммитить зелёное до доводки.
- 2026-10-28 14:13 note — glint-master: 14:20 раунд 2 хелпера принят: 52 замены на helpers.ContainsNode, −256 строк. graft consumers всех правил: расхождения только near-duplicate-func (glint 17 на старом дереве, потребители 25), остальные правила совпали. Влито fc7c730, self-check glint чист. Дальше install и письма агентам потребителей.
