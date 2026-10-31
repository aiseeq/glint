# reimplemented-stdlib: sorted map keys by hand instead of slices.Sorted(maps.Keys(m))

Статус: на проверке
Исполнитель: glint-master

## Вход
- Пилот duplicate-func-across-packages на graft 31.10 (graft-master): копии sortedKeys/sortedNames лучше всего чинятся не одной реализацией, а стандартной `slices.Sorted(maps.Keys(m))` (Go ≥ 1.23) — 12 мест вызова заменены. Та же форма — в dream (исправлено), sc2demu (sortedGameNames, sortedCohorts, sortedKeys) и была в самом glint (core.SortedKeys).
- Проба /home/aisee/.cache/worktrees/glint-measure/probe-sorted-keys: функция make → range keys → append → sort.Strings → return — reimplemented-stdlib молчит.

## Что сделать

## Приёмка
- Проба даёт 1 находку; отрицательные — 0; bin/consumers разобран; в glint нет своей SortedKeys.

## Что сделать (glint-gap)
1. TDD в reimplemented-stdlib: тело «собрать ключи map в срез и отсортировать» (sort.Strings / sort.Ints / slices.Sort / sort.Slice с a[i] < a[j]) при go ≥ 1.23 в go.mod — находка с подсказкой `slices.Sorted(maps.Keys(m))`; autofix — если правило его умеет для других форм.
2. Отрицательные: go < 1.23; сортировка с другим компаратором; ключи с фильтром в цикле.
3. Сам glint: core.SortedKeys заменить стандартным вызовом.
4. Прогон по потребителям до установки.


## Журнал
- 2026-10-31 11:53 открыт — glint-master
- 2026-10-31 11:56 в работе — glint-master
- 2026-10-31 11:56 note — glint-master: боец Luna 1031-1156-reimplemented-stdlib-sorted-keys (glint-правило): бриф /home/aisee/.cache/worktrees/glint-measure/brief-reimplemented-stdlib-sorted-keys.md, приёмка accept-reimplemented-stdlib-sorted-keys.sh там же, дерево /home/aisee/.cache/worktrees/glint/reimplemented-stdlib-sorted-keys
- 2026-10-31 14:00 note — glint-master: влито c325738 (мастер: тело ровно 4 оператора + отрицательный тест), своя копия glint mapKeys убрана 48cf2cf, совет «every call site» по замечанию пилота 07c9ffa; bin/consumers -r reimplemented-stdlib: +21 в 10 проектах, все верны; установлено v1.83.7-206/208; пилот graft-master: верно, исправлено graft 427b281; разослано aguard, llmark, demu, sc2go и четырём рабочим потребителям (все приняли, рабочие — пн 02.11)
- 2026-10-31 14:00 на проверке — glint-master
