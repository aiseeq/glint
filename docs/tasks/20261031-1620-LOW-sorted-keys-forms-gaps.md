# reimplemented-stdlib sorted keys: named and int64 key types, inline blocks, advice names the real map

Статус: открыт

## Что сделать
- Пропуски, найденные проверкой Opus 31.10 16:13 тикета reimplemented-stdlib-sorted-keys (пробы /home/aisee/.cache/claude-tmp/claude-1000/-home-aisee-git-glint/verify-sorted/m123edge/edge.go):
  - E2/E3: тип ключа только string/int — `map[int64]`, `type ID int` не ловятся (любой cmp.Ordered);
  - E1 `for k, _ := range m`; E4 именованный результат; E5 `sort.Sort(sort.StringSlice(keys))`;
  - блок «собрать ключи и отсортировать» внутри длинной функции (в glint ~15: cmd/glint/main.go:1873, pkg/core/go_project.go:381, pkg/rules/registry.go:163) — решить, ловить ли, по прогону потребителей;
  - совет пишет `slices.Sorted(maps.Keys(m))` с буквальным `m`, а не с выражением map (`s.items`).

## Приёмка
- TDD-кейсы на каждый пункт; bin/consumers разобран до установки; graft all зелёный.

## Журнал
- 2026-10-31 16:20 открыт — glint-master
