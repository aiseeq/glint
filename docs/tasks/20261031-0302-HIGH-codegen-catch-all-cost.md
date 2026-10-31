# codegen-catch-all-type-without-report: checked words only for generator files, single pass

Статус: готово
Исполнитель: glint-master

## Вход
- Сон, обход design 31.10 (dream-master 03:01 CET): правило 0 находок у 22 потребителей, 38 с CPU в сумме; первое по времени в потребителе sc2demu (15,1 с при analyze 20,4 с) и потребителе В (6,8 с). Данные: /home/aisee/.cache/claude-tmp/claude-1000/-home-aisee-git-dream/7ec55eed-b598-4b5f-aa2e-096523183ece/scratchpad/rule-cost.tsv
- Проверено: pkg/rules/patterns/gorules/codegen_catch_all_type_without_report.go AnalyzeGoProject — checkedCatchAllWords по всем пакетам до фильтра isTypeGeneratorFile; isCheckedLiteral обходит весь файл на каждый строковый литерал (литералы × узлы).
- Ждёт агент: шаг glint в гейте потребителей.

## Что сделать
1. Слова считать лениво: только у пакета, где есть файл-генератор (импорт go/ast, go/types, reflect, x/tools/go/packages).
2. Проверенные литералы — одним обходом файла (аргументы regexp.*/strings.Contains|Index, операнды ==), без обхода на литерал.

## Приёмка
- Тесты правила зелёные; находки правила на потребителях до/после совпадают.
- `glint check --timing` правила на sc2demu и потребителе В: было → стало.

## Журнал
- 2026-10-31 03:02 открыт — glint-master
- 2026-10-31 03:22 в работе — glint-master
- 2026-10-31 03:22 note — glint-master: правка: слова только у пакетов с файлом-генератором, проверенные литералы одним обходом (checkedOperands). Тесты правила 9/9. -r правила --timing: потребитель В 5.3 s → 7 ms (glint check 6.39 → 1.97 s wall), sc2demu 6.2 s → 11 ms (6.85 → 2.10 s); bin/consumers -r правила: 21 проект, 0 различий
- 2026-10-31 04:09 готово — opus-check (session glint-master): суб-агент Opus сессии glint-master (свежий контекст, бриф из тикета): эквивалентность по диффу 4ebc28d и синтетика /home/aisee/.cache/claude-tmp/verify-codegen/proj (3 пакета: слово в соседнем файле, ==, литералы в скобках) — находки старого и нового бинаря идентичны; go test -run CodegenCatchAll ok; --no-cache --timing под graft exec --heavy: потребитель В 7.0/7.1 s → 27/10 ms (check 8.06/8.38 → 1.59/1.17 s), glint 2.2 s → 143 ms, находки 0 → 0. Мастер: sc2demu 6.2 s → 11 ms; bin/consumers 21 проект, 0 различий
