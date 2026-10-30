# clock-bypass с clock_package: NOW() во фрагментах SQL, собираемых кодом (Sprintf-шаблон, аргумент функции, append фрагмента)

Статус: в работе
Исполнитель: glint-master

## Вход
- Запрос: мастер потребителя А 30.10 ~04:35 CET; у потребителя 4 места, чинит сам.
- Пропуски: шаблон fmt.Sprintf `… effective_from <= NOW() AND %[2]s …`; аргумент `membershipSQL("m", "NOW()")`; `updates = append(updates, "updated_at = NOW()")`.
- Сейчас SQL-проверка clock-bypass смотрит только patternkit.SqlLiterals (текст, начинающийся с ключевого слова SQL).

## Что сделать
- В модуле с clock_package — и фрагменты: строковые литералы с NOW()/CURRENT_TIMESTAMP/LOCALTIMESTAMP/CURRENT_DATE, которые идут в SQL: шаблон Sprintf, аргумент вызова, элемент append/слайса, склейка.

## Приёмка
- scratchpad accept-clock-composed.sh — код 0; три положительных случая выше; строка "NOW()" в сообщении лога/ошибки — без находки; graft consumers — каждая находка разобрана.

## Журнал
- 2026-10-30 06:04 открыт — glint-master
- 2026-10-30 06:13 в работе — glint-master
- 2026-10-30 06:14 note — glint-master: 06:14 CET боец 1030-0614-clock-composed-sql (luna), бриф brief-clock-composed.md, приёмка accept-clock-composed.sh, фикстура clockfrag-fixture (до правки 0 находок)
- 2026-10-30 06:34 note — glint-master: 06:5x CET боец сдал: 4 новые находки у потребителя А — ровно названные им места (fund_transfer:349, tariff_group:718/722, vault_snapshot:196); мастер свёл isStringType/expressionContains на patternkit.IsStringType/ContainsNode; повтор приёмки
