# sql-injection: a check after the query clears the parameter before it

Статус: в работе
Исполнитель: glint-master

## Что сделать
- Находка критика описания glint «как сделано» (тикет 20261031-1600-MEDIUM-spec-as-built): проверки параметра собираются по всему файлу (pkg/rules/security/sql_query_taint.go:97,126) без порядка относительно запроса; проверка после db.Query (late, main.go:27–30) снимает находку.
- TDD-репро по пробе ниже (синтетический код), затем фикс правила.

Проба (модуль `example.com/probe`, go 1.23; строки пронумерованы):

```go
// main.go
 1 package probe
 2 
 3 import (
 4 	"crypto/tls"
 5 	"database/sql"
 6 	"net/http"
 7 )
 8 
 9 type Options struct{ InsecureSkipVerify bool }
10 
11 func config() {
12 	c := &tls.Config{}
13 	c.InsecureSkipVerify = true
14 	_ = c
15 	_ = Options{InsecureSkipVerify: true}
16 	_ = &tls.Config{InsecureSkipVerify: true}
17 }
18 
19 func direct(db *sql.DB, user string) { db.Query("SELECT * FROM users WHERE name='" + user + "'") }
20 
21 func handler(db *sql.DB, r *http.Request) {
22 	user := r.URL.Query().Get("name")
23 	db.Query("SELECT * FROM users WHERE name='" + user + "'")
24 }
25 
26 func late(db *sql.DB, user string) {
27 	db.Query("SELECT * FROM users WHERE name='" + user + "'")
28 	if user != "admin" {
29 		return
30 	}
31 }
32 
33 func isBlocked(s string) bool { return s == "blocked" }
34 
35 func blacklist(db *sql.DB, user string) {
36 	if isBlocked(user) {
37 		return
38 	}
39 	db.Query("SELECT * FROM users WHERE name='" + user + "'")
40 }
41 
42 func isKnownColumn(s string) bool { return s == "name" || s == "email" }
43 
44 func whitelist(db *sql.DB, column string) {
45 	if !isKnownColumn(column) {
46 		return
47 	}
48 	db.Query("SELECT " + column + " FROM users")
49 }
```

```js
// client.js
 1 const a = { rejectUnauthorized: false };
 2 const b = { "rejectUnauthorized": false };
 3 const c = "rejectUnauthorized: false";
```

## Приёмка
- `-r sql-injection`: есть main.go:27; main.go:19 остаётся; белый список до запроса (main.go:48) — без находки (сейчас `glint check -C <проба> -r sql-injection --no-cache ./...` даёт только main.go:19).
- Прогон bin/consumers по правилу до установки, каждая новая находка разобрана; graft all зелёный.

## Журнал
- 2026-10-31 17:44 открыт — glint-master
- 2026-10-31 20:14 в работе — glint-master
- 2026-10-31 20:14 note — glint-master: боец Luna 1031-2014-sec-sql (вместе F1+F2): бриф glint-measure/security/brief-sql.md, приёмка glint-measure/security/accept-sql.sh (гейт, тесты security, проба: 19, 27, 39 есть, 48 нет), дерево sec-sql
- 2026-10-31 20:47 note — glint-master: ревью 1031-2014-sec-sql (1-й заход): 3 новых ложных на probe-sql2 (comma-ok map в init if — 14; проверка во внешнем блоке, запрос в for — 22, в if — 31), регексп ^a|.*$ принят якорным (41 не найдена); strconv.Unquote (self-check install), Inspect всего файла на каждый запрос/проверку. Приёмка accept-sql.sh дополнена probe-sql2; боец возвращён
- 2026-10-31 21:04 note — glint-master: ревью 2-го захода sec-sql: probe-sql2 чист (только 41). Остались: self-check (сложность/вложенность collect, type-assertion :147, error-masked-as-false-bool в anchoredRegexp) — install откажет; OpBeginLine/OpEndLine приняты как якорь, (?m)^[a-z_]+$ пропускает перевод строки (probe-sql2:50). Приёмка дополнена self-check и строкой 50; боец возвращён
