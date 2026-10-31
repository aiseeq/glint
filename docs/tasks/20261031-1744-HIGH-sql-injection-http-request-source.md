# sql-injection: a value from the HTTP request is not a taint source

Статус: готово
Исполнитель: glint-master

## Что сделать
- Находка критика описания glint «как сделано» (тикет 20261031-1600-MEDIUM-spec-as-built): pkg/rules/security/sql_query_taint.go:403,413 — результат вызова не прослеживается; значение из r.URL.Query().Get (handler, main.go:21–24) не источник. Охват: также FormValue, PostFormValue, PathValue, Header.Get, Cookie — тест на каждый.
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
- `-r sql-injection`: есть main.go:23; main.go:19 остаётся (сейчас `glint check -C <проба> -r sql-injection --no-cache ./...` даёт только main.go:19).
- Прогон bin/consumers по правилу до установки, каждая новая находка разобрана; graft all зелёный.

## Журнал
- 2026-10-31 17:44 открыт — glint-master
- 2026-10-31 20:14 note — glint-master: очередь: после влития sec-sql (тот же sql_query_taint.go)
- 2026-10-31 21:29 в работе — glint-master
- 2026-10-31 21:29 note — glint-master: боец Luna: бриф /home/aisee/.cache/worktrees/glint-measure/security/brief-http.md, приёмка accept-http.sh, проба probe-http (нужны 11 15 20 25 30, не 34 42 50), дерево /home/aisee/.cache/worktrees/glint/sec-http
- 2026-10-31 21:40 note — glint-master: влито d785423 (боец 1031-2129-sec-http, 1 заход): источники по go/types — *http.Request FormValue/PostFormValue/PathValue/Cookie, url.Values.Get, http.Header.Get; accept-http.sh ok (probe 19 23 27 39 не 48; probe-http 11 15 20 25 30 не 34 42 50; probe-sql2 41 50; self-check чист); consumers 20 проектов 0 разниц (consumers-sec-http.txt). Вне охвата: поля r.URL.Path/RawQuery, индексация Query()[k], роутеры сторонних библиотек
- 2026-10-31 21:51 note — glint-master: повторная независимая проверка: Terra 1031-2128-glint, 2-й заход (все 4 sql-тикета), вердикт → /home/aisee/.cache/worktrees/glint-measure/security/verdict-sql.md
- 2026-10-31 21:58 note — glint-master: повторная проверка Terra 1031-2128-glint (2-й заход): вернуть — defer/go closure принята сразу вызываемой (extra.go:15), map изменена через параметр (extra.go:30), url.Values/http.Header из констант и url.ParseQuery — ложные (verify-http :62 :66 :70). check-after-use и any-bool — готово по прямым критериям. 2-й круг: боец Luna, бриф brief-sql-review2.md, приёмка accept-sql-review2.sh, пробы скопированы в security/probe-verify-{sql,http}
- 2026-10-31 22:09 note — glint-master: 2-й круг влит a83e3dd (боец 1031-2158-sql-review2): accept-sql-review2.sh ok (5 проб, self-check чист); тест d785423 «typed values and headers» 2→0 — он закреплял ложные находки; consumers 20 проектов 0 разниц (consumers-sql-review2.txt)
- 2026-10-31 22:16 note — glint-master: проверка Terra 1031-2128-glint 3-й заход: вернуть — defer/go closure без записи после проверки стала ложной (review3.go:5 :9), len(map) снимает конечность (:15), алиас u := r.URL теряет источник (http review3.go:25 :40). Остаток вне охвата: поля структур (http :15 :20), map в пользовательскую функцию только на чтение (sql :28 :46), ^.*$. 3-й круг: боец Luna, brief-sql-review3.md, accept-sql-review3.sh
- 2026-10-31 22:25 note — glint-master: 3-й круг влит 58e1d44 (боец 1031-2216-sql-review3 + glint-master: на ревью найдено переполнение стека в isHTTPRequestURL при цикле присваиваний a = b; b = a — проба security/probe-cycle, тест TestSQLInjectionURLAssignmentCycleEnds, защита visiting как в httpRequestContainer). accept-sql-review3.sh ok; consumers 20 проектов 0 разниц (consumers-sql-review3.txt)
- 2026-10-31 22:34 готово — terra-1031-2128-glint (session glint-master): Terra 1031-2128-glint, 4-й заход: по этому тикету готово (/home/aisee/.cache/worktrees/glint-measure/security/verdict-sql.md: verify-http probe.go и review3.go установленным glint c30105c, циклы присваиваний без падения, go test security ok, consumers 0 разниц). Остаток: поля структур
