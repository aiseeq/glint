# tls-verification-disabled (Go): assignment missed, a foreign struct field reported

Статус: в работе
Исполнитель: glint-master

## Что сделать
- Находка критика описания glint «как сделано» (тикет 20261031-1600-MEDIUM-spec-as-built): pkg/rules/security/tls_verification_disabled.go:57 смотрит только ключи литералов по имени без типа: присваивание c.InsecureSkipVerify = true (main.go:13) пропущено, Options{InsecureSkipVerify: true} (main.go:15) — ложная HIGH.
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
- `-r tls-verification-disabled`: есть main.go:13 и main.go:16 (литерал tls.Config), нет main.go:15 (сейчас `-r tls-verification-disabled` даёт client.js:1, client.js:3, main.go:15, main.go:16).
- Прогон bin/consumers по правилу до установки, каждая новая находка разобрана; graft all зелёный.

## Журнал
- 2026-10-31 17:44 открыт — glint-master
- 2026-10-31 20:14 в работе — glint-master
- 2026-10-31 20:14 note — glint-master: боец Luna 1031-2014-sec-tls (F4+F5): бриф glint-measure/security/brief-tls.md, приёмка glint-measure/security/accept-tls.sh, дерево sec-tls
