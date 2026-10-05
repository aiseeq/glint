package helpers

// SQLMethods are the methods of a database handle that run or prepare SQL.
var SQLMethods = []string{
	"Query", "QueryRow", "QueryContext", "QueryRowContext",
	"Exec", "ExecContext", "Prepare", "PrepareContext",
	"Begin", "BeginTx",
}

// SQLPingMethods are the methods of a database handle that check the
// connection.
var SQLPingMethods = []string{"Ping", "PingContext"}
