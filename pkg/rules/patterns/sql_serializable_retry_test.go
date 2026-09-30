package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// PostgreSQL aborts one of two overlapping SERIALIZABLE transactions with
// 40001 and expects the application to run it again.
func TestSQLSerializableNoRetry(t *testing.T) {
	files := map[string]string{
		"storage/sessions.go": `package storage

func (r *Repo) Create(ctx context.Context) error {
	tx, err := r.db.BeginTxx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
	return err
}

func (r *Repo) Snapshot(ctx context.Context) error {
	tx, err := r.db.BeginTxx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return err
	}
	return tx.Commit()
}
`,
		"ledger/post.go": `package ledger

func (r *Repo) Post(ctx context.Context) error {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}
`,
		"ledger/retry.go": `package ledger

func serializationConflict(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "40001"
}
`,
	}
	root, _ := rulestest.Module(t, files)
	contexts, errs := core.NewWalker(root, core.DefaultConfig()).WalkSync()
	require.Empty(t, errs)
	rule := NewSQLSerializableNoRetryRule()
	rule.UseProjectFiles(contexts)
	var violations []*core.Violation
	for _, ctx := range contexts {
		violations = append(violations, rule.AnalyzeFile(ctx)...)
	}
	assert.Equal(t, []string{"storage/sessions.go:4", "storage/sessions.go:8"}, foundLines(violations))
}
