package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// An INSERT ... ON CONFLICT DO NOTHING RETURNING read as one row reports the
// conflict as no rows; a branch taking every error for the conflict masks a
// failed insert with the fallback read.
func TestSQLConflictAnyErrorTakenAsConflict(t *testing.T) {
	ctx := rulestest.GoFile(t, "storage/repo.go", `package storage

func (r *Repo) GetOrCreate(ctx context.Context, wallet string) (*Status, error) {
	status := &Status{Wallet: wallet}
	query := `+"`"+`INSERT INTO sync_status (id, wallet) VALUES ($1, $2)
		ON CONFLICT (wallet) DO NOTHING
		RETURNING *`+"`"+`
	err := r.db.GetContext(ctx, status, query, status.ID, wallet)
	if err != nil {
		log.Debug("insert conflict, fetching existing", "error", err)
		return r.Get(ctx, wallet)
	}
	return status, nil
}

func (r *Repo) Claim(ctx context.Context, wallet string) (bool, error) {
	var id string
	if err := r.db.QueryRowContext(ctx, `+"`"+`INSERT INTO claims (wallet) VALUES ($1) ON CONFLICT DO NOTHING RETURNING id`+"`"+`, wallet).Scan(&id); err != nil {
		return false, nil
	}
	return true, nil
}

func (r *Repo) GetOrCreateChecked(ctx context.Context, wallet string) (*Status, error) {
	status := &Status{Wallet: wallet}
	err := r.db.GetContext(ctx, status, `+"`"+`INSERT INTO sync_status (id, wallet) VALUES ($1, $2) ON CONFLICT (wallet) DO NOTHING RETURNING *`+"`"+`, status.ID, wallet)
	if errors.Is(err, sql.ErrNoRows) {
		return r.Get(ctx, wallet)
	}
	if err != nil {
		return nil, fmt.Errorf("create sync status: %w", err)
	}
	return status, nil
}

func (r *Repo) CreatePropagated(ctx context.Context, wallet string) (*Status, error) {
	status := &Status{Wallet: wallet}
	err := r.db.GetContext(ctx, status, `+"`"+`INSERT INTO sync_status (id, wallet) VALUES ($1, $2) ON CONFLICT (wallet) DO NOTHING RETURNING *`+"`"+`, status.ID, wallet)
	if err != nil {
		return nil, fmt.Errorf("create sync status: %w", err)
	}
	return status, nil
}

func (r *Repo) Create(ctx context.Context, wallet string) (*Status, error) {
	status := &Status{Wallet: wallet}
	err := r.db.GetContext(ctx, status, `+"`"+`INSERT INTO sync_status (id, wallet) VALUES ($1, $2) RETURNING *`+"`"+`, status.ID, wallet)
	if err != nil {
		return r.Get(ctx, wallet)
	}
	return status, nil
}
`)
	assert.Equal(t, []int{9, 18}, sqlRuleLines(t, NewSQLConflictErrorTakenAsConflictRule(), ctx))
}

func TestSQLConflictErrorTakenAsConflictRule_Metadata(t *testing.T) {
	rule := NewSQLConflictErrorTakenAsConflictRule()
	assert.Equal(t, "sql-conflict-error-taken-as-conflict", rule.Name())
	assert.Equal(t, core.SeverityHigh, rule.DefaultSeverity())
}
