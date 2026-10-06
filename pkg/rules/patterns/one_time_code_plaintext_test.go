package patterns

import "testing"

// A one-time code stored as it was sent is readable by whoever reads the
// table, a dump or a backup, and works for them until it expires. A digest
// of the code, or a column that is not a credential, is fine.
func TestOneTimeCodeStoredPlaintext(t *testing.T) {
	assertWanted(t, NewOneTimeCodeStoredPlaintextRule(), `package repo

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"time"
)

type Repo struct{ db *sql.DB }

func (r *Repo) CreatePairCode(ctx context.Context, userID, code string, expiresAt time.Time) error {
	_, err := r.db.ExecContext(ctx, // want
		`+"`"+`
		INSERT INTO link_codes (code, user_id, expires_at)
		VALUES ($1, $2, $3)
	`+"`"+`, code, userID, expiresAt)
	return err
}

func digest(code string) string {
	sum := sha256.Sum256([]byte(code))
	return hex.EncodeToString(sum[:])
}

func (r *Repo) CreateHashed(ctx context.Context, userID, code string, expiresAt time.Time) error {
	_, err := r.db.ExecContext(ctx, `+"`"+`
		INSERT INTO link_codes (code, user_id, expires_at)
		VALUES ($1, $2, $3)
	`+"`"+`, digest(code), userID, expiresAt)
	return err
}

func (r *Repo) CreateOffer(ctx context.Context, currencyCode string, rate string, expiresAt time.Time) error {
	_, err := r.db.ExecContext(ctx, `+"`"+`
		INSERT INTO quotes (currency_code, rate, expires_at)
		VALUES ($1, $2, $3)
	`+"`"+`, currencyCode, rate, expiresAt)
	return err
}

func (r *Repo) CreateSession(ctx context.Context, userID, token string) error {
	_, err := r.db.ExecContext(ctx, `+"`"+`INSERT INTO audit (token, user_id) VALUES ($1, $2)`+"`"+`, token, userID)
	return err
}
`)
}
