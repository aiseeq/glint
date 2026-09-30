package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// The user is committed, the wallet is added after: when adding it fails,
// the caller gets an error for a user that exists without a wallet.
func TestTxWriteAfterCommit(t *testing.T) {
	assert.Equal(t, []int{16, 35}, sqlFileRuleLines(t, NewTxWriteAfterCommitRule(), "service/signup.go", `package service

func (s *Service) SignUp(ctx context.Context, email, address string) (*User, error) {
	tx, err := s.db.BeginTxx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	user, err := s.users.CreateInTx(ctx, tx, email)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	if err := s.wallets.AddOwnedAddress(ctx, user.ID, address); err != nil {
		return nil, fmt.Errorf("user created without a wallet: %w", err)
	}
	s.audit.RecordSignup(ctx, user.ID)
	if err := s.cache.Invalidate(ctx, email); err != nil {
		return nil, err
	}
	return user, nil
}

func (s *Service) Rename(ctx context.Context, id, name string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	if _, err := tx.Exec("UPDATE users SET name = $1 WHERE id = $2", name, id); err != nil {
		return err
	}
	err = tx.Commit()
	_, err = s.db.Exec("UPDATE profiles SET name = $1 WHERE user_id = $2", name, id)
	if err != nil {
		return err
	}
	if err := s.events.PublishRenamed(ctx, id); err != nil {
		s.log.Warn("rename event", err)
	}
	return nil
}

func (s *Service) Notify(ctx context.Context, id string) error {
	if err := s.repo.Commit(); err != nil {
		return err
	}
	return s.mail.SendWelcome(ctx, id)
}
`))
}
