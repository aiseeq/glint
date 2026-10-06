package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// The audit record of a money action written after the action's transaction
// commits, with its failure only logged, leaves the action done without its
// audit entry.
func TestAuditWrittenAfterTransaction(t *testing.T) {
	assert.Equal(t, []string{"payout/admin.go:39", "payout/admin.go:51"}, typedFuncFindings(t, NewAuditWrittenAfterTransactionRule(), map[string]string{
		"payout/admin.go": `package payout

import (
	"context"
	"log"
)

type Repos struct{}

func (r *Repos) RunInTx(ctx context.Context, fn func(ctx context.Context) error) error { return fn(ctx) }

func (r *Repos) WithAccountLock(ctx context.Context, userID string, fn func(ctx context.Context) error) error {
	return fn(ctx)
}

type AuditRepo struct{}

func (a *AuditRepo) Record(ctx context.Context, action string) error { return nil }

type Service struct {
	repos *Repos
	audit *AuditRepo
}

func (s *Service) recordLedgerAudit(ctx context.Context, action string) {
	if err := s.audit.Record(ctx, action); err != nil {
		log.Printf("audit failed: %v", err)
	}
}

func (s *Service) complete(ctx context.Context, id string) error { return nil }

func (s *Service) Complete(ctx context.Context, id string) error {
	if err := s.repos.RunInTx(ctx, func(ctx context.Context) error {
		return s.complete(ctx, id)
	}); err != nil {
		return err
	}
	s.recordLedgerAudit(ctx, "completed")
	return nil
}

func (s *Service) Reject(ctx context.Context, id, userID string) error {
	err := s.repos.WithAccountLock(ctx, userID, func(ctx context.Context) error {
		return s.complete(ctx, id)
	})
	if err != nil {
		return err
	}
	_ = s.audit.Record(ctx, "audit")
	s.recordLedgerAudit(ctx, "rejected")
	return nil
}

func (s *Service) CompleteAudited(ctx context.Context, id string) error {
	return s.repos.RunInTx(ctx, func(ctx context.Context) error {
		if err := s.complete(ctx, id); err != nil {
			return err
		}
		return s.audit.Record(ctx, "completed")
	})
}

func (s *Service) CompleteNoTx(ctx context.Context, id string) error {
	if err := s.complete(ctx, id); err != nil {
		return err
	}
	s.recordLedgerAudit(ctx, "completed")
	return nil
}
`,
	}))
}
