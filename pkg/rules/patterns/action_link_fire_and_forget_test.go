package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// A message carrying a cancel link sent from a goroutine with its failure
// only logged is lost on a mail outage: the user never gets the link.
func TestActionLinkSentFireAndForget(t *testing.T) {
	assert.Equal(t, []string{"notify/router.go:38", "notify/router.go:44"}, typedFuncFindings(t, NewActionLinkSentFireAndForgetRule(), map[string]string{
		"notify/router.go": `package notify

import (
	"context"
	"log/slog"
)

type Mailer struct{}

func (m *Mailer) SendCancelLink(to, link string) error { return nil }
func (m *Mailer) SendReceipt(to string) error         { return nil }

type Outbox struct{}

func (o *Outbox) Enqueue(ctx context.Context, to, token string) error { return nil }

type Router struct {
	mailer *Mailer
	outbox *Outbox
	logger *slog.Logger
}

func Go(name string, fn func()) { go fn() }

func (r *Router) sendCancelEmail(to, cancelToken string) {
	if err := r.mailer.SendCancelLink(to, "https://example.test/cancel?t="+cancelToken); err != nil {
		r.logger.Error("cancel email failed", "error", err)
	}
}

func (r *Router) sendReceipt(to string) {
	if err := r.mailer.SendReceipt(to); err != nil {
		r.logger.Error("receipt failed", "error", err)
	}
}

func (r *Router) Created(to, cancelToken string) {
	Go("cancel-email", func() {
		r.sendCancelEmail(to, cancelToken)
	})
	Go("receipt", func() {
		r.sendReceipt(to)
	})
	go r.sendCancelEmail(to, cancelToken)
}

func (r *Router) Queued(ctx context.Context, to, cancelToken string) error {
	return r.outbox.Enqueue(ctx, to, cancelToken)
}
`,
	}))
}
