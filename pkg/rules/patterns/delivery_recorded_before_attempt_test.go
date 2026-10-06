package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// A dispatch that records "email" as the delivery and returns false, so that
// its caller then sends the email, has recorded a delivery that may never
// happen: with the mail down too, the journal says the alert went out.
func TestDeliveryRecordedBeforeAttempt(t *testing.T) {
	assert.Equal(t, []string{"alerts/service.go:31"}, typedFuncFindings(t, NewDeliveryRecordedBeforeAttemptRule(), map[string]string{
		"alerts/service.go": `package alerts

type Journal struct{}

func (j *Journal) SetDelivery(id, channel string, delivered int) error { return nil }

type Bot struct{}

func (b *Bot) Dispatch(text string) (int, error) { return 0, nil }

type Service struct {
	journal *Journal
	bot     *Bot
}

func (s *Service) setDelivery(id, channel string, delivered int) {
	_ = s.journal.SetDelivery(id, channel, delivered)
}

func (s *Service) sendEmail(text string) error { return nil }

func (s *Service) dispatch(id, text string) bool {
	delivered, err := s.bot.Dispatch(text)
	if err != nil {
		delivered = 0
	}
	if delivered > 0 {
		s.setDelivery(id, "bot", delivered)
		return true
	}
	s.setDelivery(id, "email", 0)
	return false
}

func (s *Service) Alert(id, text string) error {
	if s.dispatch(id, text) {
		return nil
	}
	return s.sendEmail(text)
}

func (s *Service) dispatchHonest(id, text string) bool {
	delivered, _ := s.bot.Dispatch(text)
	if delivered > 0 {
		s.setDelivery(id, "bot", delivered)
		return true
	}
	return false
}

func (s *Service) AlertHonest(id, text string) error {
	if s.dispatchHonest(id, text) {
		return nil
	}
	if err := s.sendEmail(text); err != nil {
		return err
	}
	s.setDelivery(id, "email", 1)
	return nil
}
`,
	}))
}
