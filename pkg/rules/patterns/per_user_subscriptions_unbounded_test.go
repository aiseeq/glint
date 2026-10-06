package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// A Subscribe that appends a stream to a user's list with no cap lets one
// client open any number of streams.
func TestPerUserSubscriptionsUnbounded(t *testing.T) {
	assert.Equal(t, []string{"events/events.go:32"}, typedFuncFindings(t, NewPerUserSubscriptionsUnboundedRule(), map[string]string{
		"events/events.go": `package events

import (
	"context"
	"errors"
	"log"
	"sync"
)

const maxPerUser = 10

var errTooMany = errors.New("too many subscriptions")

type Event struct{ ID string }

type Subscriber struct {
	Channel chan *Event
	Cancel  context.CancelFunc
}

type Manager struct {
	mu          sync.Mutex
	subscribers map[string][]*Subscriber
	handlers    map[string][]func(Event)
}

func (m *Manager) Subscribe(ctx context.Context, userID string) *Subscriber {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, cancel := context.WithCancel(ctx)
	sub := &Subscriber{Channel: make(chan *Event, 10), Cancel: cancel}
	m.subscribers[userID] = append(m.subscribers[userID], sub)
	log.Printf("subscribers of %s: %d", userID, len(m.subscribers[userID]))
	return sub
}

func (m *Manager) SubscribeCapped(ctx context.Context, userID string) (*Subscriber, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.subscribers[userID]) >= maxPerUser {
		return nil, errTooMany
	}
	sub := &Subscriber{Channel: make(chan *Event, 10)}
	m.subscribers[userID] = append(m.subscribers[userID], sub)
	return sub, nil
}

func (m *Manager) SubscribeTopic(topic string, handler func(Event)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.handlers[topic] = append(m.handlers[topic], handler)
}
`,
	}))
}
