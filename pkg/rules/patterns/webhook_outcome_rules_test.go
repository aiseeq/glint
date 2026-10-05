package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

const webhookService = `package hooks

import (
	"errors"
	"log/slog"
)

type UnsupportedStatusError struct{ Status string }

func (e *UnsupportedStatusError) Error() string { return "unsupported " + e.Status }

type Payload struct {
	Ref    string
	Status string
}

type Service struct{ logger *slog.Logger }

func (s *Service) Observe(p Payload) (string, error) {
	if p.Status == "" {
		return "", errors.New("empty")
	}
	return p.Status, nil
}

func (s *Service) Handle(p Payload, raw []byte) error { return nil }

func (s *Service) RecordFailure(ref string, raw []byte, err error) {}

func (s *Service) logUnknownStatus(p Payload) { s.logger.Warn("unknown status", "status", p.Status) }

func mapStatus(status string) string {
	if status == "done" {
		return "COMPLETED"
	}
	return ""
}

// HandleWebhook applies a provider's status update.
func (s *Service) HandleWebhook(p Payload, raw []byte) error {
	newStatus := mapStatus(p.Status)
	if newStatus == "" {
		s.logUnknownStatus(p)
		return nil
	}
	return s.Handle(p, raw)
}

// HandleUpdate is not a webhook entry point.
func (s *Service) HandleUpdate(p Payload) error {
	newStatus := mapStatus(p.Status)
	if newStatus == "" {
		s.logUnknownStatus(p)
		return nil
	}
	return nil
}
`

const webhookHandlers = `package api

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"

	"example.com/rulestest/hooks"
)

type webhookHandler struct {
	svc    *hooks.Service
	logger *slog.Logger
}

func (h *webhookHandler) handleWebhook(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var payload hooks.Payload
	if err := json.Unmarshal(body, &payload); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if _, err := h.svc.Observe(payload); err != nil {
		h.logger.Warn("invalid observation", "error", err)
		var unsupported *hooks.UnsupportedStatusError
		if errors.As(err, &unsupported) {
			w.WriteHeader(http.StatusUnprocessableEntity)
			return
		}
		h.svc.RecordFailure(payload.Ref, body, err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if err := h.svc.Handle(payload, body); err != nil {
		h.logger.Error("webhook processing failed", "error", err)
		// still 200: the provider must not retry
	}
	w.WriteHeader(http.StatusOK)
}

func (h *webhookHandler) handleCallback(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var payload hooks.Payload
	if _, err := h.svc.Observe(payload); err != nil {
		h.svc.RecordFailure(payload.Ref, body, err)
		var unsupported *hooks.UnsupportedStatusError
		if errors.As(err, &unsupported) {
			w.WriteHeader(http.StatusUnprocessableEntity)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if err := h.svc.Handle(payload, body); err != nil {
		h.logger.Error("callback processing failed", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func stats(w http.ResponseWriter, svc *hooks.Service, logger *slog.Logger) {
	if err := svc.Handle(hooks.Payload{}, nil); err != nil {
		logger.Error("stats failed", "error", err)
	}
	w.WriteHeader(http.StatusOK)
}
`

func webhookFiles() map[string]string {
	return map[string]string{"hooks/service.go": webhookService, "api/webhooks.go": webhookHandlers}
}

// A webhook whose processing failed is answered 200, and a processing step
// that does not know the status answers nil: the provider does not send the
// update again and it is lost.
func TestWebhookProcessingErrorAcknowledged(t *testing.T) {
	assert.Equal(t, []string{"api/webhooks.go:40", "hooks/service.go:42"},
		typedFuncFindings(t, NewWebhookProcessingErrorAcknowledgedRule(), webhookFiles()))
}

// One failure branch of a webhook stores the raw body, and a branch before it
// in the same failure answers 4xx and returns: the provider does not retry a
// 4xx, and that update is gone without a trace.
func TestWebhookEvidenceNotPersistedBefore4xx(t *testing.T) {
	assert.Equal(t, []string{"api/webhooks.go:36"},
		typedFuncFindings(t, NewWebhookEvidenceNotPersistedBefore4xxRule(), webhookFiles()))
}

const tokenCacheSource = `package secrets

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"
)

type TokenSource interface {
	Token(ctx context.Context) (string, error)
}

type LoginSource struct {
	mu      sync.Mutex
	token   string
	expires time.Time
}

func (a *LoginSource) Token(ctx context.Context) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.token != "" && time.Now().Before(a.expires) {
		return a.token, nil
	}
	if err := a.login(ctx); err != nil {
		a.token, a.expires = "", time.Time{}
		return "", err
	}
	return a.token, nil
}

func (a *LoginSource) login(ctx context.Context) error {
	a.token, a.expires = "t", time.Now().Add(time.Hour)
	return nil
}

type Encryptor struct {
	tokens TokenSource
	client *http.Client
}

func (v *Encryptor) call(ctx context.Context, path string, body []byte) error {
	token, err := v.tokens.Token(ctx)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("X-Token", token)
	resp, err := v.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("answered %d", resp.StatusCode)
	}
	return nil
}
`

const tokenCacheInvalidated = `package oauth

import (
	"context"
	"net/http"
	"time"
)

type Cache struct {
	accessToken string
	expiresAt   time.Time
}

func (c *Cache) Token(ctx context.Context) (string, error) {
	if time.Now().Before(c.expiresAt) {
		return c.accessToken, nil
	}
	c.accessToken, c.expiresAt = "fresh", time.Now().Add(time.Hour)
	return c.accessToken, nil
}

func (c *Cache) Invalidate() {
	c.accessToken = ""
}

type API struct {
	cache  *Cache
	client *http.Client
}

func (a *API) Get(ctx context.Context, url string) error {
	token, err := a.cache.Token(ctx)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		a.cache.Invalidate()
	}
	return nil
}
`

// A cached token with an expiry and no way to drop it: when the server revokes
// it early, every call fails with 401 until the local clock runs out.
func TestCachedTokenNotInvalidatedOnAuthFailure(t *testing.T) {
	assert.Equal(t, []string{"secrets/client.go:46"}, typedFuncFindings(t, NewCachedTokenNotInvalidatedRule(), map[string]string{
		"secrets/client.go": tokenCacheSource,
		"oauth/oauth.go":    tokenCacheInvalidated,
	}))
}
