package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// providerOutcomeDomain is the entity the provider rules' cases write: a
// status enum with a failure value and an entity that keeps the failure's
// cause.
const providerOutcomeDomain = `package domain

type Status string

const (
	StatusNew      Status = "NEW"
	StatusSent     Status = "SENT"
	StatusError    Status = "ERROR"
	StatusUnknown  Status = "SEND_UNKNOWN"
	StatusCanceled Status = "CANCELED"
)

type Order struct {
	ID           string
	Status       Status
	Version      int
	ErrorCode    string
	ErrorMessage string
}
`

const providerOutcomeRepo = `package storage

import "example.com/rulestest/domain"

type Repo struct{}

func (r *Repo) UpdateStatus(id string, s domain.Status, version int) error { return nil }

func (r *Repo) UpdateStatusWithError(id string, s domain.Status, code, msg string, version int) error {
	return nil
}

func (r *Repo) Save(o *domain.Order) error { return nil }
`

const providerOutcomeClient = `package payprov

type SendResponse struct{ Reference string }

type Client struct{}

func (c *Client) SendTransaction(req string) (*SendResponse, error) { return &SendResponse{}, nil }

func (c *Client) post(path string, body any, dst any) error { return nil }

func (c *Client) CancelTransaction(ref string) error {
	var result bool
	if err := c.post("/cancel", ref, &result); err != nil {
		return err
	}
	return nil
}

func (c *Client) CancelChecked(ref string) error {
	var result bool
	if err := c.post("/cancel", ref, &result); err != nil {
		return err
	}
	if !result {
		return errNotConfirmed
	}
	return nil
}

type confirmError struct{}

func (confirmError) Error() string { return "not confirmed" }

var errNotConfirmed = confirmError{}
`

func providerOutcomeFiles(service string) map[string]string {
	return map[string]string{
		"domain/domain.go":   providerOutcomeDomain,
		"storage/repo.go":    providerOutcomeRepo,
		"payprov/client.go":  providerOutcomeClient,
		"service/service.go": service,
	}
}

// A failure status written while the error reaches only the log: the stored
// order says ERROR and its error fields stay empty, so nobody can tell why.
func TestErrorStatusPersistedWithoutCause(t *testing.T) {
	assert.Equal(t, []string{"service/service.go:20"}, typedFuncFindings(t, NewErrorStatusPersistedWithoutCauseRule(), providerOutcomeFiles(`package service

import (
	"fmt"
	"log/slog"

	"example.com/rulestest/domain"
	"example.com/rulestest/storage"
)

type Service struct {
	repo   *storage.Repo
	logger *slog.Logger
}

func (s *Service) recordError(order *domain.Order, operation string, err error) {
	s.logger.Error("order failed", "id", order.ID, "operation", operation, "error", err)

	// the cause never reaches the row
	if updateErr := s.repo.UpdateStatus(order.ID, domain.StatusError, order.Version); updateErr != nil {
		s.logger.Error("failed to set error status", "error", updateErr)
	}
}

func (s *Service) recordErrorWithCause(order *domain.Order, operation string, err error) {
	s.logger.Error("order failed", "id", order.ID, "error", err)
	if updateErr := s.repo.UpdateStatusWithError(order.ID, domain.StatusError, operation, err.Error(), order.Version); updateErr != nil {
		s.logger.Error("failed to set error status", "error", updateErr)
	}
}

func (s *Service) wrap(order *domain.Order, err error) error {
	_ = s.repo.UpdateStatus(order.ID, domain.StatusError, order.Version)
	return fmt.Errorf("order %s: %w", order.ID, err)
}

func (s *Service) sent(order *domain.Order, err error) {
	s.logger.Info("sent", "error", err)
	_ = s.repo.UpdateStatus(order.ID, domain.StatusSent, order.Version)
}
`)))
}

// Some error returns of one function record the failure on the order and
// others after them do not: the order stays in its old status on those paths.
func TestErrorPathSkipsFailureRecording(t *testing.T) {
	assert.Equal(t, []string{"service/service.go:35", "service/service.go:38"}, typedFuncFindings(t, NewErrorPathSkipsFailureRecordingRule(), providerOutcomeFiles(`package service

import (
	"fmt"
	"strconv"

	"example.com/rulestest/domain"
	"example.com/rulestest/storage"
)

type Service struct {
	repo *storage.Repo
}

func (s *Service) recordError(order *domain.Order, operation string, err error) {
	_ = s.repo.UpdateStatusWithError(order.ID, domain.StatusError, operation, err.Error(), order.Version)
}

func (s *Service) rate(order *domain.Order) (string, error) { return "1", nil }

func (s *Service) Quote(order *domain.Order, raw string) error {
	if _, err := strconv.Atoi(raw); err != nil {
		return fmt.Errorf("bad input: %w", err)
	}
	rate, err := s.rate(order)
	if err != nil {
		s.recordError(order, "get rate", err)
		return fmt.Errorf("get rate: %w", err)
	}
	if rate == "" {
		return fmt.Errorf("empty rate")
	}
	n, err := strconv.Atoi(rate)
	if err != nil {
		return fmt.Errorf("parse rate: %w", err)
	}
	if err := s.repo.Save(order); err != nil {
		return fmt.Errorf("save quote %d: %w", n, err)
	}
	return nil
}

func (s *Service) QuoteAll(order *domain.Order) error {
	rate, err := s.rate(order)
	if err != nil {
		s.recordError(order, "get rate", err)
		return fmt.Errorf("get rate: %w", err)
	}
	if _, err := strconv.Atoi(rate); err != nil {
		s.recordError(order, "parse rate", err)
		return fmt.Errorf("parse rate: %w", err)
	}
	return nil
}
`)))
}

// A helper that answers the HTTP request is no failure recording (the request
// is no entity), a failed claim means another worker holds the order, and the
// recorder's own failure is not the order's.
func TestErrorPathSkipsFailureRecordingLeavesRespondersAndClaims(t *testing.T) {
	assert.Empty(t, typedFuncFindings(t, NewErrorPathSkipsFailureRecordingRule(), providerOutcomeFiles(`package service

import (
	"fmt"
	"net/http"

	"example.com/rulestest/domain"
	"example.com/rulestest/storage"
)

type Service struct {
	repo *storage.Repo
}

func (s *Service) fail(w http.ResponseWriter, r *http.Request, msg string, err error) {
	http.Error(w, msg, http.StatusInternalServerError)
}

func (s *Service) recordError(order *domain.Order, operation string, err error) error {
	return s.repo.UpdateStatusWithError(order.ID, domain.StatusError, operation, err.Error(), order.Version)
}

func (s *Service) claimSend(order *domain.Order) error { return nil }

func (s *Service) context(w http.ResponseWriter, r *http.Request) (string, bool) {
	if err := r.ParseForm(); err != nil {
		s.fail(w, r, "form", err)
		return "", false
	}
	if _, err := r.Cookie("actor"); err != nil {
		return "", false
	}
	return "", true
}

func (s *Service) Send(order *domain.Order) error {
	if err := s.repo.Save(order); err != nil {
		if recErr := s.recordError(order, "save", err); recErr != nil {
			return fmt.Errorf("record: %w", recErr)
		}
		return fmt.Errorf("save: %w", err)
	}
	if err := s.claimSend(order); err != nil {
		return fmt.Errorf("claim: %w", err)
	}
	if recErr := s.recordError(order, "later", fmt.Errorf("x")); recErr != nil {
		return fmt.Errorf("record: %w", recErr)
	}
	return nil
}
`)))
}

// A mapper with no error result that answers "" for every value it does not
// support: the outgoing request goes out without the field the client set.
func TestUnsupportedValueSilentlyDropped(t *testing.T) {
	assert.Equal(t, []string{"service/service.go:26"}, typedFuncFindings(t, NewUnsupportedValueSilentlyDroppedRule(), providerOutcomeFiles(`package service

import "example.com/rulestest/domain"

type Payout struct {
	Country        string
	Method         int
	WalletCurrency string
}

type Request struct {
	WalletCurrency string
	Country        string
}

func walletCurrency(p *Payout) string {
	if p.Country != "CN" {
		return ""
	}
	if p.Method != 5 && p.Method != 16 {
		return ""
	}
	if p.WalletCurrency != "CNY" {
		return ""
	}
	return p.WalletCurrency
}

func label(o *domain.Order) string {
	if o.Status == domain.StatusError {
		return ""
	}
	if o.ErrorCode == "" {
		return ""
	}
	return o.ErrorMessage
}

func build(p *Payout) Request {
	return Request{WalletCurrency: walletCurrency(p), Country: p.Country}
}
`)))
}

// A decoded confirmation flag that nothing reads: the provider answering
// false is taken for success.
func TestProviderSuccessFlagIgnored(t *testing.T) {
	assert.Equal(t, []string{"payprov/client.go:13"}, typedFuncFindings(t, NewProviderSuccessFlagIgnoredRule(), providerOutcomeFiles(`package service
`)))
}

// A send whose failure is stored as a definitive ERROR whatever the error
// was: a timeout after the provider accepted the payout lets the order be
// sent again.
func TestAmbiguousSendFailureRecordedAsFailed(t *testing.T) {
	assert.Equal(t, []string{"service/service.go:34"}, typedFuncFindings(t, NewAmbiguousSendFailureRecordedAsFailedRule(), providerOutcomeFiles(`package service

import (
	"context"
	"errors"
	"fmt"

	"example.com/rulestest/domain"
	"example.com/rulestest/payprov"
	"example.com/rulestest/storage"
)

type recorder struct {
	repo *storage.Repo
}

func (r *recorder) record(order *domain.Order, operation string, err error) {
	_ = r.repo.UpdateStatusWithError(order.ID, domain.StatusError, operation, err.Error(), order.Version)
}

func (r *recorder) recordStatus(order *domain.Order, status domain.Status, err error) {
	_ = r.repo.UpdateStatusWithError(order.ID, status, "send", err.Error(), order.Version)
}

type Service struct {
	provider *payprov.Client
	errors   *recorder
	repo     *storage.Repo
}

func (s *Service) Send(order *domain.Order) error {
	resp, err := s.provider.SendTransaction(order.ID)
	if err != nil {
		s.errors.record(order, "send transaction", err)
		return fmt.Errorf("send: %w", err)
	}
	_ = resp
	return nil
}

func (s *Service) SendUnknown(order *domain.Order) error {
	if _, err := s.provider.SendTransaction(order.ID); err != nil {
		s.errors.recordStatus(order, domain.StatusUnknown, err)
		return fmt.Errorf("send: %w", err)
	}
	return nil
}

func (s *Service) SendClassified(order *domain.Order) error {
	if _, err := s.provider.SendTransaction(order.ID); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		s.errors.record(order, "send transaction", err)
		return err
	}
	return nil
}

func (s *Service) Refresh(order *domain.Order) error {
	if err := s.repo.Save(order); err != nil {
		s.errors.record(order, "save", err)
		return err
	}
	return nil
}
`)))
}
