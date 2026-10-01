package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// A mapping from one struct to another copies some fields by name and
// silently leaves out others both types have: the response shows the hash
// empty, the created date as zero, though the source had them.
func TestStructMappingDropsField(t *testing.T) {
	files := map[string]string{
		"models/models.go": `package models

import "time"

type Status string

type Request struct {
	ID        string
	UserID    string
	Amount    int64
	Status    Status
	TxHash    *string
	Note      string
	Internal  string
	CreatedAt time.Time
}

type RequestWithUser struct {
	*Request
	UserEmail string
	Verified  bool
}

type Withdrawal struct {
	ID        string
	UserID    string
	Amount    int64
	Status    string
	TxHash    *string
	UserEmail string
	Verified  bool
	CreatedAt time.Time
	Internal  string ` + "`json:\"-\"`" + `
	Note      string
}

type Account struct {
	ID           string
	Email        string
	PasswordHash string
	CreatedAt    time.Time
}

type AccountView struct {
	ID           string
	Email        string
	PasswordHash string
	CreatedAt    time.Time
}

type LoginRequest struct {
	Email        string
	AccessToken  string
	RefreshToken string
}

type Ledger struct {
	ID        string
	UserID    string
	Amount    int64
	CreatedAt time.Time
}

type Group struct {
	UserID    string
	Amount    int64
	CreatedAt time.Time
	Legs      []*Request
}

type Result struct {
	UserID    string
	Amount    int64
	SessionID string
}

type AdminResult struct {
	Result
	SessionID string
}

type Claims struct {
	UserID    string
	Amount    int64
	SessionID string
}
`,
		"service/service.go": `package service

import "example.com/rulestest/models"

func Convert(r *models.RequestWithUser) models.Withdrawal {
	return models.Withdrawal{ // want struct-mapping-drops-field
		ID:        r.ID,
		UserID:    r.UserID,
		Amount:    r.Amount,
		Status:    string(r.Status),
		UserEmail: r.UserEmail,
	}
}

func ConvertAll(rs []*models.RequestWithUser) []models.Withdrawal {
	var out []models.Withdrawal
	for _, r := range rs {
		w := models.Withdrawal{
			ID:        r.ID,
			UserID:    r.UserID,
			Amount:    r.Amount,
			Status:    string(r.Status),
			UserEmail: r.UserEmail,
			TxHash:    r.TxHash,
			Note:      r.Note,
		}
		w.CreatedAt = r.CreatedAt
		w.Verified = r.Verified
		out = append(out, w)
	}
	return out
}

func View(a *models.Account) *models.AccountView {
	return &models.AccountView{
		ID:        a.ID,
		Email:     a.Email,
		CreatedAt: a.CreatedAt,
	}
}

func Partial(r *models.Request, email string) models.Withdrawal {
	return models.Withdrawal{
		ID:        r.ID,
		UserEmail: email,
	}
}

func Verify(req *models.LoginRequest) models.LoginRequest {
	return models.LoginRequest{Email: req.Email, AccessToken: req.AccessToken}
}

func Post(r *models.Request) models.Ledger {
	return models.Ledger{UserID: r.UserID, Amount: r.Amount}
}

func Groups(rs []*models.Request) []*models.Group {
	var out []*models.Group
	for _, r := range rs {
		g := &models.Group{UserID: r.UserID, Amount: r.Amount}
		g.Legs = append(g.Legs, r)
		out = append(out, g)
	}
	return out
}

func Admin(c *models.Claims) *models.AdminResult {
	return &models.AdminResult{
		Result:    models.Result{UserID: c.UserID, Amount: c.Amount},
		SessionID: c.SessionID,
	}
}

func Filled(r *models.Request) models.Withdrawal {
	w := models.Withdrawal{ID: r.ID, UserID: r.UserID, Amount: r.Amount}
	fill(&w, r)
	return w
}

func Stamped(r *models.Request) models.Withdrawal {
	w := models.Withdrawal{ID: r.ID, UserID: r.UserID, Amount: r.Amount, Status: string(r.Status), Note: r.Note}
	for _, into := range []**string{&w.TxHash} {
		*into = r.TxHash
	}
	w.CreatedAt = r.CreatedAt
	return w
}

func fill(w *models.Withdrawal, r *models.Request) {}

func Copy(r models.Request) models.Request {
	return models.Request{ID: r.ID, UserID: r.UserID}
}
`,
	}
	violations, err := NewStructMappingDropsFieldRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	assert.Equal(t, wantedLines(files, "struct-mapping-drops-field"), foundLines(violations))
	require.Len(t, violations, 1)
	assert.Contains(t, violations[0].Message, "TxHash, Verified, CreatedAt, Note")
}
