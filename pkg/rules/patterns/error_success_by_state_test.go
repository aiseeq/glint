package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// Any failure of the insert is taken for "already there" once a row with
// the address is found: a lost connection or a constraint on another column
// passes as success.
func TestErrorSuccessByState(t *testing.T) {
	ctx := rulestest.GoFile(t, "wallets/save.go", `package wallets

import (
	"context"
	"errors"
	"fmt"
)

var ErrDuplicate = errors.New("duplicate")

type Wallet struct {
	UserID  string
	Address string
}

type Repo interface {
	Create(ctx context.Context, w *Wallet) error
	ByAddress(ctx context.Context, address string) (*Wallet, error)
}

type Logger interface {
	Info(msg string)
	Warn(msg string, args ...any)
}

func Save(ctx context.Context, repo Repo, log Logger, w *Wallet) error {
	err := repo.Create(ctx, w)
	if err != nil {
		existing, lookupErr := repo.ByAddress(ctx, w.Address)
		if lookupErr != nil {
			return fmt.Errorf("create: %w, lookup: %v", err, lookupErr)
		}
		if existing.UserID == w.UserID {
			log.Info("wallet already exists")
			return nil
		}
		return fmt.Errorf("create wallet: %w", err)
	}
	return nil
}

func SaveClassified(ctx context.Context, repo Repo, w *Wallet) error {
	if err := repo.Create(ctx, w); err != nil {
		if errors.Is(err, ErrDuplicate) {
			return nil
		}
		return err
	}
	return nil
}

func SaveCancelled(ctx context.Context, repo Repo, w *Wallet) error {
	if err := repo.Create(ctx, w); err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return err
	}
	return nil
}

func Cached(ctx context.Context, repo Repo, log Logger, cached *Wallet, address string) (*Wallet, error) {
	fresh, err := repo.ByAddress(ctx, address)
	if err != nil {
		if cached != nil {
			log.Warn("serving cached wallet", "error", err)
			return cached, nil
		}
		return nil, err
	}
	return fresh, nil
}

type Transitions interface {
	Apply(ctx context.Context, id, from, to string) error
	Status(ctx context.Context, id string) (string, error)
}

// The re-read finds the very status the failed write was setting: a
// concurrent writer got there first, the outcome is the one asked for.
func Finish(ctx context.Context, repo Transitions, log Logger, id string) error {
	if err := repo.Apply(ctx, id, "cancelling", "cancelled"); err != nil {
		status, reloadErr := repo.Status(ctx, id)
		if reloadErr == nil && status == "cancelled" {
			log.Info("already cancelled")
			return nil
		}
		return err
	}
	return nil
}

type failureKind int

const (
	failureOther failureKind = iota
	failureNotModified
)

func classify(err error) (failureKind, bool) { return failureOther, false }

// The condition reads a classification of the error itself.
func Edit(ctx context.Context, repo Repo, w *Wallet) error {
	if err := repo.Create(ctx, w); err != nil {
		failure, _ := classify(err)
		if failure == failureNotModified {
			return nil
		}
		return err
	}
	return nil
}
`)
	assert.Equal(t, []int{35}, violationLines(NewErrorSuccessByStateRule().AnalyzeFile(ctx)))
}
