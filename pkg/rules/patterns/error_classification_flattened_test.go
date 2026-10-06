package patterns

import "testing"

// A function that tells a missing item from a failed read (errors.As,
// errors.Is) and then returns both as fresh text errors hands its callers
// nothing to tell them apart by: an access check answered with a 403 for any
// error refuses the operator when the database is down. A sentinel or a
// wrapped cause keeps the classification.
func TestErrorClassificationFlattened(t *testing.T) {
	assertWanted(t, NewErrorClassificationFlattenedRule(), `package admin

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
)

type NotFoundError struct{ ID string }

func (e *NotFoundError) Error() string { return "not found: " + e.ID }

type Item struct{ Owner string }

type Repo interface {
	GetByID(ctx context.Context, id string) (Item, error)
}

type Admin struct{ repo Repo }

var ErrItemNotFound = errors.New("item not found")

func (a *Admin) checkAccess(ctx context.Context, id, user string) error {
	item, err := a.repo.GetByID(ctx, id)
	if err != nil {
		var nf *NotFoundError
		if errors.As(err, &nf) {
			return fmt.Errorf("item not found") // want
		}
		log.Printf("load item %s: %v", id, err)
		return fmt.Errorf("failed to load item")
	}
	if item.Owner != user {
		return fmt.Errorf("access denied")
	}
	return nil
}

type CodedError struct{ Code string }

func (e *CodedError) Error() string { return e.Code }

func (a *Admin) checkAccessCoded(ctx context.Context, id string) error {
	_, err := a.repo.GetByID(ctx, id)
	if err != nil {
		var derr *CodedError
		if errors.As(err, &derr) && derr.Code == "not_found" {
			return fmt.Errorf("item not found") // want
		}
		return fmt.Errorf("failed to load item")
	}
	return nil
}

func (a *Admin) checkAccessNoRows(ctx context.Context, id string) error {
	if _, err := a.repo.GetByID(ctx, id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return errors.New("item not found") // want
		}
		return errors.New("item read failed")
	}
	return nil
}

func (a *Admin) checkAccessSentinel(ctx context.Context, id string) error {
	if _, err := a.repo.GetByID(ctx, id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrItemNotFound
		}
		return errors.New("item read failed")
	}
	return nil
}

func (a *Admin) checkAccessWrapped(ctx context.Context, id string) error {
	if _, err := a.repo.GetByID(ctx, id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("item %s: %w", id, err)
		}
		return fmt.Errorf("read item %s: %w", id, err)
	}
	return nil
}

func (a *Admin) describe(ctx context.Context, id string) string {
	if _, err := a.repo.GetByID(ctx, id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "item not found"
		}
		return "item read failed"
	}
	return "ok"
}
`)
}
