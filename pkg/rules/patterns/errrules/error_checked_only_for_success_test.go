package errrules

import (
	"testing"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
)

// A call going out (it takes a context) whose error is tested only for
// success, with no other branch and no other look at it, drops the failure:
// the caller gets the data missing as if there were none. A parse tested for
// success asks whether the input has the form, and an error handled before
// the check leaves success-only for the expected case.
func TestErrorCheckedOnlyForSuccess(t *testing.T) {
	ctx := rulestest.GoFile(t, "service/orders.go", `package service

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
)

func (s *Service) enrich(ctx context.Context, ids []string) map[string]string {
	numbers := map[string]string{}
	if batch, ok := s.repo.(batchRepo); ok {
		users, err := batch.LoadUsers(ctx, ids)
		if err == nil {
			for id, u := range users {
				numbers[id] = u.Number
			}
		}
	} else {
		for _, id := range ids {
			u, err := s.repo.GetUser(ctx, id)
			if err == nil && u != nil {
				numbers[id] = u.Number
			}
		}
	}
	return numbers
}

func limit(raw string) int {
	n := 10
	if v, err := strconv.Atoi(raw); err == nil {
		n = v
	}
	return n
}

func handled(ctx context.Context, id string) (*User, error) {
	u, err := load(ctx, id)
	if err == nil {
		return u, nil
	}
	return nil, fmt.Errorf("load %s: %w", id, err)
}

func withElse(ctx context.Context, id string) {
	u, err := load(ctx, id)
	if err == nil {
		use(u)
	} else {
		log.Printf("load %s: %v", id, err)
	}
}

func checkedAfter(ctx context.Context, id string) error {
	u, err := load(ctx, id)
	if err == nil {
		use(u)
	}
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	return err
}

func named(ctx context.Context, id string) (u *User, err error) {
	u, err = load(ctx, id)
	if err == nil {
		cache(u)
	}
	return
}

func examinedBefore(ctx context.Context, id string) (*User, error) {
	u, err := load(ctx, id)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if err == nil {
		cache(u)
	}
	return u, nil
}

func stats(ctx context.Context) int {
	total := 0
	if st, err := limiter.GetStats(r.Context()); err == nil && st != nil {
		total += st.Allowed
	}
	return total
}

func probes(path string) bool {
	if _, err := os.Stat(path); err == nil {
		return true
	}
	if _, err := exec.LookPath("git"); err == nil {
		return true
	}
	return false
}

func field(resp *Response) {
	if resp.Err == nil {
		use(resp)
	}
}
`)
	assert.Equal(t, []int{15, 23, 88}, rulestest.ViolationLines(NewErrorCheckedOnlyForSuccessRule().AnalyzeFile(ctx)))
}
