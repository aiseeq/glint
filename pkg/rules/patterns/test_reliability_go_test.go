package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// A fixture made in a subtest by a helper that cleans up with the subtest is
// gone when the next subtest runs.
func TestSubtestFixtureCleanedEarly(t *testing.T) {
	helper := rulestest.GoFile(t, "tests/auth/helpers.go", `package auth

import "testing"

func CreateTestUser(t *testing.T, client *Client, email string) *Response {
	return registerUser(t, client, email)
}

func registerUser(t *testing.T, client *Client, email string) *Response {
	user := client.Register(email)
	if user != nil {
		t.Cleanup(func() { client.Delete(user.ID) })
	}
	return user
}

func FindTestUser(t *testing.T, client *Client, email string) *Response {
	return client.Find(email)
}
`)
	test := rulestest.GoFile(t, "tests/integration/login_test.go", `package integration

import (
	"testing"

	"example.com/app/tests/auth"
)

func TestLogin(t *testing.T) {
	var registered *auth.Response
	var found *auth.Response
	t.Run("prepare", func(t *testing.T) {
		registered = auth.CreateTestUser(t, client, "a@example.com")
		found = auth.FindTestUser(t, client, "a@example.com")
	})
	t.Run("login", func(t *testing.T) {
		login(t, registered, found)
	})
}

func TestLoginParent(t *testing.T) {
	registered := auth.CreateTestUser(t, client, "a@example.com")
	t.Run("login", func(t *testing.T) {
		login(t, registered)
	})
}

func TestLoginSameSubtest(t *testing.T) {
	var registered *auth.Response
	t.Run("all", func(t *testing.T) {
		registered = auth.CreateTestUser(t, client, "a@example.com")
		login(t, registered)
	})
}
`)
	rule := NewSubtestFixtureCleanedEarlyRule()
	rule.UseProjectFiles([]*core.FileContext{helper, test})
	assert.Equal(t, []int{13}, violationLines(rule.AnalyzeFile(test)))
}

// A wait helper that returns once its attempts run out lets the test go on
// as if the awaited state had come.
func TestTestWaitPassesOnExhaustion(t *testing.T) {
	ctx := rulestest.GoFile(t, "tests/integration/wait_helpers.go", `package integration

import (
	"testing"
	"time"
)

func waitConfirmed(t *testing.T, client *Client, hash string) {
	retryCount := 0
	maxRetries := 10
	for {
		if client.Confirmed(hash) {
			return
		}
		retryCount++
		if retryCount >= maxRetries {
			t.Logf("assuming confirmed: %s", hash)
			return
		}
		time.Sleep(time.Second)
	}
}

func waitReady(t *testing.T, client *Client) {
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if client.Ready() {
			return
		}
		time.Sleep(time.Second)
	}
}

func waitStrict(t *testing.T, client *Client, hash string) {
	retryCount := 0
	for {
		if client.Confirmed(hash) {
			return
		}
		retryCount++
		if retryCount >= maxRetries {
			t.Fatalf("not confirmed: %s", hash)
		}
		time.Sleep(time.Second)
	}
}

func waitReadyOrFail(t *testing.T, client *Client) {
	start := time.Now()
	for time.Since(start) < time.Minute {
		if client.Ready() {
			return
		}
		time.Sleep(time.Second)
	}
	t.Fatal("never ready")
}

func pollUntil(t *testing.T, client *Client) bool {
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if client.Ready() {
			return true
		}
	}
	return false
}

func waitTwoWays(t *testing.T, client *Client) {
	retryCount := 0
	for {
		if client.Missing() {
			retryCount++
			if retryCount >= maxRetries {
				return
			}
			continue
		}
		retryCount++
		if retryCount >= maxRetries {
			return
		}
	}
}
`)
	assert.Equal(t, []int{16, 25, 72, 78}, violationLines(NewTestWaitPassesOnExhaustionRule().AnalyzeFile(ctx)))
}

// A fixed pause before a single check guesses how long the work takes.
func TestTestFixedSleepBeforeAssert(t *testing.T) {
	ctx := rulestest.GoFile(t, "service/balance_test.go", `package service

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestDeposit(t *testing.T) {
	deposit(t, user)
	time.Sleep(500 * time.Millisecond)
	balance := getBalance(t, user)
	require.True(t, balance > 1000)
}

func TestPolling(t *testing.T) {
	for i := 0; i < 10; i++ {
		time.Sleep(time.Second)
		if ready() {
			break
		}
	}
	require.True(t, ready())
}

func TestTimestamps(t *testing.T) {
	first := create()
	time.Sleep(10 * time.Millisecond)
	second := create()
	require.True(t, second.After(first))
}

func TestBackground(t *testing.T) {
	start()
	time.Sleep(2 * time.Second)
	stop()
}

func TestSubtest(t *testing.T) {
	t.Run("eventually", func(t *testing.T) {
		publish()
		time.Sleep(time.Second)
		if !received() {
			t.Fatal("not received")
		}
	})
}

func TestTokenExpiry(t *testing.T) {
	token := issueToken(time.Second)
	time.Sleep(2 * time.Second)
	expiredClient := clientWith(token)
	require.Error(t, expiredClient.Ping())
}
`)
	assert.Equal(t, []int{12, 43}, violationLines(NewTestFixedSleepBeforeAssertRule().AnalyzeFile(ctx)))
}

// An accepted status range reaching 5xx passes when the server fails.
func TestTestAcceptsServerErrorStatus(t *testing.T) {
	ctx := rulestest.GoFile(t, "server/smoke_test.go", `package server

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSmoke(t *testing.T) {
	resp := get(t, "/health")
	assert.True(t, resp.StatusCode >= 200 && resp.StatusCode <= 503, "unexpected status")
	assert.Less(t, resp.StatusCode, 600)
	if resp.StatusCode > http.StatusServiceUnavailable {
		t.Fatalf("status %d", resp.StatusCode)
	}
	assert.True(t, resp.StatusCode < 500)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	if resp.StatusCode >= 400 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	assert.True(t, len(body) <= 600)
}
`)
	assert.Equal(t, []int{12, 13, 14}, violationLines(NewTestAcceptsServerErrorRule().AnalyzeFile(ctx)))
}

// A step that can stop the test between a creation and its cleanup leaves
// the created resource behind.
func TestTestCleanupRegisteredLate(t *testing.T) {
	ctx := rulestest.GoFile(t, "external/sheet_test.go", `package external

import "testing"

func TestRowLifecycle(t *testing.T) {
	err := client.AppendRange(ctx, "Users!A:K", rows)
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	rowIndex, err := client.GetLastRowIndex(ctx, "Users")
	if err != nil {
		t.Fatalf("index: %v", err)
	}
	defer client.DeleteRow(ctx, rowIndex)
}

func TestRowLifecycleFixed(t *testing.T) {
	rowIndex, err := client.AppendRangeWithIndex(ctx, "Users!A:K", rows)
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	defer client.DeleteRow(ctx, rowIndex)
	value, err := client.Read(ctx, rowIndex)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	_ = value
}

func TestCleanupHelper(t *testing.T) {
	user, err := store.CreateUser(ctx, "a")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.DeleteUser(ctx, user.ID) })
}

func TestCreatedChecked(t *testing.T) {
	user, err := store.CreateUser(ctx, "a")
	require.NoError(t, err)
	require.NotNil(t, user, "user created")
	t.Cleanup(func() { store.DeleteUser(ctx, user.ID) })
}

func TestUnrelatedDefer(t *testing.T) {
	total := amount.Add(fee)
	assert.True(t, total.IsPositive())
	mu.Lock()
	defer mu.Unlock()
}

func TestHelperCleansItself(t *testing.T) {
	db := testutil.CreateIsolatedDB(t)
	require.NoError(t, other.Ping())
	t.Cleanup(func() { db.Reset() })
}

func TestCleanupOfAnotherChange(t *testing.T) {
	userID := store.CreateUser(ctx, "a")
	_, err := store.Exec(ctx, "ALTER TABLE x RENAME TO y")
	require.NoError(t, err)
	t.Cleanup(func() { store.Exec(ctx, "ALTER TABLE y RENAME TO x") })
	_ = userID
}

func TestSeededLock(t *testing.T) {
	registry.SeedFirstSeen(seen)
	require.False(t, fresh)
	registry.mu.Lock()
	defer registry.mu.Unlock()
}

func TestNestedAdd(t *testing.T) {
	item := &Item{At: start.Add(time.Minute)}
	require.NoError(t, other.Ping())
	t.Cleanup(func() { remove(item) })
}
`)
	assert.Equal(t, []int{11}, violationLines(NewTestCleanupRegisteredLateRule().AnalyzeFile(ctx)))
}

// Rows picked by a production constant are the application's own.
func TestTestDeletesSharedData(t *testing.T) {
	ctx := rulestest.GoFile(t, "tests/integration/yield_test.go", `package integration

import (
	"testing"

	"example.com/app/models"
	"example.com/app/testutil"
)

func TestYield(t *testing.T) {
	strategy := models.DefaultStrategyID
	_, _ = db.ExecContext(ctx, "DELETE FROM vault_snapshots WHERE strategy = $1", strategy)
	_, _ = db.ExecContext(ctx, "UPDATE users SET status = 'x' WHERE id = $1", models.SystemUserID)
}

func TestYieldIsolated(t *testing.T) {
	strategy := "test-yield"
	_, _ = db.ExecContext(ctx, "DELETE FROM vault_snapshots WHERE strategy = $1", strategy)
	_, _ = db.ExecContext(ctx, "DELETE FROM users WHERE email = $1", testutil.Email)
	_, _ = db.ExecContext(ctx, "SELECT * FROM users WHERE id = $1", models.SystemUserID)
}

func TestStatusUpdate(t *testing.T) {
	id := seedRequest(t)
	_, _ = db.ExecContext(ctx, "UPDATE requests SET status = $2 WHERE id = $1", id, models.StatusPending)
	_, _ = db.ExecContext(ctx, "UPDATE requests SET status = ? WHERE owner = ?", models.StatusPending, models.SystemUserID)
}
`)
	assert.Equal(t, []int{12, 13, 26}, violationLines(NewTestDeletesSharedDataRule().AnalyzeFile(ctx)))

	isolated := rulestest.GoFile(t, "tests/integration/gift_test.go", `package integration

import (
	"testing"

	"example.com/app/models"
	"example.com/app/testutil"
)

func TestGift(t *testing.T) {
	idb := testutil.CreateIsolatedTestDB(t)
	_, _ = idb.ExecContext(ctx, "DELETE FROM investments WHERE user_id = $1", models.SystemUserID)
}
`)
	assert.Empty(t, NewTestDeletesSharedDataRule().AnalyzeFile(isolated))
}

// A bare receive from the code's channel hangs the run when the event is lost.
func TestTestChannelReceiveWithoutTimeout(t *testing.T) {
	ctx := rulestest.GoFile(t, "events/broadcast_test.go", `package events

import (
	"testing"
	"time"
)

func TestBroadcast(t *testing.T) {
	manager.Broadcast(evt)
	received := <-subscriber.Channel
	other := <-sub.Events()
	_, _ = received, other

	select {
	case got := <-subscriber.Channel:
		_ = got
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}

	done := make(chan struct{})
	go func() { close(done) }()
	<-done
	<-ctx.Done()
	<-ticker.C
	<-time.After(time.Millisecond)
	for evt := range subscriber.Channel {
		_ = evt
	}
}

func TestQueued(t *testing.T) {
	service.Record(evt)
	if got := len(service.queue); got != 1 {
		t.Fatalf("queued %d", got)
	}
	queued := <-service.queue
	_ = queued
}
`)
	assert.Equal(t, []int{10, 11}, violationLines(NewTestChannelReceiveWithoutTimeoutRule().AnalyzeFile(ctx)))
}
