package patterns

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

func timeDerivedIDLines(t *testing.T, path, source string) []int {
	t.Helper()
	var ctx *core.FileContext
	if path[len(path)-3:] == ".go" {
		ctx = rulestest.GoFile(t, path, source)
	} else {
		ctx = core.NewFileContext(path, ".", []byte(source), nil)
	}
	lines := violationLines(NewTimeDerivedIDRule().AnalyzeFile(ctx))
	slices.Sort(lines)
	return lines
}

// An identifier formatted from the clock repeats for two calls in the same
// tick and is guessed by anyone who knows roughly when it was made.
func TestTimeDerivedIDFromClock(t *testing.T) {
	source := `package svc

import (
	"fmt"
	"math/rand"
	"strconv"
	"time"
)

type User struct{ ID, Email string }

type Meta struct{ RequestID string }

func create(email string, meta *Meta) User {
	userID := fmt.Sprintf("user-%d", time.Now().UnixNano())
	_ = userID
	meta.RequestID = fmt.Sprintf("create-user-%d", time.Now().Unix())
	return User{ID: "u-" + strconv.FormatInt(time.Now().UnixMilli(), 10), Email: email}
}

func generateJTI(adminID string, issued time.Time) string {
	return fmt.Sprintf("jti_%s_%d", adminID, issued.UnixNano())
}

func stamp() string {
	createdAt := fmt.Sprintf("%d", time.Now().Unix())
	return createdAt
}

func mixedID() string {
	id := fmt.Sprintf("%d-%d", time.Now().UnixNano(), rand.Int63())
	return id
}
`
	assert.Equal(t, []int{15, 17, 18, 22}, timeDerivedIDLines(t, "svc.go", source))
}

// The clock reduced modulo a small number picks one of a few values: two
// runs in the same window pick the same one.
func TestTimeDerivedIDModulo(t *testing.T) {
	source := `package helpers

import (
	"os"
	"time"
)

func account() int {
	timestamp := time.Now().UnixNano()
	uniqueIndex := int(timestamp % 50)
	return uniqueIndex
}

func mixed() int {
	timestamp := time.Now().UnixNano()
	hash := int(timestamp) ^ (os.Getpid() * 31)
	if hash < 0 {
		hash = -hash
	}
	uniqueIndex := hash % 50
	return uniqueIndex
}

func spinner(frames []string) string {
	frame := time.Now().UnixMilli() % int64(len(frames))
	return frames[frame]
}
`
	assert.Equal(t, []int{10, 20}, timeDerivedIDLines(t, "helpers.go", source))
	assert.Equal(t, []int{10, 20}, timeDerivedIDLines(t, "tests/helpers/accounts.go", source))
}

// Test code names its records after the clock all the time; only a clock
// squeezed into a few values collides there.
func TestTimeDerivedIDInTestCode(t *testing.T) {
	source := `package helpers

import (
	"fmt"
	"time"
)

func newUser() (string, int) {
	userID := fmt.Sprintf("test-user-%d", time.Now().UnixNano())
	walletIndex := time.Now().Nanosecond() % 50
	uniqueIndex := int(time.Now().UnixNano() % 50)
	return userID, walletIndex + uniqueIndex
}

func walletAddress() string {
	return fmt.Sprintf("0x%040d", time.Now().UnixNano()%1000000000000000000)
}
`
	assert.Equal(t, []int{10, 11}, timeDerivedIDLines(t, "tests/helpers/users.go", source))
}

func TestTimeDerivedIDModuloInTypeScript(t *testing.T) {
	source := `export function createUser(): string {
  const timestamp = Date.now();
  const userId = crypto.randomUUID();
  const clientNumber = String(100002 + (timestamp % 899998));
  const accountNumber = Date.now() % 100000;
  const frame = timestamp % frames.length;
  return insert(userId, clientNumber, accountNumber, frame);
}
`
	assert.Equal(t, []int{4, 5}, timeDerivedIDLines(t, "e2e/utils/users.ts", source))
}
