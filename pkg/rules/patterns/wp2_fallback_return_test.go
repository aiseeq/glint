package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

func fallbackReturnLines(t *testing.T, source string) []int {
	t.Helper()
	ctx := rulestest.GoFile(t, "svc/svc.go", source)
	return violationLines(NewFallbackReturnRule().AnalyzeFile(ctx))
}

// A lazily built singleton returns the value it has just stored, and a comment
// that happens to say "use" or "return" is not an error context.
func TestFallbackReturn_LazySingletonAndCommentWordsAreNotFallbacks(t *testing.T) {
	const source = `package svc

type UserService struct{}

type PaymentProvider struct{}

func NewUserService() *UserService { return &UserService{} }

var userService *UserService

var cachedProvider = &PaymentProvider{}

// Users lazily builds the shared service.
func Users() *UserService {
	if userService == nil {
		userService = NewUserService()
	}
	return userService
}

// Provider returns the provider we use for every payment.
func Provider() *PaymentProvider {
	return cachedProvider
}
`
	assert.Empty(t, fallbackReturnLines(t, source))
}

// A branch that records the failure in the result reads the error: that is
// reporting, not replacing it with a fallback.
func TestFallbackReturn_BranchThatRecordsTheErrorIsNotAFallback(t *testing.T) {
	const source = `package svc

import "strconv"

type Result struct {
	Status  string
	Message string
}

func Convert(s string) Result {
	var res Result
	_, err := strconv.Atoi(s)
	if err != nil {
		res.Status = "failed"
		res.Message = err.Error()
	}
	return res
}

func Parse(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		n = 0
	}
	return n
}
`
	assert.Equal(t, []int{23}, fallbackReturnLines(t, source))
}

// The middleware exception names whole words: GetRealIP and GetClientKey are
// defensive getters, GetRecipient only contains the letters "ip".
func TestFallbackReturn_MiddlewareGetterExceptionNeedsWholeWords(t *testing.T) {
	const source = `package svc

type Recipient struct{}

var fallbackRecipient = &Recipient{}

var fallbackIP = "127.0.0.1"

func lookup() (*Recipient, error) { return nil, nil }

func lookupIP() (string, error) { return "", nil }

func GetRecipient() (*Recipient, error) {
	r, err := lookup()
	if err != nil {
		return fallbackRecipient, nil
	}
	return r, nil
}

func GetRealIP() (string, error) {
	ip, err := lookupIP()
	if err != nil {
		return fallbackIP, nil
	}
	return ip, nil
}
`
	assert.Equal(t, []int{16}, fallbackReturnLines(t, source))
}
