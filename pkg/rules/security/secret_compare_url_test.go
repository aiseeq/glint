package security

import (
	"fmt"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

func typedRuleLines(t *testing.T, analyze func(*core.GoProjectContext) ([]*core.Violation, error), files map[string]string) []string {
	t.Helper()
	violations, err := analyze(rulestest.Project(t, files))
	require.NoError(t, err)
	var places []string
	for _, v := range violations {
		places = append(places, fmt.Sprintf("%s:%d", v.File, v.Line))
	}
	slices.Sort(places)
	return places
}

// A secret the caller sent is compared with == or bytes.Equal: the
// comparison stops at the first differing byte, and the time it takes tells
// an attacker how much of the guess was right. A comparison with a constant
// (an empty check, a token kind), a value whose name is not a secret (a cache
// key, a token type) and a test are left alone.
func TestSecretCompareNotConstantTime(t *testing.T) {
	files := map[string]string{
		"hook/verify.go": `package hook

import (
	"bytes"
	"errors"
)

type handler struct {
	publicKey string
	secret    []byte
}

type headers struct{ publicKey, signature, tokenType string }

func (h *handler) verify(hd headers, expectedSig string, body []byte, cacheKey, other string) error {
	if hd.publicKey != h.publicKey {
		return errors.New("bad key")
	}
	if hd.signature == expectedSig {
		return nil
	}
	if bytes.Equal(body, h.secret) {
		return nil
	}
	if hd.tokenType != "access" {
		return nil
	}
	if hd.signature == "" {
		return nil
	}
	if cacheKey == other {
		return nil
	}
	return nil
}

type cache struct{ token string }

// invalidate drops a cached token: the comparison decides nothing about a
// caller and is not reported.
func (c *cache) invalidate(token string) {
	if token != "" && c.token == token {
		c.token = ""
	}
}

type tx struct{ Signature string }

func confirmed(latest []tx, lastTxHash *string) (bool, error) {
	return len(latest) > 0 && latest[0].Signature == *lastTxHash, nil
}

func matchAgent(agent, token string) bool {
	if agent == token {
		return true
	}
	return false
}

func validRefresh(stored *cache, refreshToken string) error {
	if stored.token != refreshToken {
		return errors.New("mismatch")
	}
	return nil
}
`,
		"hook/verify_test.go": `package hook

func compare(token, want string) bool { return token == want }
`,
	}
	assert.Equal(t, []string{"hook/verify.go:16", "hook/verify.go:19", "hook/verify.go:22", "hook/verify.go:61"},
		typedRuleLines(t, NewSecretCompareNotConstantTimeRule().AnalyzeGoProject, files))
}

// A value that needs escaping put into a URL query by a format verb: the "+"
// of a time zone offset reads as a space, a pagination cursor or free text
// holding "&", "=" or "+" breaks the query. Identifiers, enum words, numbers
// and escaped values are fine.
func TestURLQueryBuiltByFormat(t *testing.T) {
	files := map[string]string{
		"client/client.go": `package client

import (
	"fmt"
	"net/url"
	"time"
)

type Currency string

func list(start time.Time, currency, cursor, chain string, limit int, cur Currency, base, search string) string {
	endpoint := fmt.Sprintf("/deposits/list?startDate=%s&limit=%d", start.Format(time.RFC3339), limit)
	endpoint += fmt.Sprintf("&currency=%s", currency)
	endpoint += fmt.Sprintf("&after=%v", cursor)
	endpoint += fmt.Sprintf("&after=%s", url.QueryEscape(cursor))
	endpoint += fmt.Sprintf("&limit=%d", limit)
	endpoint += fmt.Sprintf("&kind=%s", "usd")
	endpoint += fmt.Sprintf("&cur=%s", cur)
	endpoint += fmt.Sprintf("%s/v1/items?currency=usd", base)
	endpoint += fmt.Sprintf("&chain=%s&day=%s", chain, start.Format("2006-01-02"))
	endpoint += fmt.Sprintf("&q=%s", search)
	msg := fmt.Sprintf("value=%s", currency)
	return endpoint + msg
}
`,
	}
	assert.Equal(t, []string{"client/client.go:12", "client/client.go:14", "client/client.go:21"},
		typedRuleLines(t, NewURLQueryBuiltByFormatRule().AnalyzeGoProject, files))
}
