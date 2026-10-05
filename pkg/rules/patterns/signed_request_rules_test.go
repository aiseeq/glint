package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// signerSource is a request signer of a synthetic provider client.
const signerSource = `package payprov

import (
	"crypto/sha256"
	"encoding/hex"
)

type Signer struct{ key []byte }

// Sign signs the bytes it is given.
func (s *Signer) Sign(data []byte) (string, error) {
	sum := sha256.Sum256(append(s.key, data...))
	return hex.EncodeToString(sum[:]), nil
}

// SignBody marshals the value itself before signing.
func (s *Signer) SignBody(v any) (string, error) {
	data, err := canonical(v)
	if err != nil {
		return "", err
	}
	return s.Sign(data)
}
`

// The signer marshals the value on its own and the request sends another
// marshal of it: the provider checks the signature against different bytes.
func TestSignatureOverDifferentBytesThanSent(t *testing.T) {
	assert.Equal(t, []string{"payprov/client.go:23", "payprov/client.go:58"}, typedFuncFindings(t, NewSignatureOverDifferentBytesThanSentRule(), map[string]string{
		"payprov/signer.go": signerSource,
		"payprov/canonical.go": `package payprov

import "encoding/json"

func canonical(v any) ([]byte, error) { return json.Marshal(v) }

func trimmed(v any) any { return v }
`,
		"payprov/client.go": `package payprov

import (
	"bytes"
	"encoding/json"
	"net/http"
)

type Client struct {
	signer *Signer
	base   string
	http   *http.Client
}

func (c *Client) retry(fn func() error) error { return fn() }

func (c *Client) post(path string, body any) error {
	return c.retry(func() error {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		sig, err := c.signer.SignBody(body)
		if err != nil {
			return err
		}
		req, err := http.NewRequest(http.MethodPost, c.base+path, bytes.NewReader(data))
		if err != nil {
			return err
		}
		req.Header.Set("X-Signature", sig)
		_, err = c.http.Do(req)
		return err
	})
}

// postSame signs the very bytes it sends.
func (c *Client) postSame(path string, body any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	sig, err := c.signer.Sign(data)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, c.base+path, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("X-Signature", sig)
	_, err = c.http.Do(req)
	return err
}

// postTrimmed signs the value and sends a marshal of its trimmed copy.
func (c *Client) postTrimmed(path string, body any) error {
	sig, err := c.signer.SignBody(body)
	if err != nil {
		return err
	}
	data, err := json.Marshal(trimmed(body))
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, c.base+path, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("X-Signature", sig)
	_, err = c.http.Do(req)
	return err
}
`,
	}))
}

// A request body logged at Info by a client writes the customer's data
// into the logs on every call; its length or a Debug line does not.
func TestOutboundRequestBodyLogged(t *testing.T) {
	assert.Equal(t, []string{"payprov/client.go:20"}, typedFuncFindings(t, NewOutboundRequestBodyLoggedRule(), map[string]string{
		"payprov/client.go": `package payprov

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
)

type Client struct {
	logger *slog.Logger
	http   *http.Client
}

func (c *Client) post(url string, body any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	c.logger.Info("provider request", "url", url, "body", string(data))
	c.logger.Info("provider request", "url", url, "body_len", len(data))
	c.logger.Debug("provider request", "body", string(data))
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return err
	}
	_, err = c.http.Do(req)
	return err
}

// store logs what it writes to a file, not to a remote API.
func (c *Client) store(body any) []byte {
	data, _ := json.Marshal(body)
	c.logger.Info("stored", "body", string(data))
	return data
}
`,
	}))
}

// A provider's response logged at Info - here through a helper that
// truncates it - writes the provider's copy of the customer's data into the
// logs; an error-level line about a failed call does not count.
func TestProviderResponseBodyLogged(t *testing.T) {
	assert.Equal(t, []string{"payprov/client.go:39"}, typedFuncFindings(t, NewProviderResponseBodyLoggedRule(), map[string]string{
		"payprov/client.go": `package payprov

import (
	"io"
	"log/slog"
	"net/http"
)

type Client struct {
	logger *slog.Logger
	http   *http.Client
}

func (c *Client) do(req *http.Request) error {
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	logResponse(c.logger, resp.StatusCode, body)
	c.logger.Info("provider response", "status", resp.StatusCode, "body_len", len(body))
	if resp.StatusCode >= 500 {
		c.logger.Error("provider failed", "status", resp.StatusCode, "body", string(body))
	}
	return nil
}

func logResponse(logger *slog.Logger, status int, body []byte) {
	text := string(body)
	if len(text) > 500 {
		text = text[:500] + "..."
	}
	logger.Info("provider response",
		"status", status,
		"body", text,
	)
}

// logUpload logs a file the user uploaded, not a provider's answer.
func logUpload(logger *slog.Logger, data []byte) {
	logger.Info("upload", "body", string(data))
}
`,
	}))
}

// secretConfigSource loads two webhook secrets from the environment and checks
// only one of them.
const secretConfigSource = `package config

import (
	"errors"
	"os"
)

type Config struct {
	PartnerSecret string
	BillingSecret string
}

func Load() (*Config, error) {
	cfg := &Config{PartnerSecret: os.Getenv("PARTNER_SECRET"), BillingSecret: os.Getenv("BILLING_SECRET")}
	if cfg.BillingSecret == "" {
		return nil, errors.New("BILLING_SECRET is required")
	}
	return cfg, nil
}
`

// An HMAC check keyed by a secret nobody requires to be set accepts the
// signature an attacker computes with the empty key.
func TestHMACVerifiedWithEmptySecret(t *testing.T) {
	assert.Equal(t, []string{"api/verify.go:11"}, typedFuncFindings(t, NewHMACVerifiedWithEmptySecretRule(), map[string]string{
		"config/config.go": secretConfigSource,
		"api/verify.go": `package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
)

func verify(body []byte, signature, secret string) bool {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hmac.Equal([]byte(hex.EncodeToString(mac.Sum(nil))), []byte(signature))
}

func verifyBilling(body []byte, signature, secret string) bool {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hmac.Equal([]byte(hex.EncodeToString(mac.Sum(nil))), []byte(signature))
}

// verifyGuarded refuses an empty key itself.
func verifyGuarded(body []byte, signature, secret string) bool {
	if secret == "" {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hmac.Equal(mac.Sum(nil), []byte(signature))
}

func auth(secret string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !verify(nil, r.Header.Get("X-Signature"), secret) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
`,
		"app/main.go": `package app

import (
	"net/http"

	"example.com/rulestest/api"
	"example.com/rulestest/config"
)

func Routes(cfg *config.Config, next http.Handler) []http.Handler {
	return []http.Handler{api.Auth(cfg.PartnerSecret, next), api.Billing(cfg.BillingSecret, next), api.Guarded(cfg.PartnerSecret, next)}
}
`,
		"api/routes.go": `package api

import "net/http"

func Auth(secret string, next http.Handler) http.Handler { return auth(secret, next) }

func Billing(secret string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !verifyBilling(nil, r.Header.Get("X-Signature"), secret) {
			return
		}
		next.ServeHTTP(w, r)
	})
}

func Guarded(secret string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !verifyGuarded(nil, r.Header.Get("X-Signature"), secret) {
			return
		}
		next.ServeHTTP(w, r)
	})
}
`,
	}))
}

// A signature checked only when the request has a body lets a bodiless
// POST or DELETE through unsigned.
func TestRequestSignatureWithoutTimestampOrTarget(t *testing.T) {
	assert.Equal(t, []string{"api/auth.go:21"}, typedFuncFindings(t, NewRequestSignatureWithoutTimestampOrTargetRule(), map[string]string{
		"api/auth.go": `package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"io"
	"net/http"
)

func verifySignature(body []byte, signature, secret string) bool {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hmac.Equal(mac.Sum(nil), []byte(signature))
}

func auth(secret string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Key") == "" {
			return
		}
		if r.Body != nil && r.ContentLength != 0 {
			body, _ := io.ReadAll(r.Body)
			if !verifySignature(body, r.Header.Get("X-Signature"), secret) {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// strict reads and verifies every request.
func strict(secret string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength > 1<<20 {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		body, _ := io.ReadAll(r.Body)
		if !verifySignature(body, r.Header.Get("X-Signature"), secret) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
`,
	}))
}

// json.Marshal escapes <, > and & as <...: bytes signed from it differ
// from the provider's canonical form of the same document.
func TestJSONMarshalHTMLEscapingInSignedPayload(t *testing.T) {
	assert.Equal(t, []string{"payprov/canonical.go:13", "payprov/params.go:7"}, typedFuncFindings(t, NewJSONMarshalHTMLEscapingInSignedPayloadRule(), map[string]string{
		"payprov/signer.go": signerSource,
		"payprov/canonical.go": `package payprov

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
)

// canonical is what SignBody signs.
func canonical(v any) ([]byte, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}
	return data, nil
}

// canonicalRaw keeps <, > and & as they are.
func canonicalRaw(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// fingerprint identifies a document by its own marshal.
func fingerprint(v any) ([]byte, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	return sum[:], nil
}

// save writes a document nobody signs.
func save(v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return os.WriteFile("doc.json", data, 0o600)
}
`,
		"payprov/params.go": `package payprov

import "encoding/json"

func (s *Signer) SignParams(m map[string]string) (string, error) {
	raw, _ := canonicalRaw(m)
	data, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	_ = raw
	return s.Sign(data)
}
`,
	}))
}
