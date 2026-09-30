package security

import (
	"fmt"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// A key function that returns the key without looking at the algorithm the
// token names lets the token choose how it is verified.
func TestJWTParseValidationReportsUncheckedAlgorithm(t *testing.T) {
	code := `package auth

import (
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

type Claims struct{ jwt.RegisteredClaims }

func parseCookie(value, secret string) (*Claims, error) {
	claims := &Claims{}
	_, err := jwt.ParseWithClaims(value, claims, func(token *jwt.Token) (any, error) {
		return []byte(secret), nil
	})
	return claims, err
}

func parseChecked(value, secret string) (*jwt.Token, error) {
	return jwt.Parse(value, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})
}

func parseWithOption(value, secret string) (*jwt.Token, error) {
	return jwt.Parse(value, func(*jwt.Token) (any, error) { return []byte(secret), nil },
		jwt.WithValidMethods([]string{"HS256"}))
}

func parseWithParser(value, secret string) (*jwt.Token, error) {
	parser := jwt.NewParser(jwt.WithValidMethods([]string{"HS256"}))
	return parser.Parse(value, func(*jwt.Token) (any, error) { return []byte(secret), nil })
}

type verifier struct{ secret string }

func (v *verifier) keyFor(token *jwt.Token) (any, error) {
	if token.Method != jwt.SigningMethodHS256 {
		return nil, fmt.Errorf("unexpected signing method")
	}
	return []byte(v.secret), nil
}

func (v *verifier) parse(value string) (*jwt.Token, error) {
	return jwt.Parse(value, func(token *jwt.Token) (any, error) { return v.keyFor(token) })
}

func (v *verifier) parseByMethodValue(value string) (*jwt.Token, error) {
	return jwt.Parse(value, v.keyFor)
}

func (v *verifier) parseByUnknown(value string, keyfunc jwt.Keyfunc) (*jwt.Token, error) {
	return jwt.Parse(value, keyfunc)
}
`
	assert.Equal(t, []int{13}, ruleLines(t, NewJWTParseValidationRule(), code))
}

// A key taken from an identity provider's key set verifies every token the
// provider signs, for any application: without the issuer and the audience a
// token issued for someone else passes. The key set may be fetched anywhere
// in the file and handed to the function that parses; a shared secret of the
// application is not from a key set.
func TestJWTParseValidationReportsKeySetWithoutIssuerAudience(t *testing.T) {
	code := `package auth

import (
	"errors"
	"fmt"

	jwtlib "github.com/golang-jwt/jwt/v5"
)

type verifier struct{ keys map[string]any; issuer string }

func (v *verifier) parse(tokenString, kid string) (*jwtlib.RegisteredClaims, error) {
	claims := &jwtlib.RegisteredClaims{}
	_, err := jwtlib.ParseWithClaims(tokenString, claims, func(token *jwtlib.Token) (any, error) {
		if _, ok := token.Method.(*jwtlib.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return v.keys[kid], nil
	})
	return claims, err
}

func (v *verifier) parseChecked(tokenString, kid string) (*jwtlib.RegisteredClaims, error) {
	claims := &jwtlib.RegisteredClaims{}
	_, err := jwtlib.ParseWithClaims(tokenString, claims, func(token *jwtlib.Token) (any, error) {
		return v.keys[kid], nil
	}, jwtlib.WithValidMethods([]string{"ES256"}), jwtlib.WithIssuer(v.issuer), jwtlib.WithAudience("authenticated"))
	return claims, err
}

func (v *verifier) parseSession(tokenString, secret string) (*jwtlib.Token, error) {
	return jwtlib.Parse(tokenString, func(token *jwtlib.Token) (any, error) {
		if _, ok := token.Method.(*jwtlib.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return []byte(secret), nil
	})
}
`
	assert.Equal(t, []int{14}, ruleLines(t, NewJWTParseValidationRule(), code))

	compared := `package auth

import (
	"errors"

	jwtlib "github.com/golang-jwt/jwt/v5"
)

type verifier struct{ keys map[string]any; issuer string }

func (v *verifier) parseThenCompare(tokenString string) (*jwtlib.RegisteredClaims, error) {
	claims := &jwtlib.RegisteredClaims{}
	_, err := jwtlib.ParseWithClaims(tokenString, claims, func(token *jwtlib.Token) (any, error) {
		kid, _ := token.Header["kid"].(string)
		return v.keys[kid], nil
	}, jwtlib.WithValidMethods([]string{"ES256"}))
	if err != nil {
		return nil, err
	}
	if claims.Issuer != v.issuer {
		return nil, errors.New("issuer")
	}
	return claims, nil
}
`
	assert.Empty(t, ruleLines(t, NewJWTParseValidationRule(), compared))

	helper := `package auth

import (
	"crypto/ecdsa"
	"fmt"

	"github.com/golang-jwt/jwt/v4"
)

type jwksResponse struct{ Keys []map[string]string }

func verifyWithKey(tokenString string, publicKey *ecdsa.PublicKey) (*jwt.RegisteredClaims, error) {
	claims := &jwt.RegisteredClaims{}
	_, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return publicKey, nil
	})
	return claims, err
}
`
	assert.Equal(t, []int{14}, ruleLines(t, NewJWTParseValidationRule(), helper))
}

func jwtTokenTypePlaces(t *testing.T, files map[string]string) []string {
	t.Helper()
	violations, err := NewJWTTokenTypeRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	var places []string
	for _, v := range violations {
		places = append(places, fmt.Sprintf("%s:%d", v.File, v.Line))
	}
	slices.Sort(places)
	return places
}

// Claims that say which kind of token they are — access or refresh — are
// read by a refresh without looking at the kind: an access token refreshes
// the session.
func TestJWTTokenTypeUnchecked(t *testing.T) {
	places := jwtTokenTypePlaces(t, map[string]string{
		"claims.go": `package auth

type RegisteredClaims struct{ Subject string }

type TokenClaims struct {
	RegisteredClaims
	UserID    string
	TokenType string
}

type Result struct{ Data *TokenClaims }

type Validator interface{ Validate(token string) (*Result, error) }
`,
		"manager.go": `package auth

import "errors"

type Manager struct{ validator Validator }

func (m *Manager) RefreshTokens(refreshToken string) (string, error) {
	result, err := m.validator.Validate(refreshToken)
	if err != nil {
		return "", err
	}
	claims := result.Data
	return claims.UserID, nil
}

func (m *Manager) RefreshChecked(refreshToken string) (string, error) {
	result, err := m.validator.Validate(refreshToken)
	if err != nil {
		return "", err
	}
	claims := result.Data
	if claims.TokenType != "refresh" {
		return "", errors.New("not a refresh token")
	}
	return claims.UserID, nil
}

func (m *Manager) UserOf(token string) (string, error) {
	result, err := m.validator.Validate(token)
	if err != nil {
		return "", err
	}
	return result.Data.UserID, nil
}
`,
	})
	assert.Equal(t, []string{"manager.go:12"}, places)
}
