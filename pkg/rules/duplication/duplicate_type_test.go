package duplication

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

func duplicateTypeLines(t *testing.T, files map[string]string) []string {
	t.Helper()
	violations, err := NewDuplicateTypeAcrossPackagesRule().AnalyzeGoProject(rulestest.Project(t, files))
	require.NoError(t, err)
	var lines []string
	for _, v := range violations {
		lines = append(lines, v.File+":"+strconv.Itoa(v.Line))
	}
	return lines
}

// Two live copies of one handler: a fix (a new column in the insert) lands in
// one of them, and the other keeps writing rows without it.
func TestDuplicateTypeAcrossPackages(t *testing.T) {
	files := map[string]string{
		"models/models.go": `package models

type Deposit struct{ Amount string }
`,
		"cmd/app/main.go": `package main

import (
	"context"

	"example.com/rulestest/models"
)

type DepositHandler struct{ db any }

func (h *DepositHandler) ProcessDeposit(ctx context.Context, d *models.Deposit) (bool, error) {
	return true, nil
}

func main() {}
`,
		"routing/router.go": `package routing

import (
	"context"

	m "example.com/rulestest/models"
)

type DepositHandler struct{ store any }

func (h *DepositHandler) ProcessDeposit(ctx context.Context, d *m.Deposit) (bool, error) {
	return false, nil
}
`,
	}
	assert.Equal(t, []string{"cmd/app/main.go:9", "routing/router.go:9"}, duplicateTypeLines(t, files))
}

// The same name with other methods, a shared conventional method (String,
// Close), a mock package, and a one-word role name that its package qualifies
// (alpha.Client, beta.Client behind one interface) are not copies.
func TestDuplicateTypeAcrossPackagesAllowed(t *testing.T) {
	files := map[string]string{
		"a/a.go": `package a

type Config struct{ Port int }

func (c Config) String() string { return "" }

func (c *Config) Close() error { return nil }

type Service struct{}

func (s *Service) Run(n int) error { return nil }
`,
		"b/b.go": `package b

type Config struct{ Host string }

func (c Config) String() string { return "" }

func (c *Config) Close() error { return nil }

type Service struct{}

func (s *Service) Run(name string) error { return nil }
`,
		"providers/alpha/client.go": `package alpha

type Client struct{ key string }

func (c *Client) TotalBalance(address string) (float64, error) { return 1, nil }
`,
		"providers/beta/client.go": `package beta

type Client struct{ token string }

func (c *Client) TotalBalance(address string) (float64, error) { return 2, nil }
`,
		"a/mocks/service.go": `package mocks

type Service struct{}

func (s *Service) Run(n int) error { return nil }
`,
	}
	assert.Empty(t, duplicateTypeLines(t, files))
}
