package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPublishVerifiedKeepsThePreviousBinaryWhenVerificationFails(t *testing.T) {
	out := filepath.Join(t.TempDir(), "glint")
	require.NoError(t, os.WriteFile(out, []byte("previous"), 0o755))
	link := func(path string) error { return os.WriteFile(path, []byte("changed during build"), 0o755) }
	stale := errors.New("Go package BuildIDs changed during the graft build")

	err := publishVerified(out, link, func() error { return stale })

	require.ErrorIs(t, err, stale)
	got, err := os.ReadFile(out)
	require.NoError(t, err)
	assert.Equal(t, "previous", string(got))
	assert.NoFileExists(t, out+".unverified")
}

func TestPublishVerifiedReplacesTheBinaryAfterVerification(t *testing.T) {
	out := filepath.Join(t.TempDir(), "glint")
	require.NoError(t, os.WriteFile(out, []byte("previous"), 0o755))
	link := func(path string) error { return os.WriteFile(path, []byte("verified"), 0o755) }

	require.NoError(t, publishVerified(out, link, func() error { return nil }))

	got, err := os.ReadFile(out)
	require.NoError(t, err)
	assert.Equal(t, "verified", string(got))
	assert.NoFileExists(t, out+".unverified")
}
