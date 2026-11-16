package main

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A report is checked in one read of its file and used in another: between
// the two reads the file can be replaced, so the digest or the PASS that is
// printed belongs to a file nobody checked.
const verifiedRereadAcceptGo = `package report

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"syscall"
)

func validate(data []byte) error {
	if bytes.Contains(data, []byte("FAIL")) {
		return errors.New("failed report")
	}
	return nil
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func passed(data []byte) bool { return bytes.Contains(data, []byte("PASS")) }

// The check reads one version, the digest is printed from another.
func DigestAfterCheck(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := validate(data); err != nil {
		return err
	}
	newer, err := os.ReadFile(path) // WANT
	if err != nil {
		return err
	}
	fmt.Println(digest(newer))
	return nil
}

// The digest of one read is compared with the accepted one, PASS comes from
// another read.
func PassAfterDigest(path, accepted string) (bool, error) {
	parsed, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	raw, err := os.ReadFile(path) // WANT
	if err != nil {
		return false, err
	}
	if digest(raw) != accepted {
		return false, errors.New("digest mismatch")
	}
	return passed(parsed), nil
}

// One read feeds the check and the digest.
func DigestOfChecked(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := validate(data); err != nil {
		return err
	}
	fmt.Println(digest(data))
	return nil
}

// One read feeds the digest check and the PASS.
func PassOfDigested(path, accepted string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	if digest(data) != accepted {
		return false, errors.New("digest mismatch")
	}
	return passed(data), nil
}

// The second read is compared with the checked one before it is used.
func RereadComparedWithChecked(path string) error {
	first, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := validate(first); err != nil {
		return err
	}
	second, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if !bytes.Equal(first, second) {
		return errors.New("report changed while it was checked")
	}
	fmt.Println(digest(second))
	return nil
}

// Both reads happen under an explicit lock of the file.
func RereadUnderLock(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_SH); err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := validate(data); err != nil {
		return err
	}
	newer, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	fmt.Println(digest(newer))
	return nil
}

// The check and the digest read different files.
func DigestOfOtherFile(checked, printed string) error {
	data, err := os.ReadFile(checked)
	if err != nil {
		return err
	}
	if err := validate(data); err != nil {
		return err
	}
	other, err := os.ReadFile(printed)
	if err != nil {
		return err
	}
	fmt.Println(digest(other))
	return nil
}
`

func verifiedRereadRoot(t *testing.T, files map[string]string) {
	t.Helper()
	root := t.TempDir()
	var want []string
	for name, content := range files {
		path := filepath.Join(root, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
		for i, line := range strings.Split(content, "\n") {
			if strings.Contains(line, "WANT") {
				want = append(want, fmt.Sprintf("%s:%d", name, i+1))
			}
		}
	}
	findings, _ := analyzeWithRules(t, root, nil, "verified-file-reread")
	got := foundAt(findings)
	slices.Sort(got)
	slices.Sort(want)
	assert.Equal(t, want, got)
}

func TestVerifiedFileRereadAcceptance(t *testing.T) {
	verifiedRereadRoot(t, map[string]string{
		"go.mod":      "module example.com/report\n\ngo 1.24\n",
		".glint.yaml": "version: 1\n",
		"report.go":   verifiedRereadAcceptGo,
	})
}
