package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Repro from a real project: a list client followed the next link of each
// page, a URL the server put in its answer, through a method that always set
// the Authorization header - the token went to any host the server named.
func TestAuthHeaderSentToResponseURL(t *testing.T) {
	assert.Equal(t, []int{46}, appRuleLines(t, NewAuthHeaderSentToResponseURLRule(), `package app

import (
	"encoding/json"
	"net/http"
	"strings"
)

const base = "https://api.example.com/"

type Client struct {
	token string
	http  *http.Client
}

func (c *Client) url(path string) string {
	if strings.HasPrefix(path, "http") {
		return path
	}
	return base + path
}

func (c *Client) Get(path string, out any) error {
	req, err := http.NewRequest(http.MethodGet, c.url(path), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Token "+c.token)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return json.NewDecoder(resp.Body).Decode(out)
}

type page struct {
	Next    string   `+"`json:\"next\"`"+`
	Results []string `+"`json:\"results\"`"+`
}

func List(c *Client, path string) ([]string, error) {
	var all []string
	for path != "" {
		var p page
		if err := c.Get(path, &p); err != nil {
			return nil, err
		}
		all = append(all, p.Results...)
		path = p.Next
	}
	return all, nil
}
`))
}

// A header set only for the API's own host, or a pager that follows a
// counter rather than a URL from the answer, keeps the token home.
func TestAuthHeaderSentToResponseURLAccepts(t *testing.T) {
	assert.Empty(t, appRuleLines(t, NewAuthHeaderSentToResponseURLRule(), `package app

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

const base = "https://api.example.com/"

type Client struct {
	token string
	http  *http.Client
}

func (c *Client) Get(u string, out any) error {
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	if strings.HasPrefix(u, base) {
		req.Header.Set("Authorization", "Token "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return json.NewDecoder(resp.Body).Decode(out)
}

type page struct {
	Next    string
	Results []string
	More    bool
}

func List(c *Client, path string) ([]string, error) {
	var all []string
	for path != "" {
		var p page
		if err := c.Get(path, &p); err != nil {
			return nil, err
		}
		all = append(all, p.Results...)
		path = p.Next
	}
	return all, nil
}

type Signed struct{ token string }

func (s *Signed) Get(u string, out any) error {
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return json.NewDecoder(resp.Body).Decode(out)
}

func Pages(s *Signed) ([]string, error) {
	var all []string
	for n := 1; ; n++ {
		var p page
		if err := s.Get(fmt.Sprintf("%s?page=%d", base, n), &p); err != nil {
			return nil, err
		}
		all = append(all, p.Results...)
		if !p.More {
			return all, nil
		}
	}
}
`))
}

// Repro from a real project: the child process was killed on a failed dial
// and the function returned without Wait - the process stayed a zombie and
// its pipes open until the program ended.
func TestProcessKilledWithoutWait(t *testing.T) {
	assert.Equal(t, []int{22, 31}, appRuleLines(t, NewProcessKilledWithoutWaitRule(), `package app

import (
	"errors"
	"log/slog"
	"os/exec"
)

func dial() error { return errors.New("refused") }

func kill(cmd *exec.Cmd) {
	if err := cmd.Process.Kill(); err != nil {
		slog.Warn("kill", "err", err)
	}
}

func Start(cmd *exec.Cmd) error {
	if err := cmd.Start(); err != nil {
		return err
	}
	if err := dial(); err != nil {
		kill(cmd)
		return err
	}
	return nil
}

func Direct(cmd *exec.Cmd) error {
	_ = cmd.Start()
	if err := dial(); err != nil {
		_ = cmd.Process.Kill()
		return err
	}
	return cmd.Wait()
}
`))
}

// Kill followed by Wait, a deferred Wait, or a process handed back to the
// caller leaves no zombie.
func TestProcessKilledWithoutWaitAccepts(t *testing.T) {
	assert.Empty(t, appRuleLines(t, NewProcessKilledWithoutWaitRule(), `package app

import (
	"errors"
	"os/exec"
)

func dial() error { return errors.New("refused") }

func Stop(cmd *exec.Cmd) error {
	_ = cmd.Process.Kill()
	return cmd.Wait()
}

func Deferred(cmd *exec.Cmd) error {
	defer func() { _ = cmd.Wait() }()
	if err := dial(); err != nil {
		_ = cmd.Process.Kill()
		return err
	}
	return nil
}

func Handed(cmd *exec.Cmd) (*exec.Cmd, error) {
	if err := dial(); err != nil {
		_ = cmd.Process.Kill()
		return cmd, err
	}
	return cmd, nil
}
`))
}

// Repro from a real project: the old archive was removed before the new one
// was downloaded, and a failed download was only logged - the run ended
// with no archive at all and a success status.
func TestRemoveBeforeFailedReplacement(t *testing.T) {
	assert.Equal(t, []int{13}, appRuleLines(t, NewRemoveBeforeFailedReplacementRule(), `package app

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
)

func download(u, dst string) (bool, error) { return false, errors.New("timeout") }

func Pull(u, dst string) error {
	if err := os.Remove(dst); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("old copy: %w", err)
	}
	got, err := download(u, dst)
	if err != nil {
		slog.Warn("bot data", "err", err)
		return nil
	}
	_ = got
	return nil
}
`))
}

// A failed replacement that is returned, or a write into a temporary file
// renamed into place, does not hide the loss.
func TestRemoveBeforeFailedReplacementAccepts(t *testing.T) {
	assert.Empty(t, appRuleLines(t, NewRemoveBeforeFailedReplacementRule(), `package app

import (
	"errors"
	"os"
)

func download(u, dst string) (bool, error) { return false, errors.New("timeout") }

func Pull(u, dst string) error {
	_ = os.Remove(dst)
	if _, err := download(u, dst); err != nil {
		return err
	}
	return nil
}

func Seal(path string, data []byte) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.WriteFile(path, data, 0o444)
}
`))
}
