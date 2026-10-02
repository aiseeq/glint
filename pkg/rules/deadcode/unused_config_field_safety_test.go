package deadcode

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// A provider marks a history item as scam; the client decodes the flag and
// nothing reads it, so scam transfers are imported as real ones.
func TestUnusedConfigFieldReportsUnreadPayloadSafetyFlag(t *testing.T) {
	violations := analyzeConfigFields(t, map[string]string{
		"loader.go": configLoader,
		"client.go": `package config

type Root struct {
	Items []HistoryItem ` + "`json:\"items\"`" + `
}

type HistoryItem struct {
	ID      string ` + "`json:\"id\"`" + `
	Chain   string ` + "`json:\"chain\"`" + `
	IsScam  bool   ` + "`json:\"is_scam\"`" + `
	Failed  bool   ` + "`json:\"failed\"`" + `
	Pending bool   ` + "`json:\"pending\"`" + `
}

func Import(r Root) []string {
	var ids []string
	for _, item := range r.Items {
		if item.Failed {
			continue
		}
		ids = append(ids, item.ID)
	}
	return ids
}
`,
	})
	var fields []string
	for _, v := range violations {
		fields = append(fields, v.Context["field"].(string))
	}
	assert.Equal(t, []string{"HistoryItem.IsScam"}, fields)
}

// The client decodes every response through its own helper that takes the
// target as any: the response types are decoded all the same.
func TestUnusedConfigFieldFollowsDecoderWrapper(t *testing.T) {
	violations := analyzeConfigFields(t, map[string]string{
		"client.go": `package config

import (
	"encoding/json"
	"io"
)

type Client struct{ body io.Reader }

func (c *Client) get(path string, out any) error {
	return json.NewDecoder(c.body).Decode(out)
}

type History struct {
	Items []Item ` + "`json:\"items\"`" + `
}

type Item struct {
	ID     string ` + "`json:\"id\"`" + `
	IsSpam bool   ` + "`json:\"is_spam\"`" + `
}

func (c *Client) Items() ([]string, error) {
	var out History
	if err := c.get("/history", &out); err != nil {
		return nil, err
	}
	var ids []string
	for _, item := range out.Items {
		ids = append(ids, item.ID)
	}
	return ids, nil
}
`,
	})
	var fields []string
	for _, v := range violations {
		fields = append(fields, v.Context["field"].(string))
	}
	assert.Equal(t, []string{"Item.IsSpam"}, fields)
}
