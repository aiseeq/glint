package patterns

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
)

// mentionsBinding replaces a regexp compiled per catch block; it must read the
// text exactly as that pattern did.
func TestMentionsBinding_MatchesTheRegexpItReplaces(t *testing.T) {
	cases := []struct{ text, name string }{
		{"toast.error(e.message)", "e"},
		{"toast.error('failed')", "e"},
		{"setError(err)", "err"},
		{"setError(error)", "err"},
		{"this.e = 1", "e"},
		{"$e.x", "e"},
		{"e", "e"},
		{"(e)", "e"},
		{"x.$err", "$err"},
		{" $err)", "$err"},
		{"foo$ bar", "foo$"},
		{"foo$bar", "foo$"},
		{"err2 + err", "err"},
		{"", "e"},
	}
	for _, c := range cases {
		want := regexp.MustCompile(`(?:^|[^A-Za-z0-9_$.])` + regexp.QuoteMeta(c.name) + `\b`).MatchString(c.text)
		assert.Equal(t, want, mentionsBinding(c.text, c.name), "%q in %q", c.name, c.text)
	}
}
