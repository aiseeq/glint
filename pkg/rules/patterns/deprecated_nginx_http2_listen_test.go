package patterns

import (
	"strings"
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/stretchr/testify/assert"
)

func TestDeprecatedNginxHTTP2ListenRule_Metadata(t *testing.T) {
	rule := NewDeprecatedNginxHTTP2ListenRule()
	assert.Equal(t, "deprecated-nginx-http2-listen", rule.Name())
	assert.Equal(t, "patterns", rule.Category())
	assert.Equal(t, core.SeverityMedium, rule.DefaultSeverity())
}

func TestDeprecatedNginxHTTP2ListenRule_Detection(t *testing.T) {
	tests := []struct {
		name string
		path string
		code string
		want int
	}{
		{name: "deprecated IPv4 listen", path: "nginx.conf", code: "server {\n  listen 443 ssl http2;\n}", want: 1},
		{name: "deprecated IPv6 listen", path: "site.conf", code: "listen [::]:443 ssl http2;", want: 1},
		{name: "multiline deprecated listen", path: "site.conf", code: "listen 443 ssl\n       http2;", want: 1},
		{name: "modern syntax", path: "site.conf", code: "listen 443 ssl;\nhttp2 on;", want: 0},
		{name: "commented legacy syntax", path: "site.conf", code: "# listen 443 ssl http2;", want: 0},
		{name: "non nginx file", path: "notes.md", code: "listen 443 ssl http2;", want: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &core.FileContext{Path: "/" + tt.path, RelPath: tt.path, Content: []byte(tt.code), Lines: strings.Split(tt.code, "\n")}
			assert.Len(t, NewDeprecatedNginxHTTP2ListenRule().AnalyzeFile(ctx), tt.want)
		})
	}
}
