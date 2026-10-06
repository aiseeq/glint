package patterns

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// A Go server hands out a Next.js static export and revalidates the pages
// (.html, directory URLs) while every other file stays cacheable: the RSC
// payload of each page (index.txt) has no build hash in its URL either, the
// browser keeps the previous build's copy after a deploy, and the client
// rejects it by build id. Without a static export there is no payload, and a
// list that names .txt is fine.
func TestUnhashedBuildDataServedCacheable(t *testing.T) {
	server := `package web

import (
	"net/http"
	"strings"
)

func applyRevalidation(w http.ResponseWriter, urlPath string) {
	if strings.HasPrefix(urlPath, "/_next/static/") {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		return
	}
	isEntryPoint := strings.HasSuffix(urlPath, "/") ||
		strings.HasSuffix(urlPath, ".html") ||
		urlPath == "/manifest.json"
	if isEntryPoint {
		w.Header().Set("Cache-Control", "no-cache")
	}
}

func isPage(urlPath string) bool { return strings.HasSuffix(urlPath, ".html") }
`
	files := map[string]string{
		"web/static.go":               server,
		"frontend/app/next.config.js": "module.exports = {\n  output: 'export',\n  trailingSlash: true,\n}\n",
	}
	assert.Equal(t, []string{"web/static.go:14"}, projectFileFindings(t, NewUnhashedBuildDataServedCacheableRule(), files))

	files["frontend/app/next.config.js"] = "module.exports = { reactStrictMode: true }\n"
	assert.Empty(t, projectFileFindings(t, NewUnhashedBuildDataServedCacheableRule(), files))

	files["frontend/app/next.config.js"] = "module.exports = { output: \"export\" }\n"
	files["web/static.go"] = strings.Replace(server, `strings.HasSuffix(urlPath, ".html") ||`, `strings.HasSuffix(urlPath, ".html") || strings.HasSuffix(urlPath, ".txt") ||`, 1)
	assert.Empty(t, projectFileFindings(t, NewUnhashedBuildDataServedCacheableRule(), files))
}
