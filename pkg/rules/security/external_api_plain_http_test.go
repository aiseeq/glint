package security

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// A public API reached over http:// sends the request and its credentials
// in clear text; a local service, a single-label container name, a reserved
// example host or an XML namespace is not such a call.
func TestExternalAPIURLPlainHTTP(t *testing.T) {
	code := `package rates

import "net/http"

const (
	defaultURL = "http://www.rates.bank-feed.ru/scripts/daily.xml"
	localURL   = "http://localhost:8080/rates"
	serviceURL = "http://rates-service:8080/rates"
	exampleURL = "http://api.example.com/v1"
	xsiNS      = "http://www.w3.org/2001/XMLSchema-instance"
	secureURL  = "https://www.rates.bank-feed.ru/scripts/daily.xml"
	greeting   = "http://see.the.docs"
)

type Config struct{ BaseURL, Name string }

var defaults = Config{BaseURL: "http://api.partner-gateway.io/v2", Name: "http://not.a.url.field"}

func fetch() (*http.Response, error) {
	return http.Get("http://feed.metals-exchange.com/latest")
}

func private() string { return "http://10.0.0.12/api" }

func callPlain() string { return private() }
`
	var lines []int
	for _, v := range NewExternalAPIURLPlainHTTPRule().AnalyzeFile(rulestest.GoFile(t, "rates/rates.go", code)) {
		lines = append(lines, v.Line)
	}
	assert.Equal(t, []int{6, 17, 20}, lines)
}
