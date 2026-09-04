package patterns

import (
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
)

func init() {
	rules.Register(NewHTTPErrorPlaintextRule())
}

// HTTPErrorPlaintextRule detects http.Error in handlers of a JSON API.
//
// http.Error writes the message as text/plain. A client that parses every
// response as JSON fails on such a body with a parser exception, so the user
// sees "Unexpected token" instead of the reason the request was rejected —
// and the layer that rejected the request stays invisible in the client logs.
type HTTPErrorPlaintextRule struct {
	*rules.BaseRule
}

// NewHTTPErrorPlaintextRule creates the rule
func NewHTTPErrorPlaintextRule() *HTTPErrorPlaintextRule {
	return &HTTPErrorPlaintextRule{
		BaseRule: rules.NewBaseRule(
			"http-error-plaintext",
			"patterns",
			"Detects http.Error in a JSON API: the text/plain body breaks clients that parse responses as JSON",
			core.SeverityMedium,
		),
	}
}

// nonJSONContentTypes mark a handler whose body is read by something other than
// a JSON client: browsers following a redirect, EventSource, image and file
// responses. http.Error is a fine answer there.
var nonJSONContentTypes = []string{
	"text/event-stream",
	"text/html",
	"text/csv",
	"image/",
	"application/pdf",
	"application/octet-stream",
}

// externalConsumerPaths mark handlers whose caller is not our own client:
// provider webhooks and streaming endpoints answer by status code, and their
// body format is dictated by the other side.
var externalConsumerPaths = []string{
	"webhook",
	"callback",
	"/sse/",
	"sse_",
	"_sse",
}

// AnalyzeFile checks for plain-text error responses in JSON handlers
func (r *HTTPErrorPlaintextRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() || ctx.IsTestFile() {
		return nil
	}
	if r.servesExternalConsumer(ctx.RelPath) || r.servesNonJSONBody(ctx.Content) {
		return nil
	}

	var violations []*core.Violation
	for lineNum, line := range ctx.Lines {
		if !r.isHTTPErrorCall(line) {
			continue
		}
		v := r.CreateViolation(ctx.RelPath, lineNum+1,
			"http.Error replies with a text/plain body: a JSON client fails on parsing it instead of showing the reason")
		v.WithCode(strings.TrimSpace(line))
		v.WithSuggestion("Reply with the same JSON error envelope the rest of the API uses")
		violations = append(violations, v)
	}
	return violations
}

func (r *HTTPErrorPlaintextRule) isHTTPErrorCall(line string) bool {
	const call = "http.Error("
	if !strings.Contains(line, call) {
		return false
	}
	if helpers.IsInsideString(line, call) || helpers.IsInsideBackticks(line, call) || helpers.IsInComment(line, call) {
		return false
	}
	return true
}

func (r *HTTPErrorPlaintextRule) servesExternalConsumer(relPath string) bool {
	lower := strings.ToLower(relPath)
	for _, marker := range externalConsumerPaths {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func (r *HTTPErrorPlaintextRule) servesNonJSONBody(content []byte) bool {
	text := string(content)
	for _, contentType := range nonJSONContentTypes {
		if strings.Contains(text, contentType) {
			return true
		}
	}
	return false
}
