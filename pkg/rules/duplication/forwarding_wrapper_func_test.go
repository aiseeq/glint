package duplication

import (
	"testing"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/assert"
)

func TestForwardingWrapperFunc(t *testing.T) {
	files := map[string]string{
		"shared/words.go": `package shared

func IsNameByte(c byte) bool { return c >= 'a' }
func Write(parts ...string) {}
func Pair(string, string) {}
func Ping() {}
`,
		"text/text.go": `package text

import "example.com/rulestest/shared"

func isIdentChar(c byte) bool { return shared.IsNameByte(c) }
func write(parts ...string) { shared.Write(parts...) }
func ping() { shared.Ping() }
`,
	}
	violations := rulestest.RunRuleOnFiles(t, NewForwardingWrapperFuncRule(), files)
	assert.Equal(t, []string{"text/text.go:5", "text/text.go:6", "text/text.go:7"}, rulestest.ViolationPlaces(violations))
	assert.Equal(t, "isIdentChar only forwards to shared.IsNameByte — call shared.IsNameByte directly", violations[0].Message)
}

func TestForwardingWrapperFuncIgnoresAdapters(t *testing.T) {
	files := map[string]string{
		"shared/shared.go": `package shared

type Client struct{}
func (Client) Send(string) {}
func Send(string) {}
func Convert(string) string { return "" }
func Pair(string, string) {}
`,
		"adapter/adapter.go": `package adapter

import (
	"fmt"
	"strings"
	"example.com/rulestest/shared"
)

func usedAsValue(s string) { consume(usedAsValue) }
func consume(any) {}
func constant(s string) { shared.Send("fixed") }
func converted(s string) { shared.Send(fmt.Sprint(s)) }
func method(c shared.Client, s string) { c.Send(s) }
func standard(s string) string { return fmt.Sprint(s) }
func external(s string) string { return strings.Clone(s) }
func reordered(a, b string) { shared.Pair(b, a) }
func extra(a string) { shared.Pair(a, "fixed") }
`,
		"adapter/adapter_test.go": `package adapter

import "example.com/rulestest/shared"

func testOnly(s string) { shared.Send(s) }
`,
	}
	assert.Empty(t, rulestest.ProjectRulePlaces(t, NewForwardingWrapperFuncRule(), files))
}

func TestForwardingWrapperFuncCalledFromAnotherFileOfPackage(t *testing.T) {
	files := map[string]string{
		"shared/words.go": `package shared

func IsNameByte(c byte) bool { return c >= 'a' }
`,
		"text/text.go": `package text

import "example.com/rulestest/shared"

func isIdentChar(c byte) bool { return shared.IsNameByte(c) }
`,
		"text/scan.go": `package text

func Scan(s string) bool { return isIdentChar(s[0]) }
`,
	}
	violations := rulestest.RunRuleOnFiles(t, NewForwardingWrapperFuncRule(), files)
	assert.Equal(t, []string{"text/text.go:5"}, rulestest.ViolationPlaces(violations))
}
