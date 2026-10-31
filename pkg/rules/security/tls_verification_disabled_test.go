package security

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

func TestTLSVerificationDisabledUsesGoTypes(t *testing.T) {
	files := map[string]string{
		"client.go": `package client

import "crypto/tls"

type Options struct{ InsecureSkipVerify bool }

func configure() {
	c := &tls.Config{}
	c.InsecureSkipVerify = true
	o := Options{}
	o.InsecureSkipVerify = true
	_ = Options{InsecureSkipVerify: true}
	_ = &tls.Config{InsecureSkipVerify: true}
}
`,
	}
	project := rulestest.Project(t, files)
	var places []string
	for _, violation := range rulestest.RunRuleOnProject(t, NewTLSVerificationDisabledRule(), project) {
		places = append(places, fmt.Sprintf("%s:%d", violation.File, violation.Line))
	}
	assert.ElementsMatch(t, []string{"client.go:9", "client.go:13"}, places)
}

func TestTLSVerificationDisabledNeedsTypedProjectForAnalyzedFiles(t *testing.T) {
	rule := NewTLSVerificationDisabledRule()
	for _, path := range []string{"client.go", "client.js", "client.ts"} {
		ctx := core.NewFileContext("/project/"+path, "/project", nil, nil)
		assert.True(t, rule.NeedsTypedGoProject([]*core.FileContext{ctx}), path)
	}
	other := core.NewFileContext("/project/README.md", "/project", nil, nil)
	assert.False(t, rule.NeedsTypedGoProject([]*core.FileContext{other}))
}

func TestTLSVerificationDisabledScriptObjectKeys(t *testing.T) {
	script := `const a = { rejectUnauthorized: false };
const b = { "rejectUnauthorized": false };
const c = "rejectUnauthorized: false";
const d = { not_rejectUnauthorized: false, $rejectUnauthorized: false };
const e = {a:1,rejectUnauthorized:false};
`
	assert.Equal(t, []int{1, 2, 5}, rulestest.SourceFileRuleLines(t, NewTLSVerificationDisabledRule(), "client.js", script))
}

func TestTLSVerificationDisabledMultilineScriptObjectKeys(t *testing.T) {
	script := `const agent = new https.Agent({
  keepAlive: true,
  rejectUnauthorized: false,
});
const opts = {
  "rejectUnauthorized": false
};
const note = "{ rejectUnauthorized: false }";
// rejectUnauthorized: false
`
	assert.Equal(t, []int{3, 6}, rulestest.SourceFileRuleLines(t, NewTLSVerificationDisabledRule(), "client.js", script))
}
