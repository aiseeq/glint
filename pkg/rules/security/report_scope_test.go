package security

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
	"github.com/stretchr/testify/require"
)

func TestProjectRulesReportScopeMatchesFilteredFullRun(t *testing.T) {
	for _, tc := range []struct {
		name  string
		files map[string]string
		rule  func() interface {
			AnalyzeGoProject(*core.GoProjectContext) ([]*core.Violation, error)
		}
		want int
	}{
		{name: "identity read remains when B does not set", files: map[string]string{
			"a.go": "package sample\nimport \"net/http\"\nfunc Read(r *http.Request) { _ = r.Header.Get(\"X-User-ID\") }\n",
			"b.go": "package sample\nfunc Other() {}\n",
		}, rule: func() interface {
			AnalyzeGoProject(*core.GoProjectContext) ([]*core.Violation, error)
		} {
			return NewIdentityHeaderFromClientRule()
		}, want: 1},
		{name: "identity read is cleared when B sets", files: map[string]string{
			"a.go": "package sample\nimport \"net/http\"\nfunc Read(r *http.Request) { _ = r.Header.Get(\"X-User-ID\") }\n",
			"b.go": "package sample\nimport \"net/http\"\nfunc Set(r *http.Request) { r.Header.Set(\"X-User-ID\", \"verified\") }\n",
		}, rule: func() interface {
			AnalyzeGoProject(*core.GoProjectContext) ([]*core.Violation, error)
		} {
			return NewIdentityHeaderFromClientRule()
		}, want: 0},
		{name: "cookie deletion mismatch is reported from A", files: map[string]string{
			"a.go": "package sample\nimport (\"net/http\"; \"time\")\nfunc Delete(w http.ResponseWriter) { http.SetCookie(w, &http.Cookie{Name: \"session\", Path: \"/\", MaxAge: -1, Expires: time.Unix(0, 0)}) }\n",
			"b.go": "package sample\nimport \"net/http\"\nfunc Set(w http.ResponseWriter) { http.SetCookie(w, &http.Cookie{Name: \"session\", Path: \"/\", Domain: \"example.test\"}) }\n",
		}, rule: func() interface {
			AnalyzeGoProject(*core.GoProjectContext) ([]*core.Violation, error)
		} {
			return NewCookieDeletedWithOtherAttributesRule()
		}, want: 1},
		{name: "cookie deletion matches B attributes", files: map[string]string{
			"a.go": "package sample\nimport (\"net/http\"; \"time\")\nfunc Delete(w http.ResponseWriter) { http.SetCookie(w, &http.Cookie{Name: \"session\", Path: \"/\", MaxAge: -1, Expires: time.Unix(0, 0)}) }\n",
			"b.go": "package sample\nimport \"net/http\"\nfunc Set(w http.ResponseWriter) { http.SetCookie(w, &http.Cookie{Name: \"session\", Path: \"/\"}) }\n",
		}, rule: func() interface {
			AnalyzeGoProject(*core.GoProjectContext) ([]*core.Violation, error)
		} {
			return NewCookieDeletedWithOtherAttributesRule()
		}, want: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			project := rulestest.Project(t, tc.files)
			full, err := tc.rule().AnalyzeGoProject(project)
			require.NoError(t, err)
			var a *core.FileContext
			for _, file := range project.Files {
				if file.RelPath == "a.go" {
					a = file
				}
			}
			require.NotNil(t, a)
			project.SetReportFiles([]*core.FileContext{a})
			partial, err := tc.rule().AnalyzeGoProject(project)
			require.NoError(t, err)
			var expected []*core.Violation
			for _, finding := range full {
				if finding.File == "a.go" {
					expected = append(expected, finding)
				}
			}
			require.Len(t, expected, tc.want)
			require.Equal(t, expected, partial)
		})
	}
}
