package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
)

// broadTestsMessages writes a project and a settings.exclude of one pattern,
// and returns the messages of broad-exclusion over it.
func broadTestsMessages(t *testing.T, pattern string, files ...string) []string {
	t.Helper()
	root := t.TempDir()
	writeModuleFile(t, root, ".glint.yaml", "settings:\n  exclude:\n    - \""+pattern+"\"\n")
	for _, file := range files {
		writeModuleFile(t, root, file, "package fixture\n")
	}
	cfg, err := core.LoadConfigWithDefaults(root)
	require.NoError(t, err)
	var messages []string
	for _, finding := range broadFindingsForTest(t, cfg) {
		assert.Equal(t, 3, finding.Line)
		messages = append(messages, finding.Message)
	}
	return messages
}

// assertBroadTestsFinding checks the one finding an entry gives, by the start
// of its message; want "" is no finding at all.
func assertBroadTestsFinding(t *testing.T, messages []string, want string) {
	t.Helper()
	if want == "" {
		assert.Empty(t, messages)
		return
	}
	require.Len(t, messages, 1)
	assert.Contains(t, messages[0], want)
}

const (
	goTestsMessage  = "Exclusion covers every Go test file of the project"
	tsTestsMessage  = "Exclusion covers every TypeScript test file of the project"
	jsTestsMessage  = "Exclusion covers every JavaScript test file of the project"
	directoryReport = "Exclusion covers all source files in a project directory"
)

// settings.exclude that takes out every test file of a language while its
// code stays in the walk leaves the rules about tests nothing to read. A
// pattern without a separator matches the base name, as the walk matches it;
// a pattern over some tests, or over no test, is no finding. A whole
// directory taken out keeps its own message.
func TestBroadExclusionReportsEveryTestFileOfALanguage(t *testing.T) {
	mixed := []string{"cmd/app/main.go", "internal/svc/svc.go", "internal/svc/svc_test.go", "web/b.ts", "web/a.test.ts", "web/lib/c.js"}
	partial := []string{"cmd/app/main.go", "web/b.ts", "web/a.test.ts", "web/ui/v.tsx", "web/ui/v.test.tsx"}
	spec := []string{"cmd/app/main.go", "web/b.ts", "web/a.spec.ts", "web/d.js", "web/c.spec.js"}
	testsDir := []string{"p.go", "tests/y_test.go"}
	for _, tt := range []struct {
		name, pattern string
		files         []string
		want          string
	}{
		{"go tests at any depth", "**/*_test.go", mixed, goTestsMessage},
		{"go tests by base name", "*_test.go", mixed, goTestsMessage},
		{"go tests of the one package that has them", "internal/svc/*_test.go", mixed, goTestsMessage},
		{"ts tests at any depth", "**/*.test.ts", mixed, tsTestsMessage},
		{"ts tests by base name", "*.test.ts", mixed, tsTestsMessage},
		{"go tests of another tree", "legacy/**/*_test.go", mixed, ""},
		{"the one go test by its path", "internal/svc/svc_test.go", mixed, ""},
		{"go mocks", "**/*_mock.go", mixed, ""},
		{"a directory with code and tests", "internal/**", mixed, directoryReport},
		{"ts tests while tsx tests stay", "**/*.test.ts", partial, ""},
		{"ts and tsx tests", "**/*.test.{ts,tsx}", partial, tsTestsMessage},
		{"every test of any extension", "*.test.*", partial, tsTestsMessage},
		{"ts specs", "**/*.spec.ts", spec, tsTestsMessage},
		{"js specs", "**/*.spec.js", spec, jsTestsMessage},
		{"tests named otherwise", "**/*.test.ts", spec, ""},
		{"tests only directory by base name", "*_test.go", testsDir, goTestsMessage},
		{"tests only directory at any depth", "**/*_test.go", testsDir, directoryReport},
	} {
		t.Run(tt.name, func(t *testing.T) {
			assertBroadTestsFinding(t, broadTestsMessages(t, tt.pattern, tt.files...), tt.want)
		})
	}
}

// A test file is named by its language: Go by _test.go, TypeScript and
// JavaScript by .test or .spec before the extension.
func TestTestFileLanguage(t *testing.T) {
	for file, want := range map[string][2]string{
		"a/x_test.go":  {"Go", "test"},
		"a/x.go":       {"Go", ""},
		"a/x.test.ts":  {"TypeScript", "test"},
		"a/x.spec.mts": {"TypeScript", "test"},
		"a/x.tsx":      {"TypeScript", ""},
		"a/test.ts":    {"TypeScript", ""},
		"a/x.test.JS":  {"JavaScript", "test"},
		"a/x.spec.cjs": {"JavaScript", "test"},
		"a/x.jsx":      {"JavaScript", ""},
		"a/x.test.md":  {"", ""},
		"a/x_Test.go":  {"Go", ""},
		"a/x.Spec.ts":  {"TypeScript", ""},
	} {
		language, test := testFileLanguage(file)
		kind := ""
		if test {
			kind = "test"
		}
		assert.Equal(t, want, [2]string{language, kind}, file)
	}
}

// An exception of one rule for the tests is no finding: the rule may not fit
// tests, and the other rules still read them.
func TestBroadExclusionAllowsOneRuleExceptedForTests(t *testing.T) {
	root := t.TempDir()
	writeModuleFile(t, root, ".glint.yaml", "categories:\n  patterns:\n    rules:\n      error-wrap:\n        exceptions:\n          - files: \"**/*_test.go\"\n            reason: tests wrap nothing\n          - files: \"*.test.ts\"\n            reason: tests wrap nothing\n")
	for _, file := range []string{"internal/svc/svc.go", "internal/svc/svc_test.go", "web/b.ts", "web/a.test.ts"} {
		writeModuleFile(t, root, file, "package fixture\n")
	}
	cfg, err := core.LoadConfigWithDefaults(root)
	require.NoError(t, err)
	assert.Empty(t, broadFindingsForTest(t, cfg))
}

// settings.skip_dirs names a directory, not a glob: a name shaped like a
// test pattern takes out no test.
func TestBroadExclusionSkipDirsIsNoTestPattern(t *testing.T) {
	root := t.TempDir()
	writeModuleFile(t, root, ".glint.yaml", "settings:\n  skip_dirs:\n    - \"*_test.go\"\n")
	for _, file := range []string{"internal/svc/svc.go", "internal/svc/svc_test.go"} {
		writeModuleFile(t, root, file, "package fixture\n")
	}
	cfg, err := core.LoadConfigWithDefaults(root)
	require.NoError(t, err)
	assert.Empty(t, broadFindingsForTest(t, cfg))
}

// A marker with a reason keeps an exclusion of every test, on its line or the
// line above; one with the placeholder does not.
func TestBroadExclusionTestsMarker(t *testing.T) {
	root := t.TempDir()
	writeModuleFile(t, root, ".glint.yaml", "settings:\n  exclude:\n    # broad-exclusion: safe — the tests are checked by their own config\n    - \"**/*_test.go\"\n    - \"*.test.ts\" # broad-exclusion: safe — <reason>\n")
	for _, file := range []string{"internal/svc/svc.go", "internal/svc/svc_test.go", "web/b.ts", "web/a.test.ts"} {
		writeModuleFile(t, root, file, "package fixture\n")
	}
	cfg, err := core.LoadConfigWithDefaults(root)
	require.NoError(t, err)
	var lines []int
	for _, v := range broadFindingsForTest(t, cfg) {
		lines = append(lines, v.Line)
	}
	assert.Equal(t, []int{5}, lines)
}

// The configuration glint init writes is no broad exclusion in a project
// whose tests lie next to its code.
func TestInitConfigIsNoBroadExclusion(t *testing.T) {
	root := t.TempDir()
	for _, file := range []string{"cmd/app/main.go", "internal/svc/svc.go", "internal/svc/svc_test.go", "web/b.ts", "web/a.test.ts"} {
		writeModuleFile(t, root, file, "package fixture\n")
	}
	t.Chdir(root)
	require.NoError(t, runInit(nil, nil))
	cfg, err := core.LoadConfigWithDefaults(root)
	require.NoError(t, err)
	assert.Empty(t, broadFindingsForTest(t, cfg))
}
