package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
)

// oversightExceptionProject writes a project of two packages whose
// configuration lists the given exceptions of a rule watching suppressions;
// the first exception is on line 7.
func oversightExceptionProject(t *testing.T, rule, exceptions string) string {
	t.Helper()
	root := t.TempDir()
	writeModuleFile(t, root, ".glint.yaml", "version: 1\ncategories:\n  deadcode:\n    rules:\n      "+rule+":\n        exceptions:\n"+exceptions)
	writeModuleFile(t, root, "go.mod", "module example.com/projecta\n\ngo 1.22\n")
	writeModuleFile(t, root, "cmd/app/main.go", "package main\n\nfunc main() {}\n")
	writeModuleFile(t, root, "internal/payprov/client.go", "package payprov\n\n// nolint:hardcoded-secret\nvar Token = \"tok\"\n")
	writeModuleFile(t, root, "internal/payprov/refund.go", "package payprov\n")
	return root
}

// An exception of a rule watching suppressions takes that watch away from
// whatever it covers: with suppression-without-reason excepted by a pattern,
// a function, a line in every file or a directory, a marker with no reason
// silences hardcoded-secret unseen. Only exceptions naming whole files over
// the whole project were findings; each exception wider than one line of one
// file is one now, on the line of the exception, whatever narrows it.
func TestBroadExclusionReportsOversightRuleException(t *testing.T) {
	for _, rule := range oversightRules {
		for name, exception := range map[string]string{
			"pattern":                "          - pattern: \"Suppression\"\n            reason: legacy markers\n",
			"function":               "          - function: Charge\n            reason: legacy markers\n",
			"line in every file":     "          - line: 3\n            reason: legacy markers\n",
			"files with a pattern":   "          - files: \"**\"\n            pattern: \"reason\"\n            reason: legacy markers\n",
			"directory":              "          - files: \"internal/**\"\n            reason: legacy markers\n",
			"one whole file":         "          - files: internal/payprov/client.go\n            reason: legacy markers\n",
			"one file by file":       "          - file: internal/payprov/client.go\n            reason: legacy markers\n",
			"one file and a pattern": "          - files: internal/payprov/client.go\n            pattern: \"Suppression\"\n            reason: legacy markers\n",
			"reason first":           "          - reason: legacy markers\n            files: \"internal/**\"\n",
			"a line of a glob":       "          - files: \"**/client.go\"\n            line: 3\n            reason: legacy markers\n",
			"line zero of one file":  "          - files: internal/payprov/client.go\n            line: 0\n            reason: legacy markers\n",
			"a line of no file":      "          - files: \"\"\n            line: 3\n            reason: legacy markers\n",
			"a line of a base name":  "          - file: client.go\n            line: 3\n            reason: legacy markers\n",
		} {
			t.Run(rule+"/"+name, func(t *testing.T) {
				root := oversightExceptionProject(t, rule, exception)
				// A second client.go: a base name or a glob of it names two files.
				writeModuleFile(t, root, "internal/ledger/client.go", "package ledger\n")
				cfg, err := core.LoadConfigWithDefaults(root)
				require.NoError(t, err)
				found := broadFindingsForTest(t, cfg)
				require.Len(t, found, 1)
				assert.Equal(t, ".glint.yaml", found[0].File)
				assert.Equal(t, 7, found[0].Line)
				assert.Contains(t, found[0].Message, rule)
			})
		}
	}
}

// An exception of one line of one file - the file by its path, or by a base
// name or a glob only one file of the project has, matched as the exception
// matches: file and files both - keeps one marker and is no finding.
// Exceptions of other rules keep their judgement: a pattern or a directory
// is none.
func TestBroadExclusionAllowsOversightRuleExceptionOfOneLine(t *testing.T) {
	for _, rule := range oversightRules {
		for name, exception := range map[string]string{
			"files and line":     "          - files: internal/payprov/client.go\n            line: 3\n            reason: one legacy marker\n",
			"file and line":      "          - file: internal/payprov/client.go\n            line: 3\n            reason: one legacy marker\n",
			"unique base name":   "          - file: client.go\n            line: 3\n            reason: one legacy marker\n",
			"and a pattern":      "          - files: internal/payprov/client.go\n            line: 3\n            pattern: \"Suppression\"\n            reason: one legacy marker\n",
			"the first line":     "          - files: internal/payprov/client.go\n            line: 1\n            reason: one legacy marker\n",
			"a glob of one file": "          - files: \"**/client.go\"\n            line: 3\n            reason: one legacy marker\n",
			"a file in a glob":   "          - file: internal/payprov/client.go\n            files: \"**/*.go\"\n            line: 3\n            reason: one legacy marker\n",
		} {
			t.Run(rule+"/"+name, func(t *testing.T) {
				assert.Empty(t, broadPlaces(t, oversightExceptionProject(t, rule, exception)))
			})
		}
	}
	other := "          - pattern: \"wrap\"\n            reason: wrappers\n          - files: \"internal/**\"\n            reason: one tree\n"
	assert.Empty(t, broadPlaces(t, oversightExceptionProject(t, "unused-internal-export", other)))
	// The exception of one line goes, the wide one next to it stays.
	both := "          - file: client.go\n            line: 3\n            reason: one legacy marker\n          - pattern: \"Suppression\"\n            reason: legacy markers\n"
	assert.Equal(t, []string{".glint.yaml:10"}, broadPlaces(t, oversightExceptionProject(t, "suppression-without-reason", both)))
}

// A file settings.exclude or settings.skip_dirs takes out is analyzed by no
// rule, so a base name it shares names one file all the same: the exception
// of its line is none, while the exclusion is judged by itself.
func TestBroadExclusionOversightRuleExceptionOfOneLineLeavesExcludedFilesOut(t *testing.T) {
	for settings, want := range map[string][]string{
		"settings:\n  exclude:\n    - \"retired/**\"\n":   {".glint.yaml:3"},
		"settings:\n  skip_dirs:\n    - retired\n":        {".glint.yaml:3"},
		"settings:\n  exclude:\n    - \"retired/*.md\"\n": {".glint.yaml:9"},
	} {
		root := oversightExceptionProject(t, "suppression-without-reason", "          - file: client.go\n            line: 3\n            reason: one legacy marker\n")
		writeModuleFile(t, root, ".glint.yaml", settings+"categories:\n  deadcode:\n    rules:\n      suppression-without-reason:\n        exceptions:\n          - file: client.go\n            line: 3\n            reason: one legacy marker\n")
		writeModuleFile(t, root, "retired/payprov/client.go", "package payprov\n")
		assert.Equal(t, want, broadPlaces(t, root), settings)
	}
}

// An exception of one line of a file named by its path keeps one file
// whatever the tree holds: telling it needs no walk, so a directory the user
// cannot read fails no run.
func TestBroadExclusionOversightRuleExceptionOfAPathReadsNoTree(t *testing.T) {
	for _, key := range []string{"files", "file"} {
		t.Run(key, func(t *testing.T) {
			root := oversightExceptionProject(t, "suppression-without-reason", "          - "+key+": internal/payprov/client.go\n            line: 3\n            reason: one legacy marker\n")
			writeModuleFile(t, root, "pgdata/base/PG_VERSION", "16\n")
			locked := filepath.Join(root, "pgdata")
			require.NoError(t, os.Chmod(locked, 0))
			t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })
			if _, err := os.ReadDir(locked); err == nil {
				t.Skip("running with permission to read a mode 000 directory")
			}
			assert.Empty(t, broadPlaces(t, root))
		})
	}
}

// A marker of broad-exclusion with a reason keeps an exception of a rule
// watching suppressions as it keeps every broad entry: on a line of its own
// above the exception, or at the end of the exception's line. One at the end
// of a line keeps that line alone, not the next exception of the list.
func TestBroadExclusionOversightRuleExceptionMarker(t *testing.T) {
	for exceptions, want := range map[string][]string{
		"          # broad-exclusion: safe — markers of the vendored client are checked upstream\n          - files: \"internal/**\"\n            reason: legacy markers\n":                             nil,
		"          - files: \"internal/**\" # broad-exclusion: safe — checked upstream\n            reason: legacy markers\n":                                                                           nil,
		"          - files: \"internal/**\" # broad-exclusion: safe — checked upstream\n            reason: legacy markers\n          - pattern: \"Suppression\"\n            reason: legacy markers\n": {".glint.yaml:9"},
		"          # broad-exclusion: safe\n          - files: \"internal/**\"\n            reason: legacy markers\n":                                                                                   {".glint.yaml:8"},
	} {
		assert.Equal(t, want, broadPlaces(t, oversightExceptionProject(t, "suppression-without-reason", exceptions)), exceptions)
	}
}

// broad-exclusion switched off by name still reports an exception of
// another rule watching suppressions: it is a switch of that watch too.
func TestBroadExclusionSwitchedOffReportsOversightRuleException(t *testing.T) {
	root := oversightExceptionProject(t, "suppression-without-reason", "          - pattern: \"Suppression\"\n            reason: legacy markers\n      broad-exclusion:\n        enabled: false\n  patterns:\n    rules:\n      error-wrap:\n        exceptions:\n          - files: \"**\"\n            reason: everywhere\n")
	assert.Equal(t, []string{".glint.yaml:7", ".glint.yaml:10"}, broadPlaces(t, root))
}
