package main

import (
	"fmt"
	"io/fs"
	"maps"
	"path/filepath"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/aiseeq/glint/pkg/core"
)

// broadModelConfigs are the configurations the model of broad-exclusion is
// compared on: those of the probes of earlier rounds and forms of YAML that
// spell one value in several ways (tags, quotes, flow, null, duplicate keys
// of one value).
const broadModelConfigs = "testdata/broadmodel"

// exceptionFact is one exception as the model holds it.
func exceptionFact(category, rule string, exc core.Exception) string {
	return fmt.Sprintf("exception %s/%s file=%q files=%q line=%d pattern=%q function=%q", category, rule, exc.File, exc.Files, exc.Line, exc.Pattern, exc.Function)
}

// loadedModel is what the load makes of a configuration and its extends
// chain: the lists of settings, the categories and rules it names, whether
// each is on, and the exceptions of each rule.
func loadedModel(cfg *core.Config) []string {
	var facts []string
	for _, pattern := range cfg.Settings.Exclude {
		facts = append(facts, "exclude "+pattern)
	}
	for _, name := range cfg.Settings.SkipDirs {
		facts = append(facts, "skip_dirs "+name)
	}
	for _, category := range slices.Sorted(maps.Keys(cfg.Categories)) {
		categoryCfg := cfg.Categories[category]
		facts = append(facts, fmt.Sprintf("category %s enabled=%t", category, categoryCfg.Enabled))
		for _, rule := range slices.Sorted(maps.Keys(categoryCfg.Rules)) {
			facts = append(facts, fmt.Sprintf("rule %s/%s enabled=%t", category, rule, categoryCfg.Rules[rule].Enabled))
			for _, exc := range categoryCfg.Rules[rule].Exceptions {
				facts = append(facts, exceptionFact(category, rule, exc))
			}
		}
	}
	slices.Sort(facts)
	return facts
}

// broadModel is what broad-exclusion reads of the same chain: the lists of
// settings in effect (firstBroadSetting), the categories and rules the files
// name, each placed at the node in effect (firstBroadNode), and the
// exceptions of each rule in effect (broadExceptionLists), read as
// broad-exclusion reads them.
func broadModel(t *testing.T, chain []broadConfigFile) []string {
	t.Helper()
	var facts []string
	for _, key := range []string{"exclude", "skip_dirs"} {
		_, list := firstBroadSetting(chain, key)
		for _, value := range list {
			facts = append(facts, key+" "+value.Value)
		}
	}
	named := make(map[string]bool)
	for _, file := range chain {
		forEachPair(configNode(file.top, "categories"), func(category, categoryNode *yaml.Node) {
			if !named[category.Value] {
				named[category.Value] = true
				_, node := firstBroadNode(chain, category.Value)
				var decoded core.CategoryConfig
				require.NoError(t, node.Decode(&decoded))
				facts = append(facts, fmt.Sprintf("category %s enabled=%t", category.Value, decoded.Enabled))
			}
			forEachPair(configNode(categoryNode, "rules"), func(rule, _ *yaml.Node) {
				if key := category.Value + "/" + rule.Value; !named[key] {
					named[key] = true
					_, node := firstBroadNode(chain, category.Value, "rules", rule.Value)
					var decoded core.RuleConfig
					require.NoError(t, node.Decode(&decoded))
					facts = append(facts, fmt.Sprintf("rule %s enabled=%t", key, decoded.Enabled))
				}
			})
		})
	}
	for _, list := range broadExceptionLists(chain) {
		for _, exception := range broadListItems(list.exceptions) {
			decoded, err := decodeBroadException(exception, list.rule)
			require.NoError(t, err)
			facts = append(facts, exceptionFact(list.category, list.rule, decoded))
		}
	}
	slices.Sort(facts)
	return facts
}

// broad-exclusion judges a configuration by the YAML nodes, the load by
// what yaml.v3 decodes of them. Where the two part, a switch or an exception
// is in effect that broad-exclusion does not see: a !!binary category or
// rule key switched a watch off without a finding, a !!binary exclude, skip
// directory or exception glob took sources out unjudged. On every
// configuration the load accepts, broad-exclusion now reads the same lists,
// switches and exceptions as the load.
func TestBroadExclusionReadsTheConfigurationAsTheLoad(t *testing.T) {
	var paths []string
	require.NoError(t, filepath.WalkDir(broadModelConfigs, func(path string, entry fs.DirEntry, err error) error {
		if err == nil && entry.Name() == "glint.yaml" {
			paths = append(paths, path)
		}
		return err
	}))
	compared := 0
	var refused []string
	for _, path := range paths {
		abs, err := filepath.Abs(path)
		require.NoError(t, err)
		loaded, err := core.LoadConfig(abs)
		if err != nil {
			// A configuration the load refuses stops the run before any rule.
			refused = append(refused, filepath.Dir(path))
			continue
		}
		compared++
		t.Run(path, func(t *testing.T) {
			chain, err := readBroadChain(abs, filepath.Dir(abs))
			require.NoError(t, err)
			assert.Equal(t, loadedModel(loaded), broadModel(t, chain))
		})
	}
	t.Logf("%d configurations compared; refused by the load: %v", compared, refused)
	assert.GreaterOrEqual(t, compared, 81)
}

// A key or a value the load decodes - a !!binary one, a null one - is judged
// as what the load makes of it, on the line of its node: a !!binary category,
// rule, exclude, skip directory or exception glob is reported as the plain
// one is, a duplicate key the load decodes to one name is the last one, and
// a null item of a list is none, so it does not hide the list of a base. An
// exception is narrowed as the load matches it: an empty pattern or a line
// below 1 narrows nothing, one of no files keeps every file, and a file,
// never a glob, keeps that file alone.
func TestBroadExclusionJudgesWhatTheLoadDecodes(t *testing.T) {
	for name, tt := range map[string]struct {
		config string
		want   []string
	}{
		"category off":         {"version: 1\ncategories:\n  ? !!binary ZGVhZGNvZGU=\n  : enabled: false\n", []string{".glint.yaml:4"}},
		"oversight rule off":   {"version: 1\ncategories:\n  deadcode:\n    rules:\n      ? !!binary c3RhbGUtc3VwcHJlc3Npb24=\n      : enabled: false\n", []string{".glint.yaml:6"}},
		"oversight exception":  {"version: 1\ncategories:\n  deadcode:\n    rules:\n      ? !!binary c3VwcHJlc3Npb24td2l0aG91dC1yZWFzb24=\n      : exceptions:\n          - pattern: Suppression\n            reason: legacy markers\n", []string{".glint.yaml:7"}},
		"exclude":              {"version: 1\nsettings:\n  exclude:\n    - !!binary aW50ZXJuYWwvKio=\n", []string{".glint.yaml:4"}},
		"skip_dirs":            {"version: 1\nsettings:\n  skip_dirs:\n    - !!binary aW50ZXJuYWw=\n", []string{".glint.yaml:4"}},
		"exception glob":       {"version: 1\ncategories:\n  security:\n    rules:\n      hardcoded-secret:\n        exceptions:\n          - files: !!binary Kio=\n            reason: fixtures\n", []string{".glint.yaml:7"}},
		"empty pattern":        {"version: 1\ncategories:\n  security:\n    rules:\n      hardcoded-secret:\n        exceptions:\n          - files: \"**\"\n            pattern: \"\"\n            line: 0\n            reason: fixtures\n", []string{".glint.yaml:7"}},
		"line below 1":         {"version: 1\ncategories:\n  security:\n    rules:\n      hardcoded-secret:\n        exceptions:\n          - files: \"**\"\n            line: -1\n            reason: fixtures\n", []string{".glint.yaml:7"}},
		"narrowed":             {"version: 1\ncategories:\n  security:\n    rules:\n      hardcoded-secret:\n        exceptions:\n          - files: \"**\"\n            pattern: !!binary U3VwcHJlc3Npb24=\n            reason: fixtures\n          - files: \"**\"\n            function: Load\n            reason: fixtures\n          - files: \"**\"\n            line: 2\n            reason: fixtures\n", nil},
		"a line below 1 alone": {"version: 1\ncategories:\n  security:\n    rules:\n      hardcoded-secret:\n        exceptions:\n          - line: -1\n            reason: fixtures\n", []string{".glint.yaml:7"}},
		"on the line of files": {"version: 1\ncategories:\n  security:\n    rules:\n      hardcoded-secret:\n        exceptions:\n          - reason: fixtures\n            files: !!binary Kio=\n", []string{".glint.yaml:8"}},
		"file is no glob":      {"version: 1\ncategories:\n  security:\n    rules:\n      hardcoded-secret:\n        exceptions:\n          - file: \"**\"\n            reason: fixtures\n", nil},
		"file narrows files":   {"version: 1\ncategories:\n  security:\n    rules:\n      hardcoded-secret:\n        exceptions:\n          - files: \"**\"\n            file: main.go\n            reason: fixtures\n", nil},
		"last duplicate wins":  {"version: 1\ncategories:\n  security:\n    enabled: true\n  ? !!binary c2VjdXJpdHk=\n  : enabled: false\n", []string{".glint.yaml:6"}},
		"null item":            {"version: 1\nextends: conf/base.yaml\nsettings:\n  exclude: [~]\n", []string{"conf/base.yaml:3"}},
		"binary narrow":        {"version: 1\ncategories:\n  security:\n    rules:\n      hardcoded-secret:\n        exceptions:\n          - files: !!binary aW50ZXJuYWwvKio=\n            reason: fixtures\n", nil},
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			writeModuleFile(t, root, ".glint.yaml", tt.config)
			writeModuleFile(t, root, "conf/base.yaml", "version: 1\nsettings:\n  exclude: [\"internal/**\"]\n")
			writeModuleFile(t, root, "cmd/app/main.go", "package main\n")
			writeModuleFile(t, root, "internal/svc/svc.go", "package svc\n")
			assert.Equal(t, tt.want, broadPlaces(t, root))
		})
	}
}
