//go:build !race

package main

import (
	"reflect"
	"strings"
	"testing"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/architecture"
	"github.com/aiseeq/glint/pkg/rules/deadcode"
	"github.com/aiseeq/glint/pkg/rules/duplication"
	"github.com/stretchr/testify/require"
)

// These tests inspect cache dependency metadata and rule declarations only;
// they do not run analysis or start glint workers in the test process.

type projectCacheIndexConsumer struct {
	*projectStubRule
	indexName string
}

type projectCacheCodeConsumer struct {
	*projectStubRule
	symbols []string
}

func (r *projectCacheCodeConsumer) RuleCacheCodeSymbols() []string {
	return r.symbols
}

func TestProjectRuleCacheTracksCodePackagesForSharedRuleTypes(t *testing.T) {
	const logicPackage = "github.com/aiseeq/glint/pkg/rules/patterns/gorules"
	const unrelatedPackage = "github.com/aiseeq/glint/pkg/rules/deadcode"
	rule := &projectCacheCodeConsumer{
		projectStubRule: newProjectStubRule(),
		symbols:         []string{logicPackage + ".checkRandIndex.func1"},
	}
	names := []string{rule.Name()}

	open := func(logicBuild string) *resultCache {
		return &resultCache{ruleFingerprints: map[string]string{
			logicPackage:     logicBuild,
			unrelatedPackage: "unrelated-v1",
		}}
	}
	first := open("logic-v1")
	first.keyProject("", "inputs", names, []rules.Rule{rule}, "")

	changed := open("logic-v2")
	changed.previousProject = &projectEntry{Inputs: "inputs", Fingerprints: first.projectFingerprints}
	changed.keyProject("", "inputs", names, []rules.Rule{rule}, "")
	require.NotNil(t, changed.projectHit)
	require.False(t, changed.projectRuleReusable(rule), "changing a closure's package must invalidate its rule")

	unrelated := &resultCache{ruleFingerprints: map[string]string{
		logicPackage:     "logic-v1",
		unrelatedPackage: "unrelated-v2",
	}}
	unrelated.previousProject = &projectEntry{Inputs: "inputs", Fingerprints: first.projectFingerprints}
	unrelated.keyProject("", "inputs", names, []rules.Rule{rule}, "")
	require.True(t, unrelated.projectRuleReusable(rule), "unrelated package rules should remain cached")
}

func (r *projectCacheIndexConsumer) ProjectRuleCacheDependencies() []string {
	return []string{r.indexName}
}

func TestProjectRuleCacheIgnoresUnrelatedPackageRules(t *testing.T) {
	changed := architecture.NewSolidISPRule()
	other := deadcode.NewNeverAssignedFieldRule()
	ruleset := []rules.Rule{changed, other}
	names := []string{changed.Name(), other.Name()}

	open := func(changedBuild string) *resultCache {
		cache := &resultCache{ruleFingerprints: map[string]string{
			reflect.TypeFor[architecture.SolidISPRule]().PkgPath():       changedBuild,
			reflect.TypeFor[deadcode.NeverAssignedFieldRule]().PkgPath(): "other-v1",
		}}
		return cache
	}
	first := open("changed-v1")
	first.keyProject("", "inputs", names, ruleset, "")

	second := open("changed-v2")
	second.previousProject = &projectEntry{Inputs: "inputs", Fingerprints: first.projectFingerprints}
	second.keyProject("", "inputs", names, ruleset, "")
	require.NotNil(t, second.projectHit)
	require.False(t, second.projectRuleReusable(changed))
	require.True(t, second.projectRuleReusable(other), "an unrelated package rule should keep its cached findings")
}

type indexedProjectCacheRule struct {
	*rules.BaseRule
}

func newIndexedProjectCacheRule() *indexedProjectCacheRule {
	return &indexedProjectCacheRule{BaseRule: rules.NewBaseRule("indexed-project-consumer", "test", "", core.SeverityLow)}
}

func (*indexedProjectCacheRule) AnalyzeFile(*core.FileContext) []*core.Violation { return nil }

func (*indexedProjectCacheRule) AnalyzeGoProject(*core.GoProjectContext) ([]*core.Violation, error) {
	return nil, nil
}

func (*indexedProjectCacheRule) RequiresSSA() bool { return false }

func (*indexedProjectCacheRule) ProjectRuleCacheDependencies() []string {
	return []string{duplication.NewCrossFileDuplicateRule().Name()}
}

func TestProjectRuleCacheTracksIndexesItReads(t *testing.T) {
	consumer := newIndexedProjectCacheRule()
	index := duplication.NewCrossFileDuplicateRule()
	ruleset := []rules.Rule{consumer, index}
	names := []string{consumer.Name()}
	indexPkg := reflect.TypeFor[duplication.CrossFileDuplicateRule]().PkgPath()

	open := func(indexBuild string) *resultCache {
		return &resultCache{ruleFingerprints: map[string]string{
			reflect.TypeFor[indexedProjectCacheRule]().PkgPath(): "consumer-v1",
			indexPkg: "index-v1-" + indexBuild,
		}}
	}
	first := open("a")
	first.keyProject("", "inputs", names, ruleset, "")

	second := open("b")
	second.previousProject = &projectEntry{Inputs: "inputs", Fingerprints: first.projectFingerprints}
	second.keyProject("", "inputs", names, ruleset, "")
	require.NotNil(t, second.projectHit)
	require.False(t, second.projectRuleReusable(consumer), "changing a consumed index must rerun its reader")
}

// A project rule's cache key holds only the fingerprint of the package of its
// type. A rule whose type lives outside the rule packages (a shared kit type
// with the logic in callbacks) would get no rule fingerprint at all, so its
// key would survive a release that changes its logic: such a rule must name
// the code it runs.
func TestProjectRulesOutsideRulePackagesDeclareTheirCode(t *testing.T) {
	const rulePackages = "github.com/aiseeq/glint/pkg/rules/"
	checked := 0
	for _, rule := range rules.All() {
		if _, project := rule.(rules.GoProjectRule); !project {
			continue
		}
		ruleType := reflect.TypeOf(rule)
		for ruleType.Kind() == reflect.Pointer {
			ruleType = ruleType.Elem()
		}
		pkg := ruleType.PkgPath()
		if strings.HasPrefix(pkg, rulePackages) && !strings.HasPrefix(pkg, rulePackages+"patterns/internal/") && !strings.HasPrefix(pkg, rulePackages+"helpers") {
			continue
		}
		checked++
		code, declares := rule.(rules.RuleCacheCodeSymbols)
		if !declares {
			t.Errorf("%s: project rule of type %s.%s outside the rule packages does not implement rules.RuleCacheCodeSymbols", rule.Name(), pkg, ruleType.Name())
			continue
		}
		if len(code.RuleCacheCodeSymbols()) == 0 {
			t.Errorf("%s: declares no code symbols", rule.Name())
		}
	}
	require.Positive(t, checked, "no project rule outside the rule packages: the test checks nothing")
}
