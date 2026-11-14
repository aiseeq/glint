package main

import (
	"path/filepath"
	"slices"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/deadcode"
)

// silencedSeverities are the highest severities of the findings a run
// silenced, by inline marker and by configured exception. The finding about a
// marker without a reason, or about a broad exception, is as severe as what
// it hides: min_severity above low would otherwise hide the oversight with
// the finding, and a bare marker would silence a critical one unseen.
type silencedSeverities struct {
	// markers are by the file, relative to the root, and the line of the
	// marker.
	markers map[silencedPlace]core.Severity
	// exceptions are by the configuration file, absolute, and the line that
	// declares the exception.
	exceptions map[silencedPlace]core.Severity
}

type silencedPlace struct {
	file string
	line int
}

// newSilencedSeverities reads the suppression entries of one root. A finding
// of suppression-without-reason an exception silences is as severe as the
// marker it is about.
func newSilencedSeverities(cfg *core.Config, suppressions core.ViolationList) silencedSeverities {
	silenced := silencedSeverities{markers: map[silencedPlace]core.Severity{}, exceptions: map[silencedPlace]core.Severity{}}
	for _, entry := range suppressions {
		if entry.Suppression == core.SuppressionInline {
			raiseSilenced(silenced.markers, silencedPlace{entry.File, entry.Line}, entry.Severity)
		}
	}
	byKey := map[string]core.Severity{}
	for _, entry := range suppressions {
		key, ok := strings.CutPrefix(entry.Suppression, core.SuppressionExceptionPrefix)
		if !ok {
			continue
		}
		severity := entry.Severity
		if entry.Rule == core.SuppressionReasonRule {
			severity = max(severity, silenced.markers[silencedPlace{entry.File, entry.Line}])
		}
		byKey[key] = max(byKey[key], severity)
	}
	exceptions := cfg.Exceptions()
	for i := range exceptions {
		exc := exceptions[i].Exception
		if severity, ok := byKey[cfg.ExceptionKey(exc)]; ok {
			raiseSilenced(silenced.exceptions, silencedPlace{filepath.Clean(exc.Source()), exc.DeclaredAt()}, severity)
		}
	}
	return silenced
}

// raiseSilenced keeps the highest severity silenced at the place; low, the
// zero severity, is what a place silenced nothing of.
func raiseSilenced(severities map[silencedPlace]core.Severity, place silencedPlace, severity core.Severity) {
	severities[place] = max(severities[place], severity)
}

// exception returns the highest severity of the findings the exception
// declared at the line of the configuration file silenced; low when it
// silenced none.
func (s silencedSeverities) exception(file string, line int) core.Severity {
	return s.exceptions[silencedPlace{filepath.Clean(file), line}]
}

// raiseMarkerFindings gives each finding of suppression-without-reason the
// severity of what its marker silenced, when that is higher. The finding is
// copied: the stored one, in the result cache too, keeps the rule's own.
func (s silencedSeverities) raiseMarkerFindings(list core.ViolationList) core.ViolationList {
	raised := make(core.ViolationList, 0, len(list))
	for _, v := range list {
		if severity := s.markers[silencedPlace{v.File, v.Line}]; v.Rule == core.SuppressionReasonRule && severity > v.Severity {
			copied := *v
			copied.Severity = severity
			v = &copied
		}
		raised = append(raised, v)
	}
	return raised
}

// checkSuppressions runs the checks of one root that judge its suppressions
// once every rule has run, adds their findings and those of the
// configuration rules, and rates the findings about suppressions by what
// they silenced. The suppression entries drop out.
func checkSuppressions(root analysisRoot, prepared *preparedRoot, enabledRules []rules.Rule, cfg *core.Config, violations core.ViolationList) (core.ViolationList, error) {
	contexts := prepared.contexts
	violations, suppressions := core.SplitSuppressions(violations)
	stale, err := staleSuppressions(enabledRules, deadcode.StaleSuppressionRun{
		Contexts: contexts, Suppressions: suppressions, Config: cfg, WholeRoot: root.wholeRoot(),
	})
	if err != nil {
		return nil, err
	}
	closed, err := closedTicketSuppressions(enabledRules, deadcode.StaleSuppressionRun{Contexts: slices.Concat(contexts, prepared.ticketFiles), Config: cfg, WholeRoot: root.wholeRoot(), Scopes: root.walkScopes()})
	if err != nil {
		return nil, err
	}
	late, lateSuppressions := core.SplitSuppressions(slices.Concat(stale, closed))
	violations = slices.Concat(violations, late, ticketFileSuppressionsWithoutReason(enabledRules, cfg, prepared.ticketFiles))
	silenced := newSilencedSeverities(cfg, slices.Concat(suppressions, lateSuppressions))
	configFindings, err := analyzeConfigurationRules(enabledRules, cfg, contexts, root.dir, silenced)
	if err != nil {
		return nil, err
	}
	return silenced.raiseMarkerFindings(append(violations, configFindings...)), nil
}

// silenceLateFindings filters the findings of a check that runs after the
// file rules like those of any rule: an exception or an inline marker
// silences them, and the suppression entries of what silenced them come
// along, rated by the findings' severity.
func silenceLateFindings(check rules.Rule, run deadcode.StaleSuppressionRun, found []*core.Violation) core.ViolationList {
	cfg := run.Config
	contexts := make(map[string]*core.FileContext, len(run.Contexts))
	for _, ctx := range run.Contexts {
		contexts[ctx.RelPath] = ctx
	}
	var kept core.ViolationList
	for _, v := range found {
		if exc, ok := cfg.FileException(check.Category(), check.Name(), v.File); ok {
			kept = append(kept, core.NewSuppressionEntry(check.Name(), check.Category(), v.File, v.Line, v.Severity, core.SuppressionExceptionPrefix+cfg.ExceptionKey(exc)))
			continue
		}
		if exc, ok := cfg.MatchingException(check.Category(), check.Name(), v.File, v); ok {
			kept = append(kept, core.NewSuppressionEntry(check.Name(), check.Category(), v.File, v.Line, v.Severity, core.SuppressionExceptionPrefix+cfg.ExceptionKey(exc)))
			continue
		}
		if ctx := contexts[v.File]; ctx != nil && ctx.SuppressesFinding(v.Line, check.Name(), v.Severity) {
			continue
		}
		kept = append(kept, v)
	}
	for _, ctx := range run.Contexts {
		kept = append(kept, inlineSuppressions(ctx, check, nil)...)
	}
	return kept
}
