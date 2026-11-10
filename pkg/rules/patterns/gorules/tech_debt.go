package gorules

import (
	"maps"
	"regexp"
	"slices"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
)

func init() {
	rules.Register(NewTechDebtRule())
}

// TechDebtRule detects technical debt patterns beyond simple TODO comments in
// the // comments of Go, TypeScript and JavaScript files. Comments about old
// code paths that legacy-comment-marker reports are not reported again here.
type TechDebtRule struct {
	*rules.BaseRule
	patterns map[string]*debtPattern
	// order is the pattern names sorted once: the first matching pattern wins,
	// and the choice must not depend on map iteration.
	order []string
}

type debtPattern struct {
	regex *regexp.Regexp
	// except, when set, takes back a match of regex: a line it matches is
	// not reported by this pattern, unless exceptUnless matches it too.
	except       *regexp.Regexp
	exceptUnless *regexp.Regexp
	severity     core.Severity
	description  string
	suggestion   string
}

// techDebtNeedles are lower-case texts one of which every pattern match
// contains: a comment holding none of them is not matched against the regexps.
var techDebtNeedles = []string{
	"code", "instead", "вместо", "temp", "временн", "quick", "hotfix", "work",
	"refactor", "рефакторинг", "dead", "used", "никогда", "broken", "работ",
	"сломан", "ignore", "игнорир", "wip", "finished", "incomplete", "незаверш",
}

// NewTechDebtRule creates the rule
func NewTechDebtRule() *TechDebtRule {
	r := &TechDebtRule{
		BaseRule: rules.NewBaseRule(
			"tech-debt",
			"patterns",
			"Detects technical debt markers in code comments: obsolete code, fake refactoring, temporary or broken code, unfinished work",
			core.SeverityMedium,
		),
	}
	r.initPatterns()
	r.order = slices.Sorted(maps.Keys(r.patterns))
	return r
}

// unfinishedLabelEnd follows a word used as a label rather than as part of
// a phrase: the comment ends, or the next thing is not a word: punctuation
// ("в работе.", "в работе: перенос") or a dash apart from the word
// ("в работе — перенос").
const unfinishedLabelEnd = `(?:$|[^\p{L}\p{N}\s._-]|\.(?:[^\p{L}\p{N}]|$)|\s+(?:[^\p{L}\p{N}\s]|$))`

// incompleteDataNouns name data rather than code: "incomplete" before one
// describes the data.
const incompleteDataNouns = `data|info(?:rmation)?|responses?|requests?|repl(?:y|ies)|records?|rows?|transactions?|payloads?|inputs?|outputs?|reads?|writes?|pages?|batch(?:es)?|results?|uploads?|downloads?|messages?|frames?|packets?|lines?|chunks?|streams?|bod(?:y|ies)|entr(?:y|ies)|items?|orders?|snapshots?|headers?|json|utf-?8|code\s+(?:points?|units?)`

// incompleteWorld takes back "incomplete" and "незаверш..." that describe
// data rather than the code: a name of data or of a data file
// ("incomplete-data", "incomplete.json", "incomplete_reply") or the word
// followed by a noun about data that the sentence goes on from. A sign right
// after the noun ("incomplete data: in progress", "незавершённые записи —
// заглушка") makes it a label. Any other use stays a marker, so the
// pattern reports a subset of what it did before, and a marker it does not
// know is still reported.
var incompleteWorld = regexp.MustCompile(`(?i)//\s*(?:incomplete(?:[-._](?:` + incompleteDataNouns + `|ya?ml|csv|txt|log|xml|html)\b|\s+(?:` + incompleteDataNouns + `)(?:\s+\p{L}|\s*$))` +
	`|незаверш\p{L}*\s+(?:заказ|транзакци|операци|плат[её]ж|сделк|запрос|ответ|загрузк|выгрузк|сесси|запис|строк|данн|пакет|сообщени)\p{L}*(?:\s+\p{L}|\s*$))`)

// unfinishedCodeWords in a comment make "incomplete data handling: not
// wired yet" about the code again: another marker of unfinished work, a word
// for work on the code or for work left to do, or a noun about data used as
// a modifier of a noun for work or of a part of the code ("response
// decoding", "stream reader").
var unfinishedCodeWords = regexp.MustCompile(`(?i)\b(?:WIP|work[\s-]+in[\s-]+progress|stub\p{L}*|tests?|checks?|handling|parsing|processing|formatting|serializ\p{L}*|validation|support|logic|(?:un)?implement\p{L}*|mapping|conversion|(?:un)?finish\p{L}*|wired|yet|later|todo|fixme|xxx|hack|tbd|temporary|needs?\s+(?:work|fix\p{L}*)|not\s+done|rework\p{L}*)\b` +
	`|\b(?:` + incompleteDataNouns + `)\s+(?:\p{L}+(?:ing|ion|ment|[tnr]ch)(?:es|s)?|(?:read|writ|build|pars|handl|rout)ers?|caches?|layouts?|paths?|flows?|modes?|pipelines?|(?:im|ex)ports?)\b` +
	`|обработ|разбор|импорт|экспорт|додела|дописа|передела|допилить|доработ|реализ|:\s*нет(?:\P{L}|$)`)

// excused reports whether except takes back a match of the pattern on line.
func (p *debtPattern) excused(line string) bool {
	if p.except == nil || !p.except.MatchString(line) {
		return false
	}
	return p.exceptUnless == nil || !p.exceptUnless.MatchString(line)
}

func (r *TechDebtRule) initPatterns() {
	r.patterns = map[string]*debtPattern{
		"obsolete_code_marker": {
			regex:       regexp.MustCompile(`(?i)//.*\b(deprecated\s+code|old\s+code)`),
			severity:    core.SeverityMedium,
			description: "Obsolete code marker",
			suggestion:  "Remove the obsolete code or create a migration task",
		},
		"fake_refactoring": {
			regex:       regexp.MustCompile(`(?i)//.*(?:wrapper|делегирует|delegates?).*(?:вместо|instead\s+of).*(?:удаления|removal|eliminating)`),
			severity:    core.SeverityHigh,
			description: "Fake refactoring - wrapper instead of removal",
			suggestion:  "Remove wrapper and use canonical implementation directly",
		},
		"temporary_solution": {
			// "temporary" alone is an ordinary adjective (temporary credentials,
			// a temporary file); it marks debt only next to what is temporary
			// about the code, or as a label ("Temporary:"). "hotfix" is a
			// release path where hotfixes ship (hotfix branches, a hotfix
			// label): only a label on the code ("HOTFIX:", "hotfix for") counts.
			regex:       regexp.MustCompile(`(?i)//\s*(temporary\s+(?:fix|hack|workaround|solution|patch|code|measure|kludge|hotfix)\b|temporary\s*(?:[:!(\-—]|$)|временн\S*\s+(?:решени|костыл|фикс|заплатк|обход|хак)|temp\s+fix|quick\s+fix|hotfix\s*(?:[:!(\-—]|$)|hotfix\s+for\b|workaround)`),
			severity:    core.SeverityMedium,
			description: "Temporary solution marker",
			suggestion:  "Replace with proper implementation",
		},
		"needs_refactoring": {
			regex:       regexp.MustCompile(`(?i)//\s*(needs?\s+refactor|should\s+be\s+refactored|refactor\s+this|требует\s+рефакторинг)`),
			severity:    core.SeverityMedium,
			description: "Code marked for refactoring",
			suggestion:  "Refactor the code or create a task",
		},
		"dead_code_marker": {
			// "unused" must be followed by a non-letter to avoid matching "UnusedParamRule",
			// and not by a hyphen: "unused-field" is a rule name being referenced, not an
			// admission of dead code (repro: glint self-check on never_assigned_field.go).
			regex:       regexp.MustCompile(`(?i)//\s*(dead\s+code|unused(?:[^a-zA-Z-]|$)|not\s+used|никогда\s+не\s+использ)`),
			severity:    core.SeverityMedium,
			description: "Dead code marker",
			suggestion:  "Remove dead code - git remembers history",
		},
		"broken_feature": {
			// "broken pipe", "broken links" describe the world, not the code:
			// "broken" counts as a label or next to a code noun.
			regex:       regexp.MustCompile(`(?i)//\s*(broken\s*(?:[:!(\-—]|$)|broken\s+(?:feature|functionality|code|implementation|logic|behaviou?r|test|build|fix|hack|workaround)\b|не\s+работает|doesn.?t\s+work|сломан)`),
			severity:    core.SeverityHigh,
			description: "Broken feature marker",
			suggestion:  "Fix the broken feature or remove it",
		},
		"ignore_errors": {
			// Only an explicit "ignore error" with no explanation counts. \b
			// and \w know ASCII letters only, so the word edges are \p{L}.
			// Phrases like "non-critical" or "safe to ignore" usually justify
			// why ignoring is fine, so they are not lazy markers.
			regex:       regexp.MustCompile(`(?i)//(?:.*[^\p{L}\p{N}_])?(ignore\s+errors?\s*$|игнорир\p{L}*\s+ошибк\p{L}*\s*$)`),
			severity:    core.SeverityCritical,
			description: "Ignoring errors without explanation - document why it's safe",
			suggestion:  "Add explanation why ignoring is safe (e.g. 'Non-critical: uses defaults if fails')",
		},
		"unfinished_work": {
			// "incomplete data", "незавершённые транзакции" describe the
			// world, not the code (incompleteWorld); "в работе" marks work
			// only as a label, "в работе сервиса" is ordinary prose.
			regex:        regexp.MustCompile(`(?i)//\s*(\bWIP\b|work\s+in\s+progress|not\s+finished|incomplete|незаверш|в\s+работе` + unfinishedLabelEnd + `)`),
			except:       incompleteWorld,
			exceptUnless: unfinishedCodeWords,
			severity:     core.SeverityMedium,
			description:  "Unfinished work marker",
			suggestion:   "Complete the implementation or create a task",
		},
	}
}

// AnalyzeFile checks for tech debt patterns
func (r *TechDebtRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsGoFile() && !ctx.IsTypeScriptFile() && !ctx.IsJavaScriptFile() {
		return nil
	}
	if ctx.IsTestFile() {
		return nil
	}

	var violations []*core.Violation

	for lineNum, line := range ctx.Lines {
		// Skip non-comment lines for efficiency
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "//") {
			continue
		}

		if !helpers.ContainsAny(strings.ToLower(line), techDebtNeedles) {
			continue
		}
		if documentsIdentifier(ctx.Lines, lineNum) {
			continue
		}

		for _, patternName := range r.order {
			pattern := r.patterns[patternName]
			if pattern.regex.MatchString(line) && !pattern.excused(line) {
				v := r.CreateViolation(ctx.RelPath, lineNum+1, pattern.description)
				v.Severity = pattern.severity
				v.WithCode(trimmed)
				v.WithSuggestion(pattern.suggestion)
				v.WithContext("pattern", patternName)

				violations = append(violations, v)
				break // Only report first matching pattern per line
			}
		}
	}

	return violations
}

// docFirstWord captures the first word of a comment: the identifier a godoc
// comment opens with.
var docFirstWord = regexp.MustCompile(`^\s*//\s*([A-Za-z_][A-Za-z0-9_]*)`)

// documentsIdentifier reports whether the comment at index i is the godoc of
// the declaration that follows it: its first word names the function, method,
// type, variable or constant declared on the first non-comment line after the
// comment block. Such a comment describes an identifier, not the state of the
// code, whatever the identifier is called (temporaryReadError, a method named
// after a marker word).
func documentsIdentifier(lines []string, i int) bool {
	m := docFirstWord.FindStringSubmatch(lines[i])
	if m == nil {
		return false
	}
	word := m[1]
	j := i + 1
	for j < len(lines) && strings.HasPrefix(strings.TrimSpace(lines[j]), "//") {
		j++
	}
	if j >= len(lines) {
		return false
	}
	return declaresName(lines[j], word)
}

// declaresName reports whether line declares name: `func name(`, `func (r T)
// name(`, `type name`, `var name`, `const name`, or `name =`/`name T` inside a
// grouped var/const block.
func declaresName(line, name string) bool {
	rest := strings.TrimSpace(line)
	for _, kw := range []string{"func ", "type ", "var ", "const "} {
		if strings.HasPrefix(rest, kw) {
			rest = strings.TrimSpace(rest[len(kw):])
			if kw == "func " && strings.HasPrefix(rest, "(") {
				end := strings.Index(rest, ")")
				if end < 0 {
					return false
				}
				rest = strings.TrimSpace(rest[end+1:])
			}
			break
		}
	}
	if !strings.HasPrefix(rest, name) {
		return false
	}
	tail := rest[len(name):]
	return tail == "" || !patternkit.IsIdentChar(tail[0])
}
