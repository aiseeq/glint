package patterns

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewReactCallbackDependsOnStateRule())
}

// ReactCallbackDependsOnStateRule detects a useCallback or useMemo that lists a
// state among its dependencies and sets that same state, while an effect
// depends on the result:
//
//	const [attempt, setAttempt] = useState(0)
//	const connect = useCallback(() => { ...; setAttempt(0) }, [endpoint, attempt])
//	useEffect(() => { connect(); return close }, [connect])
//
// Each call of the callback changes its own dependency, so React builds a new
// callback, and the effect sees a new dependency: it cleans up and runs again
// — closes the connection it just opened, refetches, resubscribes. The state
// and the hooks must belong to one component; a callback nothing reruns on is
// only rebuilt and is not reported.
type ReactCallbackDependsOnStateRule struct {
	*rules.BaseRule
}

// NewReactCallbackDependsOnStateRule creates the rule
func NewReactCallbackDependsOnStateRule() *ReactCallbackDependsOnStateRule {
	return &ReactCallbackDependsOnStateRule{BaseRule: rules.NewBaseRule(
		"react-callback-depends-on-state-it-sets",
		"patterns",
		"Detects a useCallback/useMemo that depends on a state it sets while an effect depends on it — every call reruns the effect (reconnect, refetch)",
		core.SeverityHigh,
	)}
}

var (
	reactStatePair = regexp.MustCompile(`\bconst\s*\[\s*([A-Za-z_$][\w$]*)\s*,\s*([A-Za-z_$][\w$]*)\s*\]\s*=\s*(?:React\s*\.\s*)?useState\b`)
	reactMemoHook  = regexp.MustCompile(`\b(?:const|let)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:React\s*\.\s*)?(useCallback|useMemo)\s*(?:<[^()]*>)?\s*\(`)
	reactEffect    = regexp.MustCompile(`\b(?:React\s*\.\s*)?(useEffect|useLayoutEffect)\s*\(`)
)

// AnalyzeFile reports the dependencies a memoized callback sets.
func (r *ReactCallbackDependsOnStateRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if (!ctx.IsTypeScriptFile() && !ctx.IsJavaScriptFile()) || skipFrontendPath(ctx) {
		return nil
	}
	if !strings.Contains(string(ctx.Content), "useState") {
		return nil
	}
	f := newJSFlat(ctx)

	setters := componentSetters(f)
	if len(setters) == 0 {
		return nil
	}

	// effectDeps maps a component's block to the dependencies of its effects
	// and the hook that holds each.
	effectDeps := make(map[int]map[string]string)
	for _, m := range reactEffect.FindAllStringSubmatchIndex(f.code, -1) {
		args := f.callArgs(m[1] - 1)
		if len(args) < 2 {
			continue
		}
		scope := f.enclosingBrace(m[0])
		if effectDeps[scope] == nil {
			effectDeps[scope] = make(map[string]string)
		}
		for _, dep := range f.arrayIdents(args[len(args)-1]) {
			effectDeps[scope][dep.name] = fmt.Sprintf("%s at line %d", f.code[m[2]:m[3]], f.line(m[0]))
		}
	}

	var violations []*core.Violation
	for _, m := range reactMemoHook.FindAllStringSubmatchIndex(f.code, -1) {
		name, hook := f.code[m[2]:m[3]], f.code[m[4]:m[5]]
		scope := f.enclosingBrace(m[0])
		effect, rerun := effectDeps[scope][name]
		if !rerun || setters[scope] == nil {
			continue
		}
		args := f.callArgs(m[1] - 1)
		if len(args) < 2 {
			continue
		}
		body := f.code[args[0].start:args[0].end]
		for _, ident := range f.arrayIdents(args[len(args)-1]) {
			dep, pos := ident.name, ident.pos
			setter, isState := setters[scope][dep]
			if !isState || !callsFunction(body, setter) {
				continue
			}
			line := f.line(pos)
			if ctx.IsSuppressed(line, r.Name()) {
				continue
			}
			v := r.CreateViolation(ctx.RelPath, line, fmt.Sprintf(
				"%s '%s' depends on '%s' and sets it through %s — each call rebuilds %s, and %s, which depends on it, cleans up and runs again",
				hook, name, dep, setter, name, effect))
			v.WithCode(strings.TrimSpace(ctx.GetLine(line)))
			v.WithSuggestion(fmt.Sprintf("Drop '%s' from the dependencies: read it through a ref, or set it with a functional update (%s(prev => ...))", dep, setter))
			violations = append(violations, v)
		}
	}
	return violations
}

// callsFunction reports whether the code calls the plain function name — not
// a method of the same name on another object.
func callsFunction(code, name string) bool {
	re := regexp.MustCompile(`(?:^|[^\w$.])` + regexp.QuoteMeta(name) + `\s*\(`)
	return re.MatchString(code)
}
