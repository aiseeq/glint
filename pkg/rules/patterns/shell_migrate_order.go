package patterns

import (
	"regexp"
	"slices"
	"sort"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(newShellRule("deploy-starts-new-code-before-migrations",
		"Detects a deploy script that starts the new container (compose up -d, docker run -d) and then runs the migrations with docker exec inside it — the new code's startup jobs run on the old schema first",
		core.SeverityMedium, checkMigrationsAfterStart))
}

var (
	// execMigration is docker exec running a migration tool in a running
	// container.
	execMigration = regexp.MustCompile(`\bdocker\s+(?:compose\s+)?exec\b[^;&|]*\bmigrate\b`)
	// migrationRead is a migration tool asked for the schema version or
	// status, which changes nothing.
	migrationRead = regexp.MustCompile(`\bmigrate\b[^;&|]*(?:\s-{1,2}direction[\s=]+["']?(?:version|status)\b|\s(?:version|status)(?:\s|["']|$))`)
	// composeVariableUp is compose started through a variable holding the
	// command: $DOCKER_COMPOSE up -d.
	composeVariableUp = regexp.MustCompile(`\$\{?[A-Z_]*COMPOSE[A-Z_]*\}?\s.*\bup\b.*\s(?:-d|--detach)\b`)
)

// checkMigrationsAfterStart reports a docker exec running migrations that
// the script reaches after it started a container: in the same function or
// at the top level, directly or through the functions it calls.
func checkMigrationsAfterStart(r *shellRule, src *shellSource) []*core.Violation {
	if src.make {
		return nil
	}
	funcs := src.functions()
	names := make([]string, 0, len(funcs))
	for name := range funcs {
		names = append(names, name)
	}
	sort.Strings(names)
	rc := deployReach{names: names, starts: make(map[string]bool), migrations: make(map[string][]int)}
	for changed := true; changed; {
		changed = false
		for _, name := range names {
			for _, l := range src.body(funcs[name]) {
				changed = rc.absorb(name, l) || changed
			}
		}
	}
	starts, migrations := rc.starts, rc.migrations
	reported := make(map[int]bool)
	var out []*core.Violation
	walk := func(lines []shellLine, self string) {
		started := false
		for _, l := range lines {
			callees := shellCalledFunctions(l.text, names, self)
			if started {
				exec := lineMigrations(l, nil)
				for _, callee := range callees {
					exec = append(exec, migrations[callee]...)
				}
				for _, line := range exec {
					if reported[line] {
						continue
					}
					reported[line] = true
					out = appendReport(out, src.report(r, line,
						"Migrations run with docker exec inside a container the deploy has already started — the new code runs on the old schema until they finish, and its startup jobs fail on missing columns",
						"Run the migrations before starting the new code: a one-off container of the new image (docker compose run --rm --entrypoint migrate ...), then compose up"))
				}
			}
			if startsService(l.text) || slices.ContainsFunc(callees, func(c string) bool { return starts[c] }) {
				started = true
			}
		}
	}
	inFunction := make(map[int]bool)
	for _, name := range names {
		fn := funcs[name]
		for i := fn.first; i <= fn.last; i++ {
			inFunction[i] = true
		}
		walk(src.body(fn), name)
	}
	var top []shellLine
	for i, l := range src.lines {
		if !inFunction[i] {
			top = append(top, l)
		}
	}
	walk(top, "")
	return out
}

// deployReach is what each function of a script does, directly or through
// the functions it calls: starts a container, runs migrations by docker
// exec (the lines of those execs).
type deployReach struct {
	names      []string
	starts     map[string]bool
	migrations map[string][]int
}

// absorb adds what a line of the function does; it reports a change.
func (rc *deployReach) absorb(name string, l shellLine) bool {
	changed := false
	if startsService(l.text) {
		changed = rc.start(name)
	}
	changed = rc.reach(name, lineMigrations(l, nil)) || changed
	for _, callee := range shellCalledFunctions(l.text, rc.names, name) {
		if rc.starts[callee] {
			changed = rc.start(name) || changed
		}
		changed = rc.reach(name, rc.migrations[callee]) || changed
	}
	return changed
}

func (rc *deployReach) start(name string) bool {
	if rc.starts[name] {
		return false
	}
	rc.starts[name] = true
	return true
}

func (rc *deployReach) reach(name string, lines []int) bool {
	changed := false
	for _, line := range lines {
		if !slices.Contains(rc.migrations[name], line) {
			rc.migrations[name], changed = append(rc.migrations[name], line), true
		}
	}
	return changed
}

// startsService reports a line starting a container or a service.
func startsService(text string) bool {
	text = withoutComment(text)
	return serviceStart.MatchString(text) || composeVariableUp.MatchString(text)
}

// lineMigrations returns the line of a docker exec running migrations in
// the logical line, appended to lines.
func lineMigrations(l shellLine, lines []int) []int {
	text := withoutComment(l.text)
	at := execMigration.FindStringIndex(text)
	if at == nil || migrationRead.MatchString(text[at[0]:]) {
		return lines
	}
	return append(lines, l.lineAt(at[0]))
}

// shellCalledFunctions returns the functions of names the line calls, self left
// out.
func shellCalledFunctions(text string, names []string, self string) []string {
	var called []string
	for _, word := range shellWords(withoutComment(text)) {
		if word != self && slices.Contains(names, word) && !slices.Contains(called, word) {
			called = append(called, word)
		}
	}
	return called
}

var shellWordPattern = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*`)

// shellWords returns the identifier-like words of a line.
func shellWords(text string) []string {
	return shellWordPattern.FindAllString(text, -1)
}
