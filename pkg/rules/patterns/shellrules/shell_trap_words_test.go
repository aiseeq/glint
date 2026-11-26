package shellrules

import (
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"mvdan.cc/sh/v3/syntax"
)

// manyWords is a list of braces past the bounds of the words of trap.
const manyWords = "{1..9999}"

// manyBraces passes the bound of braces.
var manyBraces = strings.Repeat("{INT,TERM}", maxBraces+1)

// The trap that does not exit is read from the words trap gets: braces are
// expanded, options set nothing, and a word of unknown value is no guess.
func TestShellTrapSignalWords(t *testing.T) {
	for name, command := range map[string]string{
		"signals":              `trap 'echo got' {INT,TERM}`,
		"names":                `trap 'echo got' SIG{INT,TERM}`,
		"numbers":              `trap 'echo got' {2,15}`,
		"padded numbers":       `trap 'echo got' {01..03}`,
		"unknown element":      `trap 'echo got' {INT,"$sig"}`,
		"action":               `trap {'echo got',INT,TERM}`,
		"action after --":      `trap -- {'echo got',TERM}`,
		"-- of braces":         `trap {--,'echo got',TERM}`,
		"empty element":        `trap {,'echo got'} TERM`,
		"name":                 `{trap,'echo got',TERM}`,
		"builtin":              `builtin trap 'echo got' {INT,TERM}`,
		"options after --":     `trap -- -lp TERM`,
		"no signal by number":  `trap 65 TERM`,
		"one past the bounds":  `trap 'echo got' TERM ` + manyWords,
		"one past, then known": `trap 'echo got' ` + manyWords + ` TERM`,
	} {
		t.Run("set by "+name, func(t *testing.T) {
			shellWanted(t, "shell-trap-signal-without-exit", "a.sh", "#!/bin/bash\n"+command+" # want\nwhile true; do sleep 1; done\n")
		})
	}
	for name, command := range map[string]string{
		"exit":                       `trap 'exit 1' {INT,TERM}`,
		"other signals":              `trap 'echo got' {HUP,USR1}`,
		"quoted braces":              `trap 'echo got' "{INT,TERM}"`,
		"one element":                `trap 'echo got' {INT}`,
		"open brace":                 `trap 'echo got' {INT,TERM`,
		"options -lp":                `trap -lp INT TERM`,
		"options -pP":                `trap -pP INT TERM`,
		"options of braces":          `trap -{l,p} INT TERM`,
		"option -p and action":       `trap -p 'echo got' TERM`,
		"option -p":                  `trap -p INT TERM`,
		"unknown option":             `trap -x 'echo got' TERM`,
		"reset":                      `trap - {INT,TERM}`,
		"reset of braces":            `trap {-,INT,TERM}`,
		"ignore":                     `trap '' {INT,TERM}`,
		"ignore of braces":           `trap {'',INT,TERM}`,
		"reset by numbers":           `trap 2 15`,
		"reset by numbers of braces": `trap {2,15}`,
		"reset of one signal":        `trap TERM`,
		"action past the bounds":     `trap ` + manyWords + ` TERM`,
		"signals past the bounds":    `trap 'echo got' ` + manyWords,
		"all past the bounds":        `trap ` + manyWords,
		"unknown action":             `trap "$action" TERM`,
		"action of many braces":      `trap ` + manyBraces + ` TERM`,
		"name past the bounds":       manyWords + ` trap 'echo got' TERM`,
	} {
		t.Run("not set by "+name, func(t *testing.T) {
			shellWanted(t, "shell-trap-signal-without-exit", "a.sh", "#!/bin/bash\n"+command+"\nwhile true; do sleep 1; done\n")
		})
	}
}

// A later trap that takes the handler off is read from the same words; one with
// a word past the bounds may take it off from any signal.
func TestShellTrapSignalReplacedWords(t *testing.T) {
	for name, command := range map[string]string{
		"reset":                      `trap - {INT,TERM}`,
		"reset of braces":            `trap {-,INT,TERM}`,
		"reset after --":             `trap -- - {INT,TERM}`,
		"reset of braces after --":   `trap {--,-,INT,TERM}`,
		"reset through builtin":      `builtin trap - {INT,TERM}`,
		"reset of a range":           `trap - {1..20}`,
		"reset by numbers":           `trap 2 15`,
		"reset by padded numbers":    `trap 02 015`,
		"reset by numbers of braces": `trap {2,15}`,
		"ignore":                     `trap '' {INT,TERM}`,
		"another action":             `trap 'exit 1' {INT,TERM}`,
		"another action of braces":   `trap {'exit 1',INT,TERM}`,
		"name of braces":             `{trap,-,INT,TERM}`,
		"signals past the bounds":    `trap - ` + manyWords,
		"action past the bounds":     `trap ` + manyWords + ` USR1`,
		"all past the bounds":        `trap ` + manyWords,
		"reset by the last number":   `trap 64 INT TERM`,
		"signals of many braces":     `trap - ` + manyBraces,
		"one reset each":             "trap INT\ntrap -- TERM",
	} {
		t.Run("replaced by "+name, func(t *testing.T) {
			shellWanted(t, "shell-trap-signal-without-exit", "a.sh", "#!/bin/bash\ntrap 'echo got' INT TERM\nsetup\n"+command+"\nwhile true; do sleep 1; done\n")
		})
	}
	for name, command := range map[string]string{
		"reset of one":            `trap - {INT,HUP}`,
		"quoted braces":           `trap - "{INT,TERM}"`,
		"options":                 `trap -lp INT TERM`,
		"options of braces":       `trap -{l,p} INT TERM`,
		"option and action":       `trap -p - TERM`,
		"action of a signal name": `trap {INT,HUP}`,
		"no signal by number":     `trap 65 HUP`,
		"unknown action":          `trap "$action" INT TERM`,
		"a command of no words":   `{,}`,
		"a prefix of no command":  `{builtin,}`,
		"other name of braces":    `{echo,trap,-,INT,TERM}`,
	} {
		t.Run("kept by "+name, func(t *testing.T) {
			shellWanted(t, "shell-trap-signal-without-exit", "a.sh", "#!/bin/bash\ntrap 'echo got' INT TERM # want\nsetup\n"+command+"\nwhile true; do sleep 1; done\n")
		})
	}
	shellWanted(t, "shell-trap-signal-without-exit", "late.sh", `#!/bin/bash
trap 'echo got' INT TERM # want
trap - {HUP,USR1} {INT,EXIT}
while true; do sleep 1; done
`)
}

// A handler that takes itself off and sends the signal again ends the script.
func TestShellTrapSignalReraisedWords(t *testing.T) {
	for name, body := range map[string]string{
		"reset":                   `trap - {INT,TERM}; kill -TERM $$`,
		"reset of braces":         `trap {-,INT,TERM}; kill -TERM $$`,
		"reset after --":          `trap -- - {INT,TERM}; kill -TERM $$`,
		"name of braces":          `{trap,-,TERM}; kill -TERM $$`,
		"parameter in braces":     `trap - {HUP,"$1"}; kill -s "$1" $$`,
		"reset by numbers":        `trap 1 15; kill -TERM $$`,
		"reset of one signal":     `trap TERM; kill -TERM $$`,
		"padded numbers":          `trap - {014..015}; kill -015 $$`,
		"signals past the bounds": `trap - ` + manyWords + `; kill -TERM $$`,
		"action past the bounds":  `trap ` + manyWords + ` HUP; kill -TERM $$`,
	} {
		t.Run("by "+name, func(t *testing.T) {
			shellWanted(t, "shell-trap-signal-without-exit", "a.sh", "#!/bin/bash\nstop() { "+body+"; }\ntrap 'stop TERM' TERM\nwhile true; do sleep 1; done\n")
		})
	}
	shellWanted(t, "shell-trap-signal-without-exit", "again.sh", `#!/bin/bash
stop() {
	trap {'echo again',TERM} # want
	kill -TERM $$
}
trap stop TERM # want
while true; do sleep 1; done
`)
	for name, body := range map[string]string{
		"reset of other signals": `trap - {INT,HUP}; kill -TERM $$`,
		"options":                `trap -lp TERM; kill -TERM $$`,
		"options of braces":      `trap -{l,p} - TERM; kill -TERM $$`,
		"another action for signals past a bound": `trap 'echo again' ` + manyWords + `; kill -TERM $$`,
		"ignore": `trap {'',TERM}; kill -TERM $$`,
	} {
		t.Run("not by "+name, func(t *testing.T) {
			shellWanted(t, "shell-trap-signal-without-exit", "a.sh", "#!/bin/bash\nstop() { "+body+"; }\ntrap 'stop TERM' TERM # want\nwhile true; do sleep 1; done\n")
		})
	}
}

// Setting a trap is no work that runs with the handler on, whatever the trap is
// written through.
func TestShellTrapSignalTrapIsNoWork(t *testing.T) {
	for _, command := range []string{`trap 'exit 1' HUP`, `{trap,'exit 1',HUP}`, `trap {'exit 1',HUP}`, `trap -lp HUP`, `trap`, `trap --`, `builtin trap - HUP`} {
		for name, script := range map[string]string{
			"a list":          "trap 'echo got' TERM\n" + command + "\necho end\n",
			"a wait":          "server &\ntrap 'echo got' TERM\nwait\n" + command + "\nrm -f lock\n",
			"a wait in parts": "server &\ntrap 'echo got' TERM\n" + command + "\nwait\n",
		} {
			t.Run(strings.TrimSpace(command)+" in "+name, func(t *testing.T) {
				shellWanted(t, "shell-trap-signal-without-exit", "a.sh", "#!/bin/bash\n"+script)
			})
		}
	}
	shellWanted(t, "shell-trap-signal-without-exit", "work.sh", `#!/bin/bash
trap 'echo got' TERM # want
{echo,trap,-,TERM}
{run,trap,-,TERM}
`)
	shellWanted(t, "shell-trap-signal-without-exit", "substitution.sh", `#!/bin/bash
trap 'echo got' TERM # want
trap '' $(run)
`)
}

// The words of a command are read once for all the paths through it.
func TestTrapFlowReadsWordsOnce(t *testing.T) {
	file, err := syntax.NewParser().Parse(strings.NewReader(`trap - {INT,TERM}`), "a.sh")
	require.NoError(t, err)
	call, ok := file.Stmts[0].Cmd.(*syntax.CallExpr)
	require.True(t, ok)
	flow := newScriptFuncs(file).flow(file)
	built := 0
	flow.reader.built = func(*syntax.Word) { built++ }
	first := flow.readTrap(call)
	second := flow.readTrap(call)
	assert.Equal(t, 2, built)
	assert.Equal(t, first, second)
	assert.Equal(t, uint8(allTrapSignals), first.set.replaces)
}

// Escaped braces are text: they are no braces and take nothing of the bounds.
func TestShellTrapWordsEscapedBraces(t *testing.T) {
	escaped := strings.Repeat(`\{\}`, maxBraces+1)
	shellWanted(t, "shell-trap-signal-without-exit", "a.sh", "#!/bin/bash\ntrap 'exit 1' INT\ntrap "+escaped+" INT # want\nwhile true; do sleep 1; done\n")
	shellWanted(t, "shell-trap-signal-without-exit", "b.sh", "#!/bin/bash\ntrap "+escaped+" {INT,TERM} # want\nwhile true; do sleep 1; done\n")
	shellWanted(t, "shell-trap-in-loop", "c.sh", "#!/bin/bash\nfor i in 1 2; do\n\ttrap "+escaped+" {EXIT,INT} # want\ndone\n")
	shellWanted(t, "shell-trap-in-loop", "d.sh", "#!/bin/bash\nfor i in 1 2; do\n\ttrap 'rm -f a' \\{EXIT,INT}\n\ttrap 'rm -f a' {EXIT\\,INT}\ndone\n")
}

// A script that turns brace expansion off gets its braces as text, wherever it
// turns it off.
func TestShellTrapWordsBracesOff(t *testing.T) {
	for _, set := range []string{"set +B", "set +o braceexpand", "set +eB", "set -e +B", "set + +B", "builtin set +B", "set -o errexit +o braceexpand"} {
		t.Run(set, func(t *testing.T) {
			shellWanted(t, "shell-trap-in-loop", "a.sh", "#!/bin/bash\n"+set+"\nfor i in 1 2; do\n\ttrap 'rm -f a' {EXIT,INT}\ndone\n")
			shellWanted(t, "shell-trap-signal-without-exit", "b.sh", "#!/bin/bash\n"+set+"\ntrap 'echo got' {INT,TERM}\nwhile true; do sleep 1; done\n")
			shellWanted(t, "shell-trap-signal-without-exit", "c.sh", "#!/bin/bash\ntrap 'echo got' INT # want\n"+set+"\ntrap - {INT,TERM}\nwhile true; do sleep 1; done\n")
			shellWanted(t, "shell-trap-signal-without-exit", "d.sh", "#!/bin/bash\ntrap 'echo got' {INT,TERM}\nwhile true; do sleep 1; done\n"+set+"\n")
		})
	}
	for _, set := range []string{"set -B", "set -o braceexpand", "set -- +B", "set - +B", "set x +B", "echo set +B", "set +o", "set -o"} {
		t.Run(set, func(t *testing.T) {
			shellWanted(t, "shell-trap-in-loop", "a.sh", "#!/bin/bash\n"+set+"\nfor i in 1 2; do\n\ttrap 'rm -f a' {EXIT,INT} # want\ndone\n")
			shellWanted(t, "shell-trap-signal-without-exit", "b.sh", "#!/bin/bash\n"+set+"\ntrap 'echo got' {INT,TERM} # want\nwhile true; do sleep 1; done\n")
		})
	}
}

// What the braces of one command build is bound by its parts, and words past
// the bounds are not built: the bound is known before the expander runs, and a
// command that is no trap has its words built only up to its name.
func TestShellTrapWordsBuilt(t *testing.T) {
	long := strings.Repeat
	for _, tc := range []struct {
		name, command string
		sets          bool
		built         int
	}{
		{"words of many parts", `trap '' ` + long("$a", 490) + long("{1,2}", 7) + ` EXIT`, true, 0},
		{"words past the bound", `trap '' ` + long("{a,b}", 8), false, 0},
		{"a range past the bound", `trap '' {0..128}`, false, 0},
		{"lists past the bound", `trap '' {1..100} {0..28}`, false, 100},
		{"another name", long("{echo,x}", 5) + ` '' {0..100}`, false, 1},
		{"words without the letters of EXIT", `trap '' {a,b}{c,d}`, false, 0},
		{"words without 0", `trap '' {1,2}{3,4}`, false, 0},
		{"words with the letters of EXIT", `trap '' {E,X}{I,T}`, false, 4},
		{"words of a range", `trap '' {1..2}`, false, 2},
		{"words of ANSI-C quoting", `trap '' {$'\x45XIT',a}`, false, 2},
		{"a name without the letters of trap", `{x,y}{a,b} '' EXIT`, false, 0},
		{"a name of quoted letters", `{x,y}'t'"r"ap '' {EXI,a}`, false, 1},
		{"nested braces past the bound", `trap '' {a,{b,{c,{d,{e,{f,{g,{h,{i,0}}}}}}}}}`, false, 0},
		{"parts before braces", `trap '' ` + long("$a", 200) + `{0,1,2}`, false, 0},
		{"a list of many words", `trap '' {0` + strings.Repeat(",0", 110) + `}`, true, 111},
		{"ranges of letters", `trap '' {a..z}{a..z}`, false, 0},
		{"a range of a negative step", `trap '' {1..10..-3}`, false, 4},
		{"a range of a negative step to the bound", `trap '' {1..1000..-10}`, false, 100},
		{"a range of step 0", `trap '' {0..3..0}`, true, 4},
		{"another name after a prefix", `builtin ` + long("{echo,x}", 5) + ` '' {0..100}`, false, 1},
		{"a range the expander overflows", `trap '' {9223372036854775800..9223372036854775807..5}`, false, 2},
		{"parts to the bound", `trap '' {1..100}$a$a {EXIT,a` + long("$a", 108) + `}`, true, 102},
		{"one part more", `trap '' {1..100}$a$a {EXIT,a` + long("$a", 109) + `}`, false, 100},
		{"escaped text past the bound unsplit", `trap '' ` + long(`\{`, maxBraceText) + ` {EXIT,INT}`, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			file, err := syntax.NewParser().Parse(strings.NewReader(tc.command), "")
			require.NoError(t, err)
			call, ok := file.Stmts[0].Cmd.(*syntax.CallExpr)
			require.True(t, ok)
			reader := newTrapReader(file)
			assert.Equal(t, tc.sets, trapSetsExit(reader, call))
			built := 0
			reader.built = func(*syntax.Word) { built++ }
			trapSetsExit(reader, call)
			assert.Equal(t, tc.built, built, "words built")
		})
	}
}

// The words of a trap are built where they may name INT or TERM, and in a
// handler always, as a parameter there may be any signal.
func TestTrapFlowBuildsSignalWords(t *testing.T) {
	for _, tc := range []struct {
		command string
		built   int
	}{
		{`trap - {a,b}{c,d}`, 0},
		{`trap - {I,N}{x,y}`, 0},
		{`trap - {I,N}{T,x}`, 4},
		{`trap - {T,E}{R,M}`, 4},
		{`trap - {2,x}`, 2},
		{`trap - {1,5}`, 2},
		{`trap - {1,x}`, 0},
	} {
		file, err := syntax.NewParser().Parse(strings.NewReader(tc.command), "a.sh")
		require.NoError(t, err)
		call, ok := file.Stmts[0].Cmd.(*syntax.CallExpr)
		require.True(t, ok)
		flow := newScriptFuncs(file).flow(file)
		built := 0
		flow.reader.built = func(*syntax.Word) { built++ }
		flow.readTrap(call)
		assert.Equal(t, tc.built, built, tc.command)
	}
	shellWanted(t, "shell-trap-signal-without-exit", "a.sh", "#!/bin/bash\nstop() { trap - {x,\"$1\"}; kill -s \"$1\" $$; }\ntrap 'stop TERM' TERM\nwhile true; do sleep 1; done\n")
}

// A file of many traps of many parts each is read in bounded memory.
func TestShellTrapWordsMemory(t *testing.T) {
	command := "trap x " + strings.Repeat("$a", 490) + strings.Repeat("{1,2}", 7) + " HUP\n"
	source := "#!/bin/bash\n" + strings.Repeat(command, 300) + "while true; do sleep 1; done\n"
	for _, rule := range []string{"shell-trap-in-loop", "shell-trap-signal-without-exit"} {
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		shellWanted(t, rule, "a.sh", source)
		runtime.ReadMemStats(&after)
		assert.Less(t, after.TotalAlloc-before.TotalAlloc, uint64(256<<20), rule)
	}
}
