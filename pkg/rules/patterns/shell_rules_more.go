package patterns

import (
	"regexp"
	"strings"
)

var (
	// shellExpansion is what a write takes from variables, substitutions and
	// format directives rather than from its own text.
	shellExpansion = regexp.MustCompile(`\$\{[^}]*\}|\$\([^)]*\)|\$[A-Za-z_][A-Za-z0-9_]*|\$[0-9@*#?]|%-?[0-9.]*[sdqfxb]|\\[ntr]`)
	shellWord      = regexp.MustCompile(`\p{L}{2,}`)
)

// writeText returns the text a write command prints itself: the format of
// printf, the arguments of echo, with options, quotes and expansions left out.
func writeText(command string) string {
	command = strings.TrimSpace(command)
	switch {
	case strings.HasPrefix(command, "printf"):
		rest := strings.TrimSpace(strings.TrimPrefix(command, "printf"))
		rest = strings.TrimSpace(strings.TrimPrefix(rest, "--"))
		return shellExpansion.ReplaceAllString(firstShellWord(rest), " ")
	case strings.HasPrefix(command, "echo"):
		rest := strings.TrimSpace(strings.TrimPrefix(command, "echo"))
		for strings.HasPrefix(rest, "-") {
			_, rest, _ = strings.Cut(rest, " ")
			rest = strings.TrimSpace(rest)
		}
		return shellExpansion.ReplaceAllString(strings.NewReplacer(`"`, " ", `'`, " ").Replace(rest), " ")
	}
	return ""
}

// firstShellWord returns the first word of a command line without its quotes.
func firstShellWord(text string) string {
	if text == "" {
		return ""
	}
	if quote := text[0]; quote == '\'' || quote == '"' {
		if end := strings.IndexByte(text[1:], quote); end >= 0 {
			return text[1 : end+1]
		}
		return text[1:]
	}
	word, _, _ := strings.Cut(text, " ")
	return word
}

// textWords counts the words of printed text: whitespace-separated tokens
// with letters. A path or a domain is one token, a value rather than a
// message.
func textWords(text string) int {
	words := 0
	for _, token := range strings.Fields(text) {
		if shellWord.MatchString(token) {
			words++
		}
	}
	return words
}

// ownMessages returns the lines where a captured function prints a message
// of its own (two words or more of text) to the stdout that also carries its
// data (a write of expansions only). A function that prints only text, or a
// one-word answer, gives that text as its value.
func (src *shellSource) ownMessages(fn shellFunc) []int {
	var messages []int
	data := false
	for _, l := range src.body(fn) {
		for _, seg := range segments(l.text) {
			write := commandPrefix.ReplaceAllString(seg.trimmed(), "")
			if !stdoutWrite.MatchString(write) || !writesToStdout(write) || strings.Contains(seg.text, "|") {
				continue
			}
			switch words := textWords(writeText(write)); {
			case words == 0:
				data = true
			case words >= 2:
				messages = append(messages, l.lineAt(seg.offset))
			}
		}
	}
	if !data {
		return nil
	}
	return messages
}

var (
	psqlCommandAssign = regexp.MustCompile(`(?:^|[\s;])(?:(?:local|export|readonly|declare)\s+)?([A-Za-z_][A-Za-z0-9_]*)=["']?psql\b`)
	expandedHead      = regexp.MustCompile(`^\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?(?:\s|$)`)
)

// psqlCommandVariables returns the variables a script assigns a psql command
// line without ON_ERROR_STOP, with the line of that assignment: run later as
// $NAME -f file, the command is fixed where it is written.
func psqlCommandVariables(src *shellSource) map[string]int {
	vars := make(map[string]int)
	for _, l := range src.lines {
		for _, seg := range segments(l.text) {
			m := psqlCommandAssign.FindStringSubmatch(seg.text)
			if m == nil {
				continue
			}
			if strings.Contains(seg.text, "ON_ERROR_STOP") {
				delete(vars, m[1])
				continue
			}
			vars[m[1]] = l.lineAt(seg.offset)
		}
	}
	return vars
}

// expandedCommand returns NAME of a command that is the expansion $NAME or
// ${NAME} followed by its arguments, after if/then/!.
func expandedCommand(command string) string {
	if m := expandedHead.FindStringSubmatch(commandPrefix.ReplaceAllString(command, "")); m != nil {
		return m[1]
	}
	return ""
}

var (
	capturedAssign = regexp.MustCompile(`^(?:(?:local|export|readonly|declare)\s+)?[A-Za-z_][A-Za-z0-9_]*=\$\(\s*([A-Za-z_][A-Za-z0-9_.-]*)`)
	// remoteCommands talk to a service: their failure is an outage, not an
	// answer such as grep's "no match".
	remoteCommands = map[string]bool{"curl": true, "wget": true, "ssh": true, "scp": true, "http": true, "https": true, "psql": true, "mysql": true, "kubectl": true, "aws": true, "gcloud": true, "nc": true}
)

// droppedStatus reports x=$(cmd) || true (or || :) where cmd calls a service
// or a function of the script.
func droppedStatus(command, fallback string, funcs map[string]shellFunc) bool {
	if fallback != "true" && fallback != ":" {
		return false
	}
	m := capturedAssign.FindStringSubmatch(commandPrefix.ReplaceAllString(command, ""))
	if m == nil {
		return false
	}
	_, ownFunction := funcs[m[1]]
	return remoteCommands[m[1]] || ownFunction
}
