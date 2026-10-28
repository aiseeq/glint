package patternkit

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
		return shellExpansion.ReplaceAllString(FirstShellWord(rest), " ")
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

// FirstShellWord returns the first word of a command line without its quotes.
func FirstShellWord(text string) string {
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
	for token := range strings.FieldsSeq(text) {
		if shellWord.MatchString(token) {
			words++
		}
	}
	return words
}

// OwnMessages returns the lines where a captured function prints a message
// of its own (two words or more of text) to the stdout that also carries its
// data (a write of expansions only). A function that prints only text, or a
// one-word answer, gives that text as its value.
func (src *ShellSource) OwnMessages(fn ShellFunc) []int {
	var messages []int
	data := false
	for _, l := range src.Body(fn) {
		for _, seg := range Segments(l.Text) {
			write := CommandPrefix.ReplaceAllString(seg.Trimmed(), "")
			if !stdoutWrite.MatchString(write) || !WritesToStdout(write) || strings.Contains(seg.Text, "|") {
				continue
			}
			switch words := textWords(writeText(write)); {
			case words == 0:
				data = true
			case words >= 2:
				messages = append(messages, l.LineAt(seg.Offset))
			}
		}
	}
	if !data {
		return nil
	}
	return messages
}
