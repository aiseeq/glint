package shellrules

import (
	"errors"
	"slices"
	"sort"
	"strings"

	"github.com/aiseeq/akit/shellcmd"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
)

func parseSignalLines(inputs []signalInput, makeRecipes bool) []int {
	if len(inputs) == 0 {
		return nil
	}
	if makeRecipes {
		return parseMakeSignalLines(inputs)
	}
	if len(inputs) == 1 {
		if inputs[0].lineAt == nil && inputs[0].line == 0 {
			return parseSignalUnit(inputs[0].text, nil)
		}
		return parseSignalUnit(inputs[0].text, inputs[0].sourceLine)
	}
	text, lineAt := joinSignalInputs(inputs)
	return parseSignalUnit(text, lineAt)
}

func parseMakeSignalLines(inputs []signalInput) []int {
	var found []int
	var unit []signalInput
	var pending []patternkit.HeredocRedirect
	for _, input := range inputs {
		if len(unit) > 0 {
			delim := pending[0]
			unit = append(unit, signalInput{text: input.text, lineAt: input.lineAt, line: input.line, next: input.next})
			if signalHeredocTerminator(input.text, delim) {
				pending = pending[1:]
			}
			if len(pending) == 0 {
				text, lineAt := joinSignalInputs(unit)
				found = append(found, parseSignalUnit(text, lineAt)...)
				unit = nil
			}
			continue
		}
		text := input.text
		command := signalInput{text: text, lineAt: input.lineAt, line: input.line, next: input.next}
		delims := patternkit.HeredocDelimiters(text)
		if len(delims) == 0 {
			found = append(found, parseSignalUnit(text, input.sourceLine)...)
			continue
		}
		unit = []signalInput{command}
		pending = delims
	}
	if len(unit) > 0 {
		text, lineAt := joinSignalInputs(unit)
		found = append(found, parseSignalUnit(text, lineAt)...)
	}
	sort.Ints(found)
	return slices.Compact(found)
}

func signalHeredocTerminator(line string, delim patternkit.HeredocRedirect) bool {
	body := strings.TrimSuffix(line, "\r")
	if delim.StripTabs {
		body = strings.TrimLeft(body, "\t")
	}
	return body == delim.Word
}

func joinSignalInputs(inputs []signalInput) (string, func(int) int) {
	var source strings.Builder
	starts := make([]int, len(inputs))
	for i, input := range inputs {
		if i > 0 {
			source.WriteByte('\n')
		}
		starts[i] = source.Len()
		source.WriteString(input.text)
	}
	text := source.String()
	lineAt := func(offset int) int {
		idx := sort.Search(len(starts), func(i int) bool { return starts[i] > offset }) - 1
		idx = max(idx, 0)
		return inputs[idx].sourceLine(offset - starts[idx])
	}
	return text, lineAt
}

// A wholly malformed shell unit uses the fallback scanner; shellcmd's NestedError keeps valid outer calls.
func parseSignalUnit(text string, lineAt func(int) int) []int {
	calls, err := shellcmd.Find(text, "kill")
	var nested *shellcmd.NestedError
	if err != nil && !errors.As(err, &nested) {
		return fallbackSignalText(text, lineAt)
	}
	var found []int
	for _, call := range calls {
		if !badKillArgs(call.Args, call.ArgLiteral) {
			continue
		}
		line := call.Line
		if lineAt != nil {
			offset := call.Offset
			if offset < 0 || offset > len(text) {
				offset = signalLineOffset(text, call.Line)
			}
			line = lineAt(offset)
		}
		found = append(found, line)
	}
	sort.Ints(found)
	return slices.Compact(found)
}

func signalLineOffset(text string, line int) int {
	if line <= 1 {
		return 0
	}
	for offset, current := 0, 1; offset < len(text); offset++ {
		if text[offset] == '\n' {
			current++
			if current == line {
				return offset + 1
			}
		}
	}
	return len(text)
}

func fallbackSignalText(text string, lineAt func(int) int) []int {
	if lineAt == nil {
		lineAt = func(offset int) int {
			offset = min(max(offset, 0), len(text))
			return strings.Count(text[:offset], "\n") + 1
		}
	}
	parts := strings.Split(text, "\n")
	inputs := make([]signalInput, len(parts))
	offset := 0
	for i, part := range parts {
		start := offset
		inputs[i] = signalInput{text: part, lineAt: func(local int) int { return lineAt(start + local) }}
		offset += len(part) + 1
		if i+1 < len(parts) {
			inputs[i].next = parts[i+1]
		}
	}
	return scanSignalLinesFallback(inputs)
}
