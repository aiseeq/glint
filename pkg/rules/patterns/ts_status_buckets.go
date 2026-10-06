package patterns

import (
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(statusBucketsWithoutRestRule())
}

// statusBucketsWithoutRestRule detects records counted into a total and
// spread over buckets by an if/else-if chain on their status with no final
// else:
//
//	for (const t of totals) {
//	  result.total.count += t.count
//	  if (t.status === 'pending') { result.pending.count += t.count }
//	  else if (t.status === 'completed') { result.completed.count += t.count }
//	}
//
// A status no branch names ('approved', one added later) counts in the total
// and in no bucket: the cards stop adding up to the total and nobody sees
// which records fell out. Give the chain a final else bucket ("other").
func statusBucketsWithoutRestRule() *tsRule {
	return newTSRule("status-buckets-without-rest",
		"Detects records counted into a total and spread over buckets by an if/else-if chain on their status with no final else — an unnamed status counts in the total and in no bucket",
		checkStatusBucketsWithoutRest)
}

var (
	// jsForOfLoop is a for...of loop and its record variable.
	jsForOfLoop = regexp.MustCompile(`\bfor\s*\(\s*(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s+of\b`)
	// jsTotalAccumulation adds to a total: result.total.count += t.count, total++.
	jsTotalAccumulation = regexp.MustCompile(`(?i)\btotal\w*(?:\.[\w$]+)?\s*(?:\+=|\+\+)`)
	// jsAccumulation adds to anything.
	jsAccumulation = regexp.MustCompile(`\+=|\+\+`)
	// jsIfKeyword opens an if statement.
	jsIfKeyword = regexp.MustCompile(`\bif\s*\(`)
)

// minStatusBuckets is the number of branches that makes a chain a spread over
// buckets rather than a special case or two.
const minStatusBuckets = 3

func checkStatusBucketsWithoutRest(r *tsRule, ctx *core.FileContext, f jsFlat) []*core.Violation {
	var out []*core.Violation
	for _, m := range jsForOfLoop.FindAllStringSubmatchIndex(f.code, -1) {
		record := f.code[m[2]:m[3]]
		headEnd, ok := f.closing(m[0] + strings.IndexByte(f.code[m[0]:], '('))
		if !ok {
			continue
		}
		brace := headEnd + 1 + len(f.code[headEnd+1:]) - len(strings.TrimLeft(f.code[headEnd+1:], " \t\n"))
		if brace >= len(f.code) || f.code[brace] != '{' {
			continue
		}
		end, ok := f.closing(brace)
		if !ok || !accumulatesTotal(f, brace, end) {
			continue
		}
		field := regexp.MustCompile(`\b` + regexp.QuoteMeta(record) + `\??\.(\w*(?:status|state)\w*)\b`)
		for _, ifm := range jsIfKeyword.FindAllStringIndex(f.code[brace:end], -1) {
			pos := brace + ifm[0]
			if f.enclosingBrace(pos) != brace || strings.HasSuffix(strings.TrimRight(f.code[:pos], " \t\n"), "else") {
				continue
			}
			if branches, rest := statusChain(f, pos, field); branches >= minStatusBuckets && !rest {
				out = jsReport(out, r.BaseRule, ctx, f.line(pos),
					"Records counted in the total are spread over buckets by status with no final else — a status no branch names counts in the total and in no bucket",
					"End the chain with an else bucket (other statuses) so the buckets add up to the total")
			}
		}
	}
	return out
}

// accumulatesTotal reports a loop body that adds to a total outside any
// branch of its own.
func accumulatesTotal(f jsFlat, brace, end int) bool {
	for _, m := range jsTotalAccumulation.FindAllStringIndex(f.code[brace:end], -1) {
		if f.enclosingBrace(brace+m[0]) == brace {
			return true
		}
	}
	return false
}

// statusChain follows the if/else-if chain that starts at pos: the number of
// branches whose condition reads the record's status field and whose body
// accumulates, and whether the chain ends with a plain else.
func statusChain(f jsFlat, pos int, field *regexp.Regexp) (branches int, rest bool) {
	name := ""
	for {
		open := pos + strings.IndexByte(f.code[pos:], '(')
		closeParen, ok := f.closing(open)
		if !ok {
			return branches, false
		}
		m := field.FindStringSubmatch(f.text[open:closeParen])
		if m == nil || name != "" && m[1] != name {
			return 0, false
		}
		name = m[1]
		brace := skipSpaces(f.code, closeParen+1)
		if brace >= len(f.code) || f.code[brace] != '{' {
			return 0, false
		}
		end, ok := f.closing(brace)
		if !ok || !jsAccumulation.MatchString(f.code[brace:end]) {
			return 0, false
		}
		branches++
		next := skipSpaces(f.code, end+1)
		if !strings.HasPrefix(f.code[next:], "else") {
			return branches, false
		}
		next = skipSpaces(f.code, next+len("else"))
		if !strings.HasPrefix(f.code[next:], "if") {
			return branches, true
		}
		pos = next
	}
}

// skipSpaces returns the offset of the first non-space byte at or after pos.
func skipSpaces(s string, pos int) int {
	for pos < len(s) && strings.IndexByte(" \t\r\n", s[pos]) >= 0 {
		pos++
	}
	return pos
}
