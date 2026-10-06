package patterns

import (
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(retryAfterOwnTimeoutRule())
}

// retryAfterOwnTimeoutRule detects a request function that aborts its own
// fetch by a timer and retries transport failures without asking whether the
// failure was that abort:
//
//	const timeoutId = setTimeout(() => controller.abort(), 30000)
//	...
//	} catch (error) {
//	  if (isTransportError(error) && retryCount < 3) return this.makeRequest(endpoint, retryCount + 1)
//	}
//
// The abort fails the fetch like a dropped connection, so a server that did
// not answer in time is asked again and again, each attempt waiting the whole
// timeout: four attempts of 30 seconds keep the spinner for two minutes, and
// the server keeps working on every copy. Check controller.signal.aborted (or
// the AbortError) before retrying.
func retryAfterOwnTimeoutRule() *tsRule {
	return newTSRule("retry-after-own-timeout",
		"Detects a request that aborts itself by a timer and retries transport failures without checking that the abort was its own — every attempt waits the whole timeout again",
		checkRetryAfterOwnTimeout)
}

var (
	// jsTimerAbort is a timer that aborts a controller: setTimeout(() => c.abort(), ms).
	jsTimerAbort = regexp.MustCompile(`setTimeout\(\s*(?:\(\s*\)|\w+)\s*=>\s*\{?\s*([A-Za-z_$][\w$]*)\.abort\(\s*\)`)
	// jsTransportFailure is a test for a failure to deliver the request.
	jsTransportFailure = regexp.MustCompile(`\bis(?:Transport|Network)Error\s*\(|instanceof\s+TypeError\b`)
	// jsOwnAbortCheck tells an own abort from a transport failure.
	jsOwnAbortCheck = regexp.MustCompile(`\.signal\.aborted\b|AbortError|\btimedOut\b|\btimeoutHit\b`)
)

func checkRetryAfterOwnTimeout(r *tsRule, ctx *core.FileContext, f jsFlat) []*core.Violation {
	var out []*core.Violation
	for _, m := range jsTimerAbort.FindAllStringSubmatchIndex(f.code, -1) {
		fn, ok := namedEnclosingFunction(f, m[0])
		if !ok {
			continue
		}
		end, ok := f.closing(fn.brace)
		if !ok {
			continue
		}
		body := f.text[fn.brace:end]
		if jsOwnAbortCheck.MatchString(body) || !callsItself(body, fn.name) {
			continue
		}
		if loc := jsTransportFailure.FindStringIndex(body); loc != nil {
			out = jsReport(out, r.BaseRule, ctx, f.line(fn.brace+loc[0]),
				"The retry takes the request's own timeout abort for a transport failure — every attempt waits the whole timeout again",
				"Check controller.signal.aborted before retrying and give up on the own timeout")
		}
	}
	return out
}

// namedEnclosingFunction returns the innermost named function around pos,
// past the anonymous callbacks inside it.
func namedEnclosingFunction(f jsFlat, pos int) (jsFunc, bool) {
	fn, ok := f.enclosingFunction(pos)
	for ok && fn.name == "" {
		fn, ok = f.enclosingFunction(fn.start)
	}
	return fn, ok
}

// callsItself reports a body that calls the function it belongs to again:
// name(...) or name<T>(...).
func callsItself(body, name string) bool {
	re := regexp.MustCompile(`\b` + regexp.QuoteMeta(name) + `\s*(?:<[^>()]*>)?\s*\(`)
	return re.MatchString(strings.TrimSpace(body))
}
