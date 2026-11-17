package concurrencyrules

import (
	"go/ast"
	"go/types"
	"regexp"
	"slices"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
)

func init() {
	rules.Register(NewRuntimeGCTuningRule())
}

// RuntimeGCTuningRule combines the typed Go check with checks of deployment files.
type RuntimeGCTuningRule struct{ *patternkit.TypedFuncRule }

// gcTuningEnvVars are the environment variables that set the collector up.
var gcTuningEnvVars = []string{"GOGC", "GOMEMLIMIT"}

// gcForcingFuncs force a collection: a measurement does it before reading the
// heap, anything else runs the collector by hand.
var gcForcingFuncs = []struct{ pkg, name string }{
	{"runtime", "GC"},
	{"runtime/debug", "FreeOSMemory"},
}

// NewRuntimeGCTuningRule creates runtime-gc-tuning: production code that sets
// the collector up - debug.SetGCPercent, debug.SetMemoryLimit, GOGC or
// GOMEMLIMIT through os.Setenv, a forced runtime.GC or debug.FreeOSMemory -
// hides where the garbage comes from. The collector runs less often and the
// program pays with memory, while the allocations stay:
//
//	if os.Getenv("GOGC") == "" {
//		debug.SetGCPercent(400) // GC was 19% of the profile
//	}
//
// The fix removes the allocations (buffers on the receiver, refilled in
// place). A collection forced right before a heap profile or a memory reading
// in the same function is measurement and is not reported; tests are not
// checked. A memory limit sized to a container is a deliberate setting and
// takes a suppression with the limit and the measured RSS as its reason.
func NewRuntimeGCTuningRule() *RuntimeGCTuningRule {
	r := &patternkit.TypedFuncRule{
		BaseRule: rules.NewBaseRule(
			"runtime-gc-tuning",
			"patterns",
			"Detects the collector set up from production code — debug.SetGCPercent, debug.SetMemoryLimit, os.Setenv of GOGC or GOMEMLIMIT, a forced runtime.GC, or GOGC/GOMEMLIMIT in shell, Makefile, Dockerfile or compose — it trades memory for CPU and hides where the garbage comes from; remove the allocations instead. In compose, GOMEMLIMIT in a service with mem_limit or deploy.resources.limits.memory is an intentional memory bound; GOGC remains reportable. It ignores .graft.yaml because its env configures development tasks, and ignores a bench script containing go test with -bench or -benchmem because those settings configure a measurement.",
			core.SeverityMedium,
		),
		Suggestion: "Find the allocations in the profile (go tool pprof -sample_index=alloc_space) and remove them; a memory limit sized to a container takes // runtime-gc-tuning: safe — <limit, measured RSS>",
	}
	r.Check = func(scope patternkit.FuncScope, fn *ast.FuncDecl) []patternkit.FuncFinding {
		measures := measuresMemory(scope.Info, fn.Body)
		var findings []patternkit.FuncFinding
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if what := gcTuningCall(scope.Info, call, measures); what != "" {
				findings = append(findings, patternkit.FuncFinding{Node: call, Message: what + " sets the collector up from code — it trades memory for CPU and leaves the allocations where they are"})
			}
			return true
		})
		return findings
	}
	return &RuntimeGCTuningRule{TypedFuncRule: r}
}

var (
	gcEnvAssignment = regexp.MustCompile(`(?:^|[\s;])(?:export\s+)?(GOGC|GOMEMLIMIT)\s*=`)
	gcDockerEnv     = regexp.MustCompile(`(?i)^\s*ENV\s+(.*)$`)
	gcYAMLKey       = regexp.MustCompile(`^\s*(?:-\s*)?(GOGC|GOMEMLIMIT)\s*:`)
	gcYAMLList      = regexp.MustCompile(`^\s*-\s*(GOGC|GOMEMLIMIT)\s*=`)
	gcYAMLAnyKey    = regexp.MustCompile(`^\s*([A-Za-z0-9_.-]+)\s*:`)
	gcServicesKey   = regexp.MustCompile(`^\s*services\s*:`)
	gcInlineYAML    = regexp.MustCompile(`\b(GOGC|GOMEMLIMIT)\s*:`)
	gcBenchCommand  = regexp.MustCompile(`\bgo\s+test\b`)
	gcBenchFlag     = regexp.MustCompile(`(?:^|\s)-bench(?:mem)?(?:=|\s|$)`)
)

// gcTuningCall describes a call that sets the collector up, "" for any other
// call. A forced collection counts only outside a measurement.
func gcTuningCall(info *types.Info, call *ast.CallExpr, measures bool) string {
	if name, ok := patternkit.PackageFuncName(nil, info, call, "runtime/debug"); ok && (name == "SetGCPercent" || name == "SetMemoryLimit") {
		return "debug." + name
	}
	if name, ok := patternkit.PackageFuncName(nil, info, call, "os"); ok && name == "Setenv" && len(call.Args) == 2 {
		if key, isConst := patternkit.StringConstant(info, call.Args[0]); isConst && slices.Contains(gcTuningEnvVars, key) {
			return "os.Setenv(" + key + ")"
		}
	}
	if measures {
		return ""
	}
	for _, f := range gcForcingFuncs {
		if name, ok := patternkit.PackageFuncName(nil, info, call, f.pkg); ok && name == f.name {
			return "a forced " + types.ExprString(call.Fun)
		}
	}
	return ""
}

// measuresMemory reports a body that reads the heap after forcing a
// collection: it writes a runtime/pprof profile or reads runtime.MemStats or
// runtime/metrics.
func measuresMemory(info *types.Info, body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || found {
			return !found
		}
		fn := patternkit.StaticFunc(info, call)
		if fn == nil || fn.Pkg() == nil {
			return true
		}
		switch fn.Pkg().Path() {
		case "runtime/pprof", "runtime/metrics":
			found = true
		case "runtime":
			found = fn.Name() == "ReadMemStats"
		}
		return !found
	})
	return found
}

// AnalyzeFile checks runtime GC settings in shell, Makefile, Dockerfile and compose.
func (r *RuntimeGCTuningRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	switch {
	case ctx.IsShellFile() || ctx.IsMakefile():
		return r.analyzeShellFile(ctx)
	case ctx.IsDockerfile():
		return r.analyzeDockerfile(ctx)
	case ctx.IsComposeFile():
		return r.analyzeCompose(ctx)
	default:
		return nil
	}
}

// ReadsNonGoFiles lets the check flow analyze deployment files alongside Go.
func (r *RuntimeGCTuningRule) ReadsNonGoFiles() {}

// ReportsOn includes Go files and the deployment formats this rule inspects.
func (r *RuntimeGCTuningRule) ReportsOn(ctx *core.FileContext) bool {
	return ctx.IsGoFile() || ctx.IsShellFile() || ctx.IsMakefile() || ctx.IsDockerfile() || ctx.IsComposeFile()
}

func (r *RuntimeGCTuningRule) analyzeShellFile(ctx *core.FileContext) []*core.Violation {
	src, ok := patternkit.ReadShell(ctx)
	if !ok || isBenchScript(ctx.Content) {
		return nil
	}
	heredocExempt := shellComposeGOMEMLIMITExemptions(ctx)
	var out []*core.Violation
	for _, logical := range src.Lines {
		text := patternkit.WithoutComment(logical.Text)
		for _, loc := range gcEnvAssignment.FindAllStringSubmatchIndex(text, -1) {
			line := logical.LineAt(loc[0])
			if text[loc[2]:loc[3]] == "GOMEMLIMIT" && shellLineIsExempt(ctx, line, heredocExempt) {
				continue
			}
			line = shellComposeListLine(ctx, line)
			out = appendGCSetting(out, r, ctx, line, text, "shell or make recipe")
		}
	}
	return out
}

func (r *RuntimeGCTuningRule) analyzeDockerfile(ctx *core.FileContext) []*core.Violation {
	var out []*core.Violation
	for i, raw := range ctx.Lines {
		match := gcDockerEnv.FindStringSubmatch(raw)
		if match == nil {
			continue
		}
		if len(gcEnvAssignment.FindAllStringSubmatchIndex(match[1], -1)) > 0 {
			out = appendGCSetting(out, r, ctx, i+1, raw, "Dockerfile ENV")
		}
	}
	return out
}

func (r *RuntimeGCTuningRule) analyzeCompose(ctx *core.FileContext) []*core.Violation {
	var out []*core.Violation
	variables, exempt := composeServiceVariables(ctx, ctx.Lines, 1)
	for _, variable := range variables {
		if variable.key == "GOMEMLIMIT" && exempt[variable.line] {
			continue
		}
		out = appendGCSetting(out, r, ctx, variable.line, ctx.GetLine(variable.line), "compose environment")
	}
	return out
}

type composeGCVariable struct {
	key  string
	line int
}

type composeYAMLKey struct {
	indent int
	name   string
}

func composeServiceVariables(ctx *core.FileContext, lines []string, firstLine int) ([]composeGCVariable, map[int]bool) {
	var variables []composeGCVariable
	exempt := make(map[int]bool)
	servicesIndent := -1
	for i, raw := range lines {
		text := composeBody(ctx, raw)
		indent := yamlIndent(raw)
		if gcServicesKey.MatchString(text) {
			servicesIndent = indent
			continue
		}
		if servicesIndent < 0 || (text != "" && indent <= servicesIndent) {
			servicesIndent = -1
			continue
		}
		if indent != servicesIndent+2 || !gcYAMLAnyKey.MatchString(text) {
			continue
		}
		end := composeServiceEnd(ctx, lines, i+1, servicesIndent+2)
		serviceVars, hardLimit := composeServiceVariablesInBlock(ctx, lines[i+1:end], firstLine+i+1)
		for _, variable := range serviceVars {
			variables = append(variables, variable)
			if hardLimit && variable.key == "GOMEMLIMIT" {
				exempt[variable.line] = true
			}
		}
	}
	return variables, exempt
}

func composeServiceEnd(ctx *core.FileContext, lines []string, from, serviceIndent int) int {
	for i := from; i < len(lines); i++ {
		text := composeBody(ctx, lines[i])
		if text != "" && yamlIndent(lines[i]) <= serviceIndent {
			return i
		}
	}
	return len(lines)
}

func composeServiceVariablesInBlock(ctx *core.FileContext, lines []string, firstLine int) ([]composeGCVariable, bool) {
	var variables []composeGCVariable
	var path []composeYAMLKey
	envIndent := -1
	hardLimit := false
	for i, raw := range lines {
		text := composeBody(ctx, raw)
		indent := yamlIndent(raw)
		key := gcYAMLAnyKey.FindStringSubmatch(text)
		if key != nil {
			path = trimYAMLPath(path, indent)
			if key[1] == "mem_limit" || key[1] == "memory" && hasComposeMemoryLimitPath(path) {
				hardLimit = true
			}
			path = append(path, composeYAMLKey{indent: indent, name: key[1]})
		}
		if envIndent >= 0 && text != "" && indent <= envIndent {
			envIndent = -1
		}
		if strings.HasPrefix(text, "environment:") {
			envIndent = indent
			if gcInlineYAML.MatchString(text) {
				variables = append(variables, composeInlineVariables(text, firstLine+i)...)
			}
			continue
		}
		if envIndent >= 0 && (gcYAMLKey.MatchString(text) || gcYAMLList.MatchString(text)) {
			match := gcYAMLKey.FindStringSubmatch(text)
			if match == nil {
				match = gcYAMLList.FindStringSubmatch(text)
			}
			variables = append(variables, composeGCVariable{key: match[1], line: firstLine + i})
		}
	}
	return variables, hardLimit
}

func composeInlineVariables(text string, line int) []composeGCVariable {
	var variables []composeGCVariable
	for _, match := range gcInlineYAML.FindAllStringSubmatch(text, -1) {
		variables = append(variables, composeGCVariable{key: match[1], line: line})
	}
	return variables
}

func trimYAMLPath(path []composeYAMLKey, indent int) []composeYAMLKey {
	for len(path) > 0 && path[len(path)-1].indent >= indent {
		path = path[:len(path)-1]
	}
	return path
}

func hasComposeMemoryLimitPath(path []composeYAMLKey) bool {
	if len(path) < 3 {
		return false
	}
	return path[len(path)-1].name == "limits" && path[len(path)-2].name == "resources" && path[len(path)-3].name == "deploy"
}

func composeBody(ctx *core.FileContext, raw string) string {
	return strings.TrimSpace(strings.TrimSuffix(raw, ctx.CommentOf(raw)))
}

func yamlIndent(raw string) int {
	return len(raw) - len(strings.TrimLeft(raw, " \t"))
}

func shellComposeGOMEMLIMITExemptions(ctx *core.FileContext) map[int]bool {
	exempt := make(map[int]bool)
	for i, raw := range ctx.Lines {
		for _, delimiter := range patternkit.HeredocDelimiters(raw) {
			end := heredocEnd(ctx, i+1, delimiter)
			if end <= i+1 {
				continue
			}
			body := ctx.Lines[i+1 : end]
			_, serviceExempt := composeServiceVariables(ctx, body, i+2)
			for line := range serviceExempt {
				exempt[line] = true
			}
			i = end
		}
	}
	return exempt
}

func heredocEnd(ctx *core.FileContext, from int, delimiter patternkit.HeredocRedirect) int {
	for i := from; i < len(ctx.Lines); i++ {
		line := ctx.Lines[i]
		if delimiter.StripTabs {
			line = strings.TrimLeft(line, "\t")
		}
		if line == delimiter.Word {
			return i
		}
	}
	return from
}

func shellLineIsExempt(ctx *core.FileContext, line int, exempt map[int]bool) bool {
	if exempt[line] {
		return true
	}
	return line < len(ctx.Lines) && exempt[line+1] && strings.Contains(ctx.Lines[line], "GOMEMLIMIT=")
}

func shellComposeListLine(ctx *core.FileContext, line int) int {
	for i, raw := range ctx.Lines {
		for _, delimiter := range patternkit.HeredocDelimiters(raw) {
			end := heredocEnd(ctx, i+1, delimiter)
			if line < i+2 || line >= end+1 {
				continue
			}
			if strings.HasPrefix(strings.TrimSpace(ctx.Lines[line-1]), "- GOGC=") || strings.HasPrefix(strings.TrimSpace(ctx.Lines[line-1]), "- GOMEMLIMIT=") {
				return line - 1
			}
		}
	}
	return line
}

func appendGCSetting(out []*core.Violation, r *RuntimeGCTuningRule, ctx *core.FileContext, line int, code, where string) []*core.Violation {
	if ctx.SuppressesFinding(line, r.Name(), r.DefaultSeverity()) {
		return out
	}
	v := r.CreateViolation(ctx.RelPath, line, "GOGC or GOMEMLIMIT sets the garbage collector up in "+where+" — it trades memory for CPU and leaves allocations in place")
	v.WithCode(strings.TrimSpace(code))
	v.WithSuggestion(r.Suggestion)
	return append(out, v)
}

func isBenchScript(content []byte) bool {
	text := string(content)
	return gcBenchCommand.MatchString(text) && gcBenchFlag.MatchString(text)
}
