package shellrules

import (
	"fmt"
	"go/ast"
	"go/types"
	"sort"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

const rawProcessKillSuggestion = "Use proc.StopChild from github.com/aiseeq/akit/proc; pass the request (signal, stdin close, or context cancellation) in its request function literal."

var rawHarmlessSignalNumbers = map[string]bool{
	"1": true, "10": true, "12": true, "19": true, "20": true, "21": true, "22": true,
}

type rawProcessKillRule struct{ *rules.BaseRule }

func init() { rules.Register(newRawProcessKillRule()) }

func newRawProcessKillRule() *rawProcessKillRule {
	return &rawProcessKillRule{rules.NewBaseRule("raw-process-kill", "patterns", "Detects process termination signals sent outside the approved child process helper", core.SeverityMedium)}
}

// AnalyzeFile is not called: the rule reads Go through AnalyzeGoProject.
func (r *rawProcessKillRule) AnalyzeFile(*core.FileContext) []*core.Violation { return nil }

func (r *rawProcessKillRule) RequiresSSA() bool { return false }

func (r *rawProcessKillRule) AnalyzeGoProject(project *core.GoProjectContext) ([]*core.Violation, error) {
	return analyzeSignalProject(project, r.analyzeGo)
}

func (r *rawProcessKillRule) ReportsOn(ctx *core.FileContext) bool { return ctx.IsGoFile() }

func (r *rawProcessKillRule) analyzeGo(file *core.FileContext, pkg *signalPackage) []*core.Violation {
	if pkg == nil || pkg.path == akitProcPath {
		return nil
	}
	var findings []*core.Violation
	for _, site := range fileSignalSites(file, pkg) {
		if site.request || site.implicitTarget() || site.toSelf() || harmlessSignal(site.signal(), site.info) || rawHarmlessSignalNumbers[iValue(site.signal(), site.info)] {
			continue
		}
		line := file.LineFor(site.node)
		if file.IsSuppressed(line, r.Name()) {
			continue
		}
		callee := site.node
		if call, ok := site.node.(*ast.CallExpr); ok {
			callee = call.Fun
		}
		message := fmt.Sprintf("Call to %s sends a process-termination signal outside the approved child stopper; use proc.StopChild from github.com/aiseeq/akit/proc and pass the request in its function literal", types.ExprString(callee))
		v := r.CreateViolation(file.RelPath, line, message)
		v.WithCode(strings.TrimSpace(file.GetLine(line)))
		v.WithSuggestion(rawProcessKillSuggestion)
		findings = append(findings, v)
	}
	sort.SliceStable(findings, func(i, j int) bool { return findings[i].Line < findings[j].Line })
	return findings
}
