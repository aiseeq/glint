package patterns

import (
	"errors"
	"fmt"
	"go/constant"
	"go/token"
	"go/types"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"golang.org/x/tools/go/callgraph/cha"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

var defaultAuditActorSinks = []string{
	"RecordStatusHistory",
	"CreateWithHistory",
	"CreateOrGet",
	"ApplyStatusTransition",
	"ClaimCancellationIntent",
	"MarkWaitingApproval",
	"ApplyQuote",
	"ApplySentToProvider",
}

var auditActorParameterNames = map[string]bool{
	"actorUserID":       true,
	"approverUserID":    true,
	"submittedByUserID": true,
	"createdByUserID":   true,
	"operatorUserID":    true,
	"userID":            true,
}

var auditSourceParameterNames = map[string]bool{
	"source":        true,
	"auditSource":   true,
	"historySource": true,
}

var auditActorFieldNames = map[string]bool{
	"CreatedByUserID":   true,
	"SubmittedByUserID": true,
	"ApprovedByUserID":  true,
	"ActorUserID":       true,
	"OperatorUserID":    true,
}

var auditHumanCallNames = map[string]bool{
	"currentUser":       true,
	"authenticatedUser": true,
	"currentAdmin":      true,
}

func init() {
	rules.Register(NewAuditActorPropagationRule())
}

// AuditActorPropagationRule detects loss of human actor and audit source
// attribution before typed audit sinks.
type AuditActorPropagationRule struct {
	*rules.BaseRule
	sinks map[string]bool
}

// NewAuditActorPropagationRule creates the package-level SSA rule.
func NewAuditActorPropagationRule() *AuditActorPropagationRule {
	return &AuditActorPropagationRule{
		BaseRule: rules.NewBaseRule(
			"audit-actor-propagation",
			"patterns",
			"Detects human actor or audit source attribution lost before audit writes",
			core.SeverityHigh,
		),
		sinks: auditSinkSet(defaultAuditActorSinks),
	}
}

// Configure replaces the default sink names when sinks is explicitly set.
// Callers can supplement the defaults by including them in the configured list.
func (r *AuditActorPropagationRule) Configure(settings map[string]any) error {
	if err := r.BaseRule.Configure(settings); err != nil {
		return err
	}
	configured, ok := settings["sinks"]
	if !ok {
		return nil
	}
	sinks, err := auditSinkNames(configured)
	if err != nil {
		return err
	}
	r.sinks = auditSinkSet(sinks)
	return nil
}

// auditSinkNames reads the sinks setting: a list of non-empty function names,
// as []string from code or []any from a YAML configuration.
func auditSinkNames(configured any) ([]string, error) {
	var items []any
	switch list := configured.(type) {
	case []string:
		for _, name := range list {
			items = append(items, name)
		}
	case []any:
		items = list
	default:
		return nil, fmt.Errorf("configure audit-actor-propagation sinks: expected a list of function names, got %T", configured)
	}
	sinks := make([]string, 0, len(items))
	for i, item := range items {
		name, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("configure audit-actor-propagation sinks: item %d is %T, expected a function name string", i, item)
		}
		if strings.TrimSpace(name) == "" {
			return nil, fmt.Errorf("configure audit-actor-propagation sinks: item %d is empty", i)
		}
		sinks = append(sinks, name)
	}
	return sinks, nil
}

func auditSinkSet(names []string) map[string]bool {
	sinks := make(map[string]bool, len(names))
	for _, name := range names {
		sinks[name] = true
	}
	return sinks
}

// AnalyzeFile is a no-op because this rule requires shared package SSA.
func (r *AuditActorPropagationRule) AnalyzeFile(_ *core.FileContext) []*core.Violation {
	return nil
}

// RequiresSSA reports that AnalyzeGoProject requires built SSA and its program.
func (r *AuditActorPropagationRule) RequiresSSA() bool { return true }

// AnalyzeGoProject follows actor and source taint through context-sensitive SSA calls.
func (r *AuditActorPropagationRule) AnalyzeGoProject(ctx *core.GoProjectContext) ([]*core.Violation, error) {
	if ctx == nil {
		return nil, errors.New("audit actor propagation: nil Go project context")
	}
	if ctx.Program == nil {
		// A tolerated load in which no package type-checked has no SSA to
		// follow; typed packages without SSA are a loader fault.
		if len(ctx.Packages) == 0 {
			return nil, nil
		}
		return nil, errors.New("audit actor propagation: Go project has no SSA program")
	}
	if ctx.FileSet == nil {
		return nil, errors.New("audit actor propagation: project has no file set for source positions")
	}

	analyzer := &auditActorAnalyzer{
		rule:           r,
		project:        ctx,
		seen:           make(map[auditStateKey]bool),
		reported:       make(map[auditFindingKey]bool),
		sourcePackages: make(map[*ssa.Package]bool),
		sourceFiles:    make(map[string]bool),
		humanRoots:     make(map[*ssa.Function]bool),
	}
	for _, pkg := range ctx.Packages {
		if pkg != nil && pkg.SSA != nil {
			analyzer.sourcePackages[pkg.SSA] = true
			for _, file := range pkg.Files {
				analyzer.sourceFiles[filepath.Clean(file.Path)] = true
			}
		}
	}
	if err := analyzer.initialize(); err != nil {
		return nil, err
	}
	if err := analyzer.run(); err != nil {
		return nil, err
	}
	sort.Slice(analyzer.violations, func(i, j int) bool {
		left, right := analyzer.violations[i], analyzer.violations[j]
		if left.File != right.File {
			return left.File < right.File
		}
		if left.Line != right.Line {
			return left.Line < right.Line
		}
		leftPattern, _ := left.Context["pattern"].(string)
		rightPattern, _ := right.Context["pattern"].(string)
		return leftPattern < rightPattern
	})
	return analyzer.violations, nil
}

// bitsPerTaintWord is how many values one word of the taint bitset holds.
const bitsPerTaintWord = 64

type auditTaintBits []uint64

func newAuditTaintBits(size int) auditTaintBits {
	return make(auditTaintBits, (size+bitsPerTaintWord-1)/bitsPerTaintWord)
}

func (bits auditTaintBits) clone() auditTaintBits {
	return append(auditTaintBits(nil), bits...)
}

func (bits auditTaintBits) set(index int) {
	bits[index/64] |= uint64(1) << uint(index%64)
}

func (bits auditTaintBits) has(index int) bool {
	return index >= 0 && index/64 < len(bits) && bits[index/64]&(uint64(1)<<uint(index%64)) != 0
}

func (bits auditTaintBits) any() bool {
	for _, word := range bits {
		if word != 0 {
			return true
		}
	}
	return false
}

func (bits auditTaintBits) anyBefore(limit int) bool {
	for index := 0; index < limit; index++ {
		if bits.has(index) {
			return true
		}
	}
	return false
}

func (bits auditTaintBits) key() string {
	var result strings.Builder
	for _, word := range bits {
		result.WriteString(strconv.FormatUint(word, 16))
		result.WriteByte('/')
	}
	return result.String()
}

type auditState struct {
	function *ssa.Function
	actor    auditTaintBits
	source   auditTaintBits
	human    bool
}

type auditStateKey struct {
	function *ssa.Function
	actor    string
	source   string
	human    bool
}

type auditFindingKey struct {
	file    string
	line    int
	column  int
	sink    string
	pattern string
}

type auditActorAnalyzer struct {
	rule           *AuditActorPropagationRule
	project        *core.GoProjectContext
	targets        map[ssa.CallInstruction][]*ssa.Function
	sourcePackages map[*ssa.Package]bool
	sourceFiles    map[string]bool
	sources        map[*ssa.Function]bool
	humanRoots     map[*ssa.Function]bool
	worklist       []auditState
	seen           map[auditStateKey]bool
	reported       map[auditFindingKey]bool
	violations     []*core.Violation
}

// auditCallIndexKey caches the call index once per module load: the SSA
// functions, the call graph and the call targets do not depend on which files
// the run analyzes.
type auditCallIndexKey struct{}

// auditCallIndex is the analyzed-root independent part of the analysis: every
// SSA function sorted by name, the file declaring each one, the targets of
// each call site with the reverse view, and the caller-callee edges of the
// call graph between distinct functions.
type auditCallIndex struct {
	functions []*ssa.Function
	files     map[*ssa.Function]string
	targets   map[ssa.CallInstruction][]*ssa.Function
	callSites map[*ssa.Function][]auditCallSite
	edges     []auditCallEdge
}

// auditCallSite is one call that may reach a target, in caller order.
type auditCallSite struct {
	caller *ssa.Function
	call   ssa.CallInstruction
}

type auditCallEdge struct {
	caller *ssa.Function
	callee *ssa.Function
}

func buildAuditCallIndex(program *ssa.Program, fset *token.FileSet) *auditCallIndex {
	allFunctions := ssautil.AllFunctions(program)
	index := &auditCallIndex{
		functions: make([]*ssa.Function, 0, len(allFunctions)),
		files:     make(map[*ssa.Function]string),
		targets:   make(map[ssa.CallInstruction][]*ssa.Function),
		callSites: make(map[*ssa.Function][]auditCallSite),
	}
	for function := range allFunctions {
		index.functions = append(index.functions, function)
		if function.Syntax() == nil {
			continue
		}
		if position := fset.PositionFor(function.Syntax().Pos(), false); position.IsValid() {
			index.files[function] = filepath.Clean(position.Filename)
		}
	}
	sortFunctionsByName(index.functions)

	graph := cha.CallGraph(program)
	for _, node := range graph.Nodes {
		if node == nil {
			continue
		}
		for _, edge := range node.Out {
			if edge == nil || edge.Site == nil || edge.Callee == nil || edge.Callee.Func == nil {
				continue
			}
			index.addTarget(edge.Site, edge.Callee.Func)
			if edge.Caller != nil && edge.Caller.Func != nil && edge.Caller.Func != edge.Callee.Func {
				index.edges = append(index.edges, auditCallEdge{caller: edge.Caller.Func, callee: edge.Callee.Func})
			}
		}
	}
	for _, function := range index.functions {
		for _, block := range function.Blocks {
			for _, instruction := range block.Instrs {
				call, ok := instruction.(ssa.CallInstruction)
				if !ok {
					continue
				}
				if static := call.Common().StaticCallee(); static != nil {
					index.addTarget(call, static)
				}
			}
		}
	}
	for _, targets := range index.targets {
		sortFunctionsByName(targets)
	}
	for _, function := range index.functions {
		for _, block := range function.Blocks {
			for _, instruction := range block.Instrs {
				call, ok := instruction.(ssa.CallInstruction)
				if !ok {
					continue
				}
				for _, target := range index.targets[call] {
					index.callSites[target] = append(index.callSites[target], auditCallSite{caller: function, call: call})
				}
			}
		}
	}
	return index
}

func (index *auditCallIndex) addTarget(call ssa.CallInstruction, target *ssa.Function) {
	for _, existing := range index.targets[call] {
		if existing == target {
			return
		}
	}
	index.targets[call] = append(index.targets[call], target)
}

func (a *auditActorAnalyzer) initialize() error {
	index, err := core.SharedLoad(a.project, auditCallIndexKey{}, func() (*auditCallIndex, error) {
		return buildAuditCallIndex(a.project.Program, a.project.FileSet), nil
	})
	if err != nil {
		return err
	}
	a.targets = index.targets
	a.sources = make(map[*ssa.Function]bool)
	for _, function := range index.functions {
		if a.sourcePackages[function.Package()] && a.sourceFiles[index.files[function]] {
			a.sources[function] = true
		}
	}
	sourceIncoming := make(map[*ssa.Function]bool)
	for _, edge := range index.edges {
		if a.isSourceFunction(edge.caller) && a.isSourceFunction(edge.callee) {
			sourceIncoming[edge.callee] = true
		}
	}
	for _, function := range index.functions {
		if a.isSourceFunction(function) {
			a.enqueue(auditState{
				function: function,
				actor:    newAuditTaintBits(auditFunctionTaintSize(function)),
				source:   newAuditTaintBits(auditFunctionTaintSize(function)),
			})
			if !sourceIncoming[function] || auditExportedFunction(function) {
				a.enqueue(a.rootState(function))
			}
		}
	}
	return a.validateSourceSinkCalls(index)
}

// sortFunctionsByName orders functions by their full name for a stable walk.
// The name is built once per function: ssa.Function.String formats the whole
// qualified signature, and building it in every comparison dominated the rule.
func sortFunctionsByName(functions []*ssa.Function) {
	if len(functions) < 2 {
		return
	}
	names := make(map[*ssa.Function]string, len(functions))
	for _, function := range functions {
		names[function] = function.String()
	}
	sort.Slice(functions, func(i, j int) bool { return names[functions[i]] < names[functions[j]] })
}

func auditExportedFunction(function *ssa.Function) bool {
	object := function.Object()
	return object != nil && object.Exported()
}

// isSourceFunction reports whether the function is declared in an analyzed
// file of a loaded package.
func (a *auditActorAnalyzer) isSourceFunction(function *ssa.Function) bool {
	return a.sources[function]
}

// validateSourceSinkCalls checks every call that may reach a sink declared in
// an analyzed file, from anywhere in the module.
func (a *auditActorAnalyzer) validateSourceSinkCalls(index *auditCallIndex) error {
	for _, target := range index.functions {
		if !a.rule.sinks[target.Name()] || !a.isSourceFunction(target) {
			continue
		}
		roles, inScope := auditRoles(target)
		if !inScope {
			continue
		}
		for _, site := range index.callSites[target] {
			actuals := auditCallActuals(site.call.Common())
			if len(actuals) != len(target.Params) || roles.actor >= len(actuals) || roles.source >= len(actuals) {
				return fmt.Errorf("malformed audit sink call to %s: got %d actuals for %d formal parameters", target, len(actuals), len(target.Params))
			}
			if _, _, err := a.sourcePosition(site.call.Pos()); err != nil {
				return fmt.Errorf("validate source sink call to %s from %s: %w", target, site.caller, err)
			}
		}
	}
	return nil
}

func (a *auditActorAnalyzer) rootState(function *ssa.Function) auditState {
	size := auditFunctionTaintSize(function)
	state := auditState{
		function: function,
		actor:    newAuditTaintBits(size),
		source:   newAuditTaintBits(size),
	}
	for index, parameter := range function.Params {
		if auditActorParameterNames[parameter.Name()] {
			state.actor.set(index)
			state.human = true
		}
		if auditSourceParameterNames[parameter.Name()] {
			state.source.set(index)
		}
	}
	return state
}

func auditFunctionTaintSize(function *ssa.Function) int {
	return len(function.Params) + len(function.FreeVars)
}

func (a *auditActorAnalyzer) enqueue(state auditState) {
	key := auditStateKey{
		function: state.function,
		actor:    state.actor.key(),
		source:   state.source.key(),
		human:    state.human,
	}
	if a.seen[key] {
		return
	}
	a.seen[key] = true
	a.worklist = append(a.worklist, state)
}

func (a *auditActorAnalyzer) run() error {
	for len(a.worklist) > 0 {
		state := a.worklist[0]
		a.worklist = a.worklist[1:]
		if err := a.analyzeFunction(state); err != nil {
			return err
		}
	}
	return nil
}

func (a *auditActorAnalyzer) analyzeFunction(state auditState) error {
	localHuman := state.human || a.hasHumanRoot(state.function)
	for _, block := range state.function.Blocks {
		for _, instruction := range block.Instrs {
			call, ok := instruction.(ssa.CallInstruction)
			if !ok {
				continue
			}
			for _, target := range a.targets[call] {
				if a.rule.sinks[target.Name()] && a.isSourceFunction(target) {
					if err := a.inspectSink(state, localHuman, call, target); err != nil {
						return err
					}
				}
				children, err := a.childStates(state, localHuman, call, target)
				if err != nil {
					return err
				}
				for _, child := range children {
					a.enqueue(child)
				}
			}
		}
	}
	return nil
}

func (a *auditActorAnalyzer) childStates(
	caller auditState,
	localHuman bool,
	call ssa.CallInstruction,
	target *ssa.Function,
) ([]auditState, error) {
	if target == nil || len(target.Blocks) == 0 {
		return []auditState{}, nil
	}
	actuals := auditCallActuals(call.Common())
	if len(actuals) != len(target.Params) {
		if a.isSourceFunction(target) {
			return nil, fmt.Errorf("map call to %s: got %d actuals for %d formal parameters", target, len(actuals), len(target.Params))
		}
		return []auditState{}, nil
	}

	base := auditState{
		function: target,
		actor:    newAuditTaintBits(auditFunctionTaintSize(target)),
		source:   newAuditTaintBits(auditFunctionTaintSize(target)),
	}
	for index, actual := range actuals {
		if auditValueDepends(actual, caller.function, caller.actor, auditTaintActor, make(map[ssa.Value]bool)) {
			base.actor.set(index)
		}
		if auditValueDepends(actual, caller.function, caller.source, auditTaintSource, make(map[ssa.Value]bool)) {
			base.source.set(index)
		}
	}
	base.human = auditChildHuman(call, localHuman, base.actor, len(target.Params))

	if len(target.FreeVars) == 0 {
		return []auditState{base}, nil
	}
	bindings := auditClosureBindings(call.Common().Value, target, make(map[ssa.Value]bool))
	if len(bindings) == 0 {
		return []auditState{}, nil
	}
	children := make([]auditState, 0, len(bindings))
	for _, closureBindings := range bindings {
		if len(closureBindings) != len(target.FreeVars) {
			return nil, fmt.Errorf("map closure call to %s: got %d bindings for %d free variables", target, len(closureBindings), len(target.FreeVars))
		}
		child := base
		child.actor = base.actor.clone()
		child.source = base.source.clone()
		for index, binding := range closureBindings {
			bit := len(target.Params) + index
			if auditValueDepends(binding, caller.function, caller.actor, auditTaintActor, make(map[ssa.Value]bool)) {
				child.actor.set(bit)
			}
			if auditValueDepends(binding, caller.function, caller.source, auditTaintSource, make(map[ssa.Value]bool)) {
				child.source.set(bit)
			}
		}
		child.human = auditChildHuman(call, localHuman, child.actor, len(target.Params))
		children = append(children, child)
	}
	return children, nil
}

func auditChildHuman(call ssa.CallInstruction, localHuman bool, actor auditTaintBits, formalCount int) bool {
	switch call.(type) {
	case *ssa.Go, *ssa.Defer:
		return actor.anyBefore(formalCount)
	default:
		return localHuman || actor.any()
	}
}

func auditCallActuals(common *ssa.CallCommon) []ssa.Value {
	if common.IsInvoke() {
		actuals := make([]ssa.Value, 0, len(common.Args)+1)
		actuals = append(actuals, common.Value)
		return append(actuals, common.Args...)
	}
	return common.Args
}

func auditClosureBindings(value ssa.Value, target *ssa.Function, visited map[ssa.Value]bool) [][]ssa.Value {
	if value == nil || visited[value] {
		return nil
	}
	visited[value] = true
	switch current := value.(type) {
	case *ssa.MakeClosure:
		if current.Fn == target {
			return [][]ssa.Value{current.Bindings}
		}
	case *ssa.Phi:
		var bindings [][]ssa.Value
		for _, edge := range current.Edges {
			bindings = append(bindings, auditClosureBindings(edge, target, visited)...)
		}
		return bindings
	case *ssa.ChangeType:
		return auditClosureBindings(current.X, target, visited)
	case *ssa.ChangeInterface:
		return auditClosureBindings(current.X, target, visited)
	case *ssa.Convert:
		return auditClosureBindings(current.X, target, visited)
	case *ssa.MakeInterface:
		return auditClosureBindings(current.X, target, visited)
	}
	return nil
}

type auditSinkRoles struct {
	actor  int
	source int
}

// auditRoles finds the actor and source parameters of a function named like a
// sink. Only a function with exactly one integer actor parameter and exactly
// one string source parameter is an audit sink; any other signature (a
// get-or-create keyed by userID, two actor parameters, wrong role types) merely
// shares the name and is skipped.
func auditRoles(target *ssa.Function) (auditSinkRoles, bool) {
	roles := auditSinkRoles{actor: -1, source: -1}
	actorCount := 0
	sourceCount := 0
	for index, parameter := range target.Params {
		if auditActorParameterNames[parameter.Name()] {
			roles.actor = index
			actorCount++
		}
		if auditSourceParameterNames[parameter.Name()] {
			roles.source = index
			sourceCount++
		}
	}
	if actorCount != 1 || sourceCount != 1 {
		return roles, false
	}
	if !auditActorRoleType(target.Params[roles.actor].Type()) || !auditSourceRoleType(target.Params[roles.source].Type()) {
		return roles, false
	}
	return roles, true
}

func auditActorRoleType(roleType types.Type) bool {
	underlying := types.Unalias(roleType).Underlying()
	if pointer, ok := underlying.(*types.Pointer); ok {
		underlying = types.Unalias(pointer.Elem()).Underlying()
	}
	basic, ok := underlying.(*types.Basic)
	return ok && basic.Info()&types.IsInteger != 0
}

func auditSourceRoleType(roleType types.Type) bool {
	basic, ok := types.Unalias(roleType).Underlying().(*types.Basic)
	return ok && basic.Info()&types.IsString != 0
}

func (a *auditActorAnalyzer) inspectSink(
	state auditState,
	human bool,
	call ssa.CallInstruction,
	target *ssa.Function,
) error {
	roles, inScope := auditRoles(target)
	if !inScope {
		return nil
	}
	actuals := auditCallActuals(call.Common())
	if len(actuals) != len(target.Params) || roles.actor >= len(actuals) || roles.source >= len(actuals) {
		return fmt.Errorf("malformed audit sink call to %s: got %d actuals for %d formal parameters", target, len(actuals), len(target.Params))
	}

	actorActual := actuals[roles.actor]
	sourceActual := actuals[roles.source]
	actorTainted := auditValueDepends(actorActual, state.function, state.actor, auditTaintActor, make(map[ssa.Value]bool))
	actorZero := auditLiteralZeroOrNil(actorActual)
	adminZero := auditAdminLiteral(sourceActual) && actorZero
	if (human && (!actorTainted || actorZero)) || adminZero {
		if err := a.report(state, human, call, target, "actor_loss", "human audit action reaches "+target.Name()+" without its actor"); err != nil {
			return err
		}
	}
	if state.source.any() && !auditValueDepends(sourceActual, state.function, state.source, auditTaintSource, make(map[ssa.Value]bool)) {
		if err := a.report(state, human, call, target, "source_loss", "audit source is replaced before "+target.Name()); err != nil {
			return err
		}
	}
	return nil
}

func (a *auditActorAnalyzer) report(
	state auditState,
	human bool,
	call ssa.CallInstruction,
	target *ssa.Function,
	pattern string,
	message string,
) error {
	position, file, err := a.sourcePosition(call.Pos())
	if err != nil {
		return fmt.Errorf("report %s at call to %s: %w", pattern, target, err)
	}
	key := auditFindingKey{
		file:    file.Path,
		line:    position.Line,
		column:  position.Column,
		sink:    target.Name(),
		pattern: pattern,
	}
	if a.reported[key] {
		return nil
	}
	a.reported[key] = true

	violation := a.rule.CreateViolation(file.Path, position.Line, message)
	violation.WithColumn(position.Column)
	violation.WithCode(file.GetLine(position.Line))
	violation.WithSuggestion("Forward the original audit actor and source through every synchronous wrapper")
	violation.WithContext("pattern", pattern)
	violation.WithContext("sink", target.Name())
	violation.WithContext("function", state.function.Name())
	violation.WithContext("human_action", human)
	a.violations = append(a.violations, violation)
	return nil
}

func (a *auditActorAnalyzer) sourcePosition(pos token.Pos) (token.Position, *core.FileContext, error) {
	if pos == token.NoPos {
		return token.Position{}, nil, errors.New("source sink call has no source position")
	}
	position := a.project.FileSet.PositionFor(pos, false)
	if !position.IsValid() || position.Filename == "" || position.Line <= 0 {
		return token.Position{}, nil, fmt.Errorf("source sink call position %d is invalid or unmappable", pos)
	}
	file, err := a.project.File(position.Filename)
	if err != nil {
		return token.Position{}, nil, fmt.Errorf("map valid source sink call position %s: %w", position, err)
	}
	return position, file, nil
}

type auditTaintKind uint8

const (
	auditTaintActor auditTaintKind = iota
	auditTaintSource
)

func auditValueDepends(
	value ssa.Value,
	function *ssa.Function,
	bits auditTaintBits,
	kind auditTaintKind,
	visited map[ssa.Value]bool,
) bool {
	if value == nil || visited[value] {
		return false
	}
	visited[value] = true

	switch current := value.(type) {
	case *ssa.Parameter:
		return current.Parent() == function && bits.has(auditParameterIndex(function, current))
	case *ssa.FreeVar:
		index := auditFreeVarIndex(function, current)
		return index >= 0 && bits.has(len(function.Params)+index)
	case *ssa.Field:
		return auditFieldDepends(current.X, current.Field, false, function, bits, kind, visited)
	case *ssa.FieldAddr:
		return auditFieldDepends(current.X, current.Field, true, function, bits, kind, visited)
	case *ssa.Index:
		return auditValueDepends(current.X, function, bits, kind, visited)
	case *ssa.IndexAddr:
		return auditValueDepends(current.X, function, bits, kind, visited)
	case *ssa.Alloc:
		return auditAllocDepends(current, function, bits, kind, visited)
	case *ssa.Call:
		return kind == auditTaintActor && auditHumanCallNames[auditCalledName(current.Common())]
	}
	if !auditTransitiveDependencyValue(value) {
		return false
	}
	node, ok := value.(ssa.Node)
	if !ok {
		return false
	}
	var operands [4]*ssa.Value
	for _, operand := range node.Operands(operands[:0]) {
		if operand != nil && auditValueDepends(*operand, function, bits, kind, visited) {
			return true
		}
	}
	return false
}

func auditFieldDepends(
	value ssa.Value,
	field int,
	address bool,
	function *ssa.Function,
	bits auditTaintBits,
	kind auditTaintKind,
	visited map[ssa.Value]bool,
) bool {
	name := auditFieldName(value.Type(), field, address)
	if kind == auditTaintActor && auditActorFieldName(name) {
		return true
	}
	if kind == auditTaintActor && name == "ID" && auditIntrinsicHumanValue(value, make(map[ssa.Value]bool)) {
		return true
	}
	return auditValueDepends(value, function, bits, kind, visited)
}

func auditAllocDepends(
	allocation *ssa.Alloc,
	function *ssa.Function,
	bits auditTaintBits,
	kind auditTaintKind,
	visited map[ssa.Value]bool,
) bool {
	if references := allocation.Referrers(); references != nil {
		for _, reference := range *references {
			store, ok := reference.(*ssa.Store)
			if ok && store.Addr == allocation && auditValueDepends(store.Val, function, bits, kind, visited) {
				return true
			}
		}
	}
	return false
}

func auditTransitiveDependencyValue(value ssa.Value) bool {
	switch value.(type) {
	case *ssa.Phi, *ssa.Convert, *ssa.ChangeType, *ssa.ChangeInterface, *ssa.Extract,
		*ssa.UnOp, *ssa.BinOp, *ssa.MakeInterface, *ssa.TypeAssert:
		return true
	default:
		return false
	}
}

func auditParameterIndex(function *ssa.Function, parameter *ssa.Parameter) int {
	for index, candidate := range function.Params {
		if candidate == parameter {
			return index
		}
	}
	return -1
}

func auditFreeVarIndex(function *ssa.Function, variable *ssa.FreeVar) int {
	for index, candidate := range function.FreeVars {
		if candidate == variable {
			return index
		}
	}
	return -1
}

// hasHumanRoot memoizes auditFunctionHasHumanRoot: a function is analyzed in
// many taint states.
func (a *auditActorAnalyzer) hasHumanRoot(function *ssa.Function) bool {
	human, done := a.humanRoots[function]
	if !done {
		human = auditFunctionHasHumanRoot(function)
		a.humanRoots[function] = human
	}
	return human
}

func auditFunctionHasHumanRoot(function *ssa.Function) bool {
	for _, block := range function.Blocks {
		for _, instruction := range block.Instrs {
			value, ok := instruction.(ssa.Value)
			if ok && auditIntrinsicHumanValue(value, make(map[ssa.Value]bool)) {
				return true
			}
		}
	}
	return false
}

func auditIntrinsicHumanValue(value ssa.Value, visited map[ssa.Value]bool) bool {
	if value == nil || visited[value] {
		return false
	}
	visited[value] = true
	switch current := value.(type) {
	case *ssa.Call:
		return auditHumanCallNames[auditCalledName(current.Common())]
	case *ssa.Extract:
		return auditIntrinsicHumanValue(current.Tuple, visited)
	case *ssa.Field:
		return auditActorFieldName(auditFieldName(current.X.Type(), current.Field, false)) ||
			auditIntrinsicHumanValue(current.X, visited)
	case *ssa.FieldAddr:
		return auditActorFieldName(auditFieldName(current.X.Type(), current.Field, true)) ||
			auditIntrinsicHumanValue(current.X, visited)
	case *ssa.UnOp:
		return auditIntrinsicHumanValue(current.X, visited)
	case *ssa.Convert:
		return auditIntrinsicHumanValue(current.X, visited)
	case *ssa.ChangeType:
		return auditIntrinsicHumanValue(current.X, visited)
	case *ssa.ChangeInterface:
		return auditIntrinsicHumanValue(current.X, visited)
	case *ssa.MakeInterface:
		return auditIntrinsicHumanValue(current.X, visited)
	case *ssa.Phi:
		for _, edge := range current.Edges {
			if auditIntrinsicHumanValue(edge, visited) {
				return true
			}
		}
	}
	return false
}

func auditActorFieldName(name string) bool {
	return auditActorFieldNames[name] || auditActorParameterNames[name]
}

func auditCalledName(common *ssa.CallCommon) string {
	if common == nil {
		return ""
	}
	if callee := common.StaticCallee(); callee != nil {
		return callee.Name()
	}
	if common.Method != nil {
		return common.Method.Name()
	}
	return ""
}

func auditFieldName(valueType types.Type, index int, address bool) string {
	typeValue := types.Unalias(valueType)
	if address {
		pointer, ok := typeValue.Underlying().(*types.Pointer)
		if !ok {
			return ""
		}
		typeValue = types.Unalias(pointer.Elem())
	}
	structure, ok := typeValue.Underlying().(*types.Struct)
	if !ok || index < 0 || index >= structure.NumFields() {
		return ""
	}
	return structure.Field(index).Name()
}

func auditLiteralZeroOrNil(value ssa.Value) bool {
	constantValue, ok := value.(*ssa.Const)
	if !ok {
		return false
	}
	if constantValue.IsNil() {
		return true
	}
	return constantValue.Value != nil && constant.Sign(constantValue.Value) == 0
}

func auditAdminLiteral(value ssa.Value) bool {
	constantValue, ok := value.(*ssa.Const)
	return ok && constantValue.Value != nil && constantValue.Value.Kind() == constant.String &&
		strings.HasPrefix(constant.StringVal(constantValue.Value), "admin")
}
