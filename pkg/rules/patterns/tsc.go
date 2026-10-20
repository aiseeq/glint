package patterns

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/toolcache"
)

func init() {
	rules.Register(NewTscRule())
}

// tscCache keeps tsc's answers between runs.
var tscCache = toolcache.New("tsc")

// standaloneTSOptions are the compiler options of a TS file no tsconfig
// compiles: a script run by node, type-checked as strictly as a project.
var standaloneTSOptions = []string{
	"--noEmit", "--strict", "--module", "nodenext", "--allowImportingTsExtensions",
	"--erasableSyntaxOnly", "--types", "node",
}

// strictFamily are the checks strict turns on; a tsconfig that sets strict
// and turns one of them off is not strict either.
var strictFamily = []string{
	"noImplicitAny", "noImplicitThis", "alwaysStrict", "strictBindCallApply",
	"strictFunctionTypes", "strictNullChecks", "strictPropertyInitialization",
	"useUnknownInCatchVariables", "strictBuiltinIteratorReturn",
}

// TscRule type-checks the TypeScript of the project with tsc. A file a
// tsconfig compiles is checked by that tsconfig with the project's own tsc
// (node_modules/.bin/tsc), a file no tsconfig compiles by the global tsc 7
// with strict defaults (standaloneTSOptions). Type errors are high, and so is
// a tsconfig that does not make tsc strict; a tsconfig that the project's
// tsc builds and tsc 7 does not is medium - the project has to move before
// it can take the new compiler.
//
// tsc reads every file of the program, so the rule is not file-local: it
// keeps tsc's answers in a cache of its own, keyed by the tsc versions, the
// effective configuration and the content of every file of the program.
type TscRule struct {
	*rules.BaseRule
	// global is the tsc 7 to run outside tsconfigs; tests point it elsewhere.
	global string

	files   []*core.FileContext
	plan    *tscPlan
	planErr error
	results func() map[string][]*core.Violation
}

// NewTscRule creates the tsc rule.
func NewTscRule() *TscRule {
	r := &TscRule{
		BaseRule: rules.NewBaseRule("tsc", "patterns",
			"Type-checks TypeScript with tsc: by its tsconfig with the project's tsc, or strictly with the global tsc 7 when no tsconfig compiles the file. Type errors and a tsconfig without strict are high, a tsconfig tsc 7 does not build is medium",
			core.SeverityHigh),
		global: "tsc",
	}
	r.ResetState()
	return r
}

// ReadsOtherFiles reports that the findings of a file depend on the files it
// imports and on its tsconfig.
func (r *TscRule) ReadsOtherFiles() bool { return true }

// ResetState forgets the previous root's plan and answers.
func (r *TscRule) ResetState() {
	r.files, r.plan, r.planErr = nil, nil, nil
	r.results = sync.OnceValue(r.check)
}

// tscProgram is one tsc run: a tsconfig, or one file no tsconfig compiles.
type tscProgram struct {
	config string // the tsconfig; empty for a standalone file
	file   string // the standalone file
	tsc    string // the tsc that checks it; empty when the project has none
	anchor string // the analyzed file that carries findings about the program itself
}

func (p *tscProgram) name() string {
	if p.config != "" {
		return p.config
	}
	return p.file
}

// tscPlan is what the root needs checked.
type tscPlan struct {
	programs   []*tscProgram
	standalone int
}

// UseProjectFiles decides which programs check the TypeScript of the root:
// every type-checked tsconfig (one a package.json script runs) that
// compiles a file of it, else the nearest tsconfig.json above the file that
// compiles it, else the file alone.
func (r *TscRule) UseProjectFiles(files []*core.FileContext) {
	r.ResetState()
	r.files = files
	r.plan, r.planErr = planTscPrograms(files)
}

func planTscPrograms(files []*core.FileContext) (*tscPlan, error) {
	plan := &tscPlan{}
	configs := map[string]*tscProgram{}
	analyzed := map[string]bool{}
	for _, ctx := range files {
		analyzed[ctx.Path] = true
	}
	scopes := map[string]tsconfigScope{}
	loadScope := func(path string) (tsconfigScope, error) {
		if scope, ok := scopes[path]; ok {
			return scope, nil
		}
		scope, err := loadTSConfigScope(path)
		if err != nil {
			return tsconfigScope{}, err
		}
		scopes[path] = scope
		return scope, nil
	}
	sorted := slicesSortedByRelPath(files)
	for _, ctx := range sorted {
		if !ctx.IsTypeScriptFile() || strings.HasSuffix(ctx.Path, ".d.ts") {
			continue
		}
		owners, err := tsconfigsOf(ctx, loadScope)
		if err != nil {
			return nil, err
		}
		if len(owners) == 0 {
			plan.programs = append(plan.programs, &tscProgram{file: ctx.Path, anchor: ctx.Path})
			plan.standalone++
			continue
		}
		for _, config := range owners {
			if configs[config] != nil {
				continue
			}
			anchor := ctx.Path
			if analyzed[config] {
				anchor = config
			}
			program := &tscProgram{config: config, tsc: projectTsc(filepath.Dir(config)), anchor: anchor}
			configs[config] = program
			plan.programs = append(plan.programs, program)
		}
	}
	return plan, nil
}

func slicesSortedByRelPath(files []*core.FileContext) []*core.FileContext {
	sorted := append([]*core.FileContext(nil), files...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].RelPath < sorted[j].RelPath })
	return sorted
}

// tsconfigsOf returns the tsconfigs that compile a TS file: the
// type-checked ones of the project, else the nearest tsconfig.json above it
// that takes it, as an editor picks one.
func tsconfigsOf(ctx *core.FileContext, loadScope func(string) (tsconfigScope, error)) ([]string, error) {
	checked, err := projectCheckedTSConfigs(ctx.ProjectRoot)
	if err != nil {
		return nil, err
	}
	var owners []string
	for _, scope := range checked {
		covered, err := scope.covers(ctx.Path)
		if err != nil {
			return nil, err
		}
		if covered {
			owners = append(owners, scope.path)
		}
	}
	if len(owners) > 0 {
		return owners, nil
	}
	for dir := filepath.Dir(ctx.Path); ; dir = filepath.Dir(dir) {
		config := filepath.Join(dir, "tsconfig.json")
		_, err := os.Stat(config)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("stat %s: %w", config, err)
		}
		if err == nil {
			scope, err := loadScope(config)
			if err != nil {
				return nil, err
			}
			covered, err := scope.covers(ctx.Path)
			if err != nil {
				return nil, err
			}
			if covered {
				return []string{config}, nil
			}
		}
		if dir == ctx.ProjectRoot || dir == filepath.Dir(dir) {
			return nil, nil
		}
	}
}

// projectTsc returns the tsc the package above dir installs, or "" when no
// node_modules above it has one.
func projectTsc(dir string) string {
	for ; ; dir = filepath.Dir(dir) {
		tsc := filepath.Join(dir, "node_modules", ".bin", "tsc")
		if info, err := os.Stat(tsc); err == nil && !info.IsDir() {
			return tsc
		}
		if dir == filepath.Dir(dir) {
			return ""
		}
	}
}

// CheckTools fails when the root holds TypeScript and a tsc it needs is
// missing: the project's own for a tsconfig, the global tsc 7 (and its
// @types/node for a file outside tsconfigs).
func (r *TscRule) CheckTools(files []*core.FileContext) error {
	hasTS := false
	for _, ctx := range files {
		hasTS = hasTS || ctx.IsTypeScriptFile()
	}
	if !hasTS {
		return nil
	}
	if r.plan == nil && r.planErr == nil {
		return errors.New("the TypeScript files were not planned: the rule was not given the project files")
	}
	if r.planErr != nil {
		return nil // reported on the files
	}
	var missing []string
	for _, program := range r.plan.programs {
		if program.config != "" && program.tsc == "" {
			missing = append(missing, program.config)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("%d tsconfigs have no tsc of their project (node_modules/.bin/tsc), install the project's packages (npm ci): %s", len(missing), strings.Join(missing, ", "))
	}
	global, err := r.globalTsc()
	if err != nil {
		return err
	}
	if r.plan.standalone > 0 {
		if _, err := os.Stat(filepath.Join(global.typeRoots, "node", "package.json")); err != nil {
			return fmt.Errorf("%d TS files outside every tsconfig are checked with the types of node, which are not installed next to the global tsc (npm i -g @types/node): %w", r.plan.standalone, err)
		}
	}
	return nil
}

// globalTscInfo is the global tsc 7: the program, its version and the
// @types directory of the global packages.
type globalTscInfo struct {
	path, version, typeRoots string
}

var tscVersion = regexp.MustCompile(`Version (\d+)\.`)

// globalTsc finds the global tsc and checks it is tsc 7.
func (r *TscRule) globalTsc() (globalTscInfo, error) {
	path, err := exec.LookPath(r.global)
	if err != nil {
		return globalTscInfo{}, fmt.Errorf("TypeScript needs the global tsc 7, which is not installed (npm i -g typescript@7): %w", err)
	}
	version, err := toolVersion(path)
	if err != nil {
		return globalTscInfo{}, err
	}
	if m := tscVersion.FindStringSubmatch(version); m == nil || m[1] != "7" {
		return globalTscInfo{}, fmt.Errorf("the global tsc %s is %q, the rule needs tsc 7 (npm i -g typescript@7)", path, strings.TrimSpace(version))
	}
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return globalTscInfo{}, fmt.Errorf("resolve the global tsc: %w", err)
	}
	// <prefix>/lib/node_modules/typescript/bin/tsc: the types are beside typescript.
	modules := filepath.Dir(filepath.Dir(filepath.Dir(real)))
	if filepath.Base(modules) != "node_modules" {
		return globalTscInfo{}, fmt.Errorf("the global tsc %s is not inside a node_modules directory, so its @types cannot be found", real)
	}
	return globalTscInfo{path: path, version: version, typeRoots: filepath.Join(modules, "@types")}, nil
}

var (
	toolVersionsMu sync.Mutex
	toolVersions   = map[string]string{}
)

// toolVersion returns what program --version prints, asked once per program.
func toolVersion(program string) (string, error) {
	toolVersionsMu.Lock()
	defer toolVersionsMu.Unlock()
	if version, ok := toolVersions[program]; ok {
		return version, nil
	}
	out, err := exec.Command(program, "--version").Output()
	if err != nil {
		return "", fmt.Errorf("%s --version: %w", program, err)
	}
	toolVersions[program] = string(out)
	return string(out), nil
}

// AnalyzeFile reports what tsc found in the file, and on a tsconfig (or the
// first file of a program whose tsconfig is not analyzed) what is wrong with
// the program itself.
func (r *TscRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsTypeScriptFile() && !ctx.IsTSConfig() {
		return nil
	}
	if r.planErr != nil {
		v := r.CreateViolation(ctx.RelPath, 1, "The tsconfigs of the project cannot be read, so tsc checked nothing: "+r.planErr.Error())
		return []*core.Violation{v.WithSuggestion("Fix the tsconfig or package.json the error names")}
	}
	if r.plan == nil {
		return nil
	}
	return r.results()[ctx.Path]
}

// tscDiagnostic is one error tsc reports; File is empty for an error of the
// program as a whole.
type tscDiagnostic struct {
	File    string `json:"file,omitempty"`
	Line    int    `json:"line,omitempty"`
	Column  int    `json:"column,omitempty"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (d tscDiagnostic) place() string {
	return fmt.Sprintf("%s:%d:%s", d.File, d.Line, d.Code)
}

func (d tscDiagnostic) String() string {
	if d.File == "" {
		return d.Code + ": " + d.Message
	}
	return fmt.Sprintf("%s(%d,%d): %s: %s", d.File, d.Line, d.Column, d.Code, d.Message)
}

// tscAnswer is what the tsc runs of one program found.
type tscAnswer struct {
	Errors    []tscDiagnostic `json:"errors"`
	NotStrict []string        `json:"notStrict,omitempty"` // why the tsconfig is not strict
	// TSC7 are the errors tsc 7 reports on the tsconfig that the project's
	// tsc does not.
	TSC7 []tscDiagnostic `json:"tsc7,omitempty"`
}

// check runs every program, as many at a time as the run has threads, and
// returns the findings by file.
func (r *TscRule) check() map[string][]*core.Violation {
	answers := make([]tscAnswer, len(r.plan.programs))
	failures := make([]error, len(r.plan.programs))
	global, globalErr := r.globalTsc()
	slots := make(chan struct{}, runtime.GOMAXPROCS(0))
	var wg sync.WaitGroup
	for i, program := range r.plan.programs {
		if globalErr != nil {
			failures[i] = globalErr
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			slots <- struct{}{}
			defer func() { <-slots }()
			answers[i], failures[i] = runTscProgram(program, global)
		}()
	}
	wg.Wait()

	byPath := map[string]*core.FileContext{}
	for _, ctx := range r.files {
		byPath[ctx.Path] = ctx
	}
	found := map[string][]*core.Violation{}
	seen := map[string]bool{}
	for i, program := range r.plan.programs {
		anchor := byPath[program.anchor]
		if failures[i] != nil {
			v := r.CreateViolation(anchor.RelPath, 1, fmt.Sprintf("tsc could not check %s, so nothing it compiles was checked: %v", relTo(anchor.ProjectRoot, program.name()), failures[i]))
			found[anchor.Path] = append(found[anchor.Path], v.WithSuggestion("Fix what the error names: the tsconfig, the installed packages or tsc"))
			continue
		}
		answer := answers[i]
		var elsewhere []tscDiagnostic
		for _, d := range answer.Errors {
			ctx := byPath[d.File]
			if ctx == nil {
				elsewhere = append(elsewhere, d)
				continue
			}
			key := d.String()
			if seen[key] {
				continue // two programs compile the file
			}
			seen[key] = true
			suggestion := "Fix the type error; tsc reports it for " + relTo(ctx.ProjectRoot, program.config)
			if program.config == "" {
				suggestion = "Fix the type error; no tsconfig compiles the file, so tsc 7 checks it alone, strictly, as a node script"
			}
			v := r.CreateViolation(ctx.RelPath, d.Line, d.Code+": "+d.Message).
				WithColumn(d.Column).
				WithCode(ctx.GetLine(d.Line)).
				WithSuggestion(suggestion)
			found[ctx.Path] = append(found[ctx.Path], v)
		}
		if len(elsewhere) > 0 {
			v := r.CreateViolation(anchor.RelPath, 1, fmt.Sprintf("tsc reports %d errors of %s outside the files glint analyzes: %s", len(elsewhere), relTo(anchor.ProjectRoot, program.name()), firstDiagnostics(anchor.ProjectRoot, elsewhere)))
			found[anchor.Path] = append(found[anchor.Path], v.WithSuggestion("Fix the errors, or take the files out of the tsconfig"))
		}
		if len(answer.NotStrict) > 0 {
			v := r.CreateViolation(anchor.RelPath, 1, fmt.Sprintf("%s does not make tsc strict (%s): the type errors strict mode finds are not checked", relTo(anchor.ProjectRoot, program.config), strings.Join(answer.NotStrict, ", ")))
			found[anchor.Path] = append(found[anchor.Path], v.WithSuggestion(`Set "strict": true in compilerOptions and fix what tsc then reports`))
		}
		if len(answer.TSC7) > 0 {
			v := r.CreateViolation(anchor.RelPath, 1, fmt.Sprintf("tsc 7 does not build %s, which the project's tsc builds: %d errors, %s", relTo(anchor.ProjectRoot, program.config), len(answer.TSC7), firstDiagnostics(anchor.ProjectRoot, answer.TSC7)))
			v.Severity = core.SeverityMedium
			found[anchor.Path] = append(found[anchor.Path], v.WithSuggestion("Move the tsconfig and the code to what tsc 7 accepts (removed options such as baseUrl, types no longer defaulting to every @types package), then upgrade the project's typescript"))
		}
	}
	return found
}

// firstDiagnostics names the first three errors.
func firstDiagnostics(root string, diagnostics []tscDiagnostic) string {
	parts := make([]string, 0, 3)
	for _, d := range diagnostics[:min(3, len(diagnostics))] {
		if d.File != "" {
			d.File = relTo(root, d.File)
		}
		parts = append(parts, d.String())
	}
	more := ""
	if len(diagnostics) > 3 {
		more = "; …"
	}
	return strings.Join(parts, "; ") + more
}

// relTo names a path under root relative to it; a path outside the root
// (a package installed above it) stays absolute.
func relTo(root, path string) string {
	return strings.TrimPrefix(path, root+string(filepath.Separator))
}

// runTscProgram checks one program, from the cache when nothing tsc reads
// has changed.
func runTscProgram(program *tscProgram, global globalTscInfo) (tscAnswer, error) {
	if program.config == "" {
		return runStandalone(program.file, global)
	}
	dir := filepath.Dir(program.config)
	version, err := toolVersion(program.tsc)
	if err != nil {
		return tscAnswer{}, err
	}
	project := []string{"-p", program.config}
	shown, err := tscOutput(program.tsc, dir, append(project, "--showConfig")...)
	if err != nil {
		return tscAnswer{}, err
	}
	notStrict, err := strictGaps(shown)
	if err != nil {
		return tscAnswer{}, fmt.Errorf("read tsc --showConfig of %s: %w", program.config, err)
	}
	listed, err := tscOutput(program.tsc, dir, append(project, "--listFilesOnly")...)
	if err != nil {
		return tscAnswer{}, err
	}
	key, err := programKey([]string{version, global.version, string(shown)}, listed)
	if err != nil {
		return tscAnswer{}, err
	}
	var answer tscAnswer
	hit, err := tscCache.Load(key, &answer)
	if err != nil {
		return tscAnswer{}, err
	}
	if hit {
		return answer, nil
	}
	// --incremental false: tsc would write a .tsbuildinfo into the project.
	run := append(project, "--noEmit", "--incremental", "false", "--pretty", "false")
	answer.Errors, err = tscDiagnostics(program.tsc, dir, run...)
	if err != nil {
		return tscAnswer{}, err
	}
	answer.NotStrict = notStrict
	newer, err := tscDiagnostics(global.path, dir, run...)
	if err != nil {
		return tscAnswer{}, fmt.Errorf("tsc 7: %w", err)
	}
	// tsc 7 words some messages differently: the same error is the same
	// code at the same place.
	known := map[string]bool{}
	for _, d := range answer.Errors {
		known[d.place()] = true
	}
	for _, d := range newer {
		if !known[d.place()] {
			answer.TSC7 = append(answer.TSC7, d)
		}
	}
	if err := tscCache.Store(key, answer); err != nil {
		return tscAnswer{}, err
	}
	return answer, nil
}

// runStandalone checks a TS file no tsconfig compiles with the global tsc 7.
func runStandalone(file string, global globalTscInfo) (tscAnswer, error) {
	dir := filepath.Dir(file)
	// --ignoreConfig: a tsconfig.json in dir that does not compile the file
	// is not its configuration.
	args := append(append([]string{}, standaloneTSOptions...), "--typeRoots", global.typeRoots, "--ignoreConfig")
	listed, err := tscOutput(global.path, dir, append(append([]string{}, args...), "--listFilesOnly", file)...)
	if err != nil {
		return tscAnswer{}, err
	}
	key, err := programKey(append([]string{global.version}, args...), listed)
	if err != nil {
		return tscAnswer{}, err
	}
	var answer tscAnswer
	hit, err := tscCache.Load(key, &answer)
	if err != nil {
		return tscAnswer{}, err
	}
	if hit {
		return answer, nil
	}
	answer.Errors, err = tscDiagnostics(global.path, dir, append(args, "--pretty", "false", file)...)
	if err != nil {
		return tscAnswer{}, err
	}
	if err := tscCache.Store(key, answer); err != nil {
		return tscAnswer{}, err
	}
	return answer, nil
}

// programKey names a program's input: the settings, and every file tsc
// lists with its content.
func programKey(settings []string, listed []byte) (string, error) {
	parts := make([][]byte, 0, len(settings)+64)
	for _, s := range settings {
		parts = append(parts, []byte(s))
	}
	scanner := bufio.NewScanner(bytes.NewReader(listed))
	for scanner.Scan() {
		path := strings.TrimSpace(scanner.Text())
		if path == "" {
			continue
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("read a file of the program: %w", err)
		}
		parts = append(parts, []byte(path), content)
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return toolcache.Key(parts...), nil
}

// tscOutput runs tsc for its output (--showConfig, --listFilesOnly), which
// must succeed.
func tscOutput(tsc, dir string, args ...string) ([]byte, error) {
	cmd := exec.Command(tsc, args...)
	cmd.Dir = dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s %s: %w: %s", tsc, strings.Join(args, " "), err, headOf(stdout.String()+stderr.String()))
	}
	return stdout.Bytes(), nil
}

var (
	tscFileDiagnostic   = regexp.MustCompile(`^(.+)\((\d+),(\d+)\): error (TS\d+): (.*)$`)
	tscGlobalDiagnostic = regexp.MustCompile(`^error (TS\d+): (.*)$`)
)

// tscDiagnostics runs a type check and returns its errors; tsc failing
// without reporting one is an error of the run.
func tscDiagnostics(tsc, dir string, args ...string) ([]tscDiagnostic, error) {
	cmd := exec.Command(tsc, args...)
	cmd.Dir = dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	runErr := cmd.Run()
	var exit *exec.ExitError
	if runErr != nil && !errors.As(runErr, &exit) {
		return nil, fmt.Errorf("run %s: %w", tsc, runErr)
	}
	diagnostics := []tscDiagnostic{}
	continued := map[int][]string{} // diagnostic → the lines continuing its message
	for _, line := range strings.Split(stdout.String(), "\n") {
		line = strings.TrimRight(line, "\r")
		if m := tscFileDiagnostic.FindStringSubmatch(line); m != nil {
			file := m[1]
			if !filepath.IsAbs(file) {
				file = filepath.Join(dir, file)
			}
			lineNo, lerr := strconv.Atoi(m[2])
			column, cerr := strconv.Atoi(m[3])
			if err := errors.Join(lerr, cerr); err != nil {
				return nil, fmt.Errorf("read tsc output %q: %w", line, err)
			}
			diagnostics = append(diagnostics, tscDiagnostic{File: file, Line: lineNo, Column: column, Code: m[4], Message: m[5]})
			continue
		}
		if m := tscGlobalDiagnostic.FindStringSubmatch(line); m != nil {
			diagnostics = append(diagnostics, tscDiagnostic{Code: m[1], Message: m[2]})
			continue
		}
		// An indented line continues the message of the error above it.
		if strings.HasPrefix(line, "  ") && len(diagnostics) > 0 {
			last := len(diagnostics) - 1
			continued[last] = append(continued[last], strings.TrimSpace(line))
		}
	}
	for i, lines := range continued {
		diagnostics[i].Message = strings.Join(append([]string{diagnostics[i].Message}, lines...), " ")
	}
	if runErr != nil && len(diagnostics) == 0 {
		return nil, fmt.Errorf("%s failed without reporting an error: %w: %s", tsc, runErr, headOf(stdout.String()+stderr.String()))
	}
	return diagnostics, nil
}

func headOf(s string) string {
	s = strings.TrimSpace(s)
	if r := []rune(s); len(r) > 500 {
		return string(r[:500]) + "…"
	}
	return s
}

// strictGaps reads tsc --showConfig and names what keeps the configuration
// from being strict: strict not set, or one of its checks turned off.
func strictGaps(shown []byte) ([]string, error) {
	var config struct {
		CompilerOptions map[string]any `json:"compilerOptions"`
	}
	if err := json.Unmarshal(shown, &config); err != nil {
		return nil, err
	}
	var gaps []string
	if strict, _ := config.CompilerOptions["strict"].(bool); !strict {
		gaps = append(gaps, "strict is not set")
	}
	for _, option := range strictFamily {
		if on, set := config.CompilerOptions[option].(bool); set && !on {
			gaps = append(gaps, option+" is false")
		}
	}
	return gaps, nil
}
