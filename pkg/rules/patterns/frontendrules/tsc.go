package frontendrules

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

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
	r.reset()
	return r
}

// ReadsOtherFiles reports that the findings of a file depend on the files it
// imports and on its tsconfig.
func (r *TscRule) ReadsOtherFiles() bool { return true }

// reset forgets the previous run's plan and answers.
func (r *TscRule) reset() {
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

// CheckTools decides which programs check the TypeScript of the run: every
// type-checked tsconfig (one a package.json script runs) that compiles a
// file of it, else the nearest tsconfig.json above the file that compiles
// it, else the file alone. It fails when a tsc a program needs is missing:
// the project's own for a tsconfig, the global tsc 7 (and its @types/node
// for a file outside tsconfigs).
func (r *TscRule) CheckTools(files []*core.FileContext) error {
	r.reset()
	r.files = files
	r.plan, r.planErr = planTscPrograms(files)
	hasTS := false
	for _, ctx := range files {
		hasTS = hasTS || ctx.IsTypeScriptFile()
	}
	if !hasTS {
		return nil
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
	global, err := r.globalTscBase()
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

func globalTscVersion(info globalTscInfo) (globalTscInfo, error) {
	version, err := toolVersion(info.path)
	if err != nil {
		return globalTscInfo{}, err
	}
	if m := tscVersion.FindStringSubmatch(version); m == nil || m[1] != "7" {
		return globalTscInfo{}, fmt.Errorf("the global tsc %s is %q, the rule needs tsc 7 (npm i -g typescript@7)", info.path, strings.TrimSpace(version))
	}
	info.version = version
	return info, nil
}

func (r *TscRule) globalTscBase() (globalTscInfo, error) {
	path, err := exec.LookPath(r.global)
	if err != nil {
		return globalTscInfo{}, fmt.Errorf("TypeScript needs the global tsc 7, which is not installed (npm i -g typescript@7): %w", err)
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
	return globalTscInfo{path: path, typeRoots: filepath.Join(modules, "@types")}, nil
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

func (d tscDiagnostic) place() tscPlace {
	return tscPlace{file: d.File, line: d.Line, code: d.Code}
}

// tscPlace is the code of a diagnostic at its place.
type tscPlace struct {
	file string
	line int
	code string
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
	global, globalErr := r.globalTscBase()
	slots := make(chan struct{}, runtime.GOMAXPROCS(0))
	var wg sync.WaitGroup
	for i, program := range r.plan.programs {
		if globalErr != nil {
			failures[i] = globalErr
			continue
		}
		wg.Go(func() {
			slots <- struct{}{}
			defer func() { <-slots }()
			answers[i], failures[i] = runTscProgram(program, global)
		})
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
	project := []string{"-p", program.config}
	run := append(append([]string{}, project...), "--noEmit", "--incremental", "--pretty", "false", "--listFiles")
	identity := append([]string{program.config, program.tsc, global.path}, project...)
	identity = append(identity, "--showConfig")
	identity = append(identity, run...)
	lookup, err := statCachedAnswer(identity, []string{program.tsc, global.path})
	if err != nil {
		return tscAnswer{}, err
	}
	if lookup.status == tscStatHit {
		return lookup.answer, nil
	}
	slowStarted := time.Now()
	shown, err := tscOutput(program.tsc, dir, append(project, "--showConfig")...)
	if err != nil {
		return tscAnswer{}, err
	}
	notStrict, err := strictGaps(shown)
	if err != nil {
		return tscAnswer{}, fmt.Errorf("read tsc --showConfig of %s: %w", program.config, err)
	}
	global, err = globalTscVersion(global)
	if err != nil {
		return tscAnswer{}, err
	}
	answer := tscAnswer{NotStrict: notStrict}
	var listed []byte
	answer.Errors, listed, err = incrementalTscDiagnostics(program.tsc, dir, program.config, run...)
	if err != nil {
		return tscAnswer{}, err
	}
	newer, _, err := incrementalTscDiagnostics(global.path, dir, program.config, run...)
	if err != nil {
		return tscAnswer{}, fmt.Errorf("tsc 7: %w", err)
	}
	// tsc 7 words some messages differently: the same error is the same
	// code at the same place.
	known := map[tscPlace]bool{}
	for _, d := range answer.Errors {
		known[d.place()] = true
	}
	for _, d := range newer {
		if !known[d.place()] {
			answer.TSC7 = append(answer.TSC7, d)
		}
	}
	if err := storeProjectStatFingerprintIfStable(identity, []string{program.tsc, global.path}, program.config, listed, answer, slowStarted); err != nil {
		return tscAnswer{}, err
	}
	return answer, nil
}

func incrementalTscDiagnostics(tsc, dir, config string, args ...string) ([]tscDiagnostic, []byte, error) {
	cacheDir, err := tscCache.Dir()
	if err != nil {
		return nil, nil, fmt.Errorf("locate the tsc build info cache: %w", err)
	}
	config, err = filepath.Abs(config)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve tsconfig path: %w", err)
	}
	tsc, err = filepath.Abs(tsc)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve tsc path: %w", err)
	}
	identity := toolcache.Key([]byte(config), []byte(tsc))
	buildInfo := filepath.Join(cacheDir, identity+".tsbuildinfo")
	return runWithBuildInfo(tsc, dir, args, buildInfo)
}

func runWithBuildInfo(tsc, dir string, args []string, buildInfo string) ([]tscDiagnostic, []byte, error) {
	data, readErr := os.ReadFile(buildInfo)
	if readErr != nil && !errors.Is(readErr, fs.ErrNotExist) {
		return nil, nil, fmt.Errorf("read tsc build info %s: %w", buildInfo, readErr)
	}
	usePrevious := readErr == nil
	result, listed, temp, err := runTscWithTempBuildInfo(tsc, dir, args, buildInfo, data, usePrevious)
	if err != nil && usePrevious {
		slog.Warn("tsc could not use build info; rerunning from scratch", "path", buildInfo, "error", err)
		if removeErr := removeTempBuildInfo(temp); removeErr != nil {
			return nil, nil, errors.Join(err, removeErr)
		}
		result, listed, temp, err = runTscWithTempBuildInfo(tsc, dir, args, buildInfo, nil, false)
	}
	if err != nil {
		return nil, nil, errors.Join(err, removeTempBuildInfo(temp))
	}
	if err := os.Rename(temp, buildInfo); err != nil {
		return nil, nil, errors.Join(fmt.Errorf("install tsc build info %s: %w", buildInfo, err), removeTempBuildInfo(temp))
	}
	return result, listed, nil
}

func runTscWithTempBuildInfo(tsc, dir string, args []string, buildInfo string, previous []byte, usePrevious bool) ([]tscDiagnostic, []byte, string, error) {
	tmp, err := os.CreateTemp(filepath.Dir(buildInfo), ".tsc-build-info-*.tsbuildinfo")
	if err != nil {
		return nil, nil, "", fmt.Errorf("create temporary tsc build info: %w", err)
	}
	temp := tmp.Name()
	if err := tmp.Close(); err != nil {
		return nil, nil, "", errors.Join(fmt.Errorf("close temporary tsc build info: %w", err), removeTempBuildInfo(temp))
	}
	if err := removeTempBuildInfo(temp); err != nil {
		return nil, nil, temp, err
	}
	if usePrevious {
		if err := os.WriteFile(temp, previous, 0o600); err != nil {
			return nil, nil, temp, fmt.Errorf("copy tsc build info: %w", err)
		}
	}
	args = append(append([]string{}, args...), "--tsBuildInfoFile", temp)
	diagnostics, listed, err := tscDiagnosticsWithFiles(tsc, dir, args...)
	if err != nil {
		return nil, nil, temp, err
	}
	return diagnostics, listed, temp, nil
}

func removeTempBuildInfo(path string) error {
	if path == "" {
		return nil
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove temporary tsc build info %s: %w", path, err)
	}
	return nil
}

// runStandalone checks a TS file no tsconfig compiles with the global tsc 7.
func runStandalone(file string, global globalTscInfo) (tscAnswer, error) {
	dir := filepath.Dir(file)
	// --ignoreConfig: a tsconfig.json in dir that does not compile the file
	// is not its configuration.
	args := append(append([]string{}, standaloneTSOptions...), "--typeRoots", global.typeRoots, "--ignoreConfig")
	identity := append([]string{file, global.path}, args...)
	identity = append(identity, "--listFilesOnly", file, "--pretty", "false", file)
	lookup, err := statCachedAnswer(identity, []string{global.path})
	if err != nil {
		return tscAnswer{}, err
	}
	if lookup.status == tscStatHit {
		return lookup.answer, nil
	}
	slowStarted := time.Now()
	listed, err := tscOutput(global.path, dir, append(append([]string{}, args...), "--listFilesOnly", file)...)
	if err != nil {
		return tscAnswer{}, err
	}
	global, err = globalTscVersion(global)
	if err != nil {
		return tscAnswer{}, err
	}
	before, err := makeStatFingerprint([]string{global.path}, "", listed, "", global.typeRoots)
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
		if err := storeStatFingerprintIfStable(identity, []string{global.path}, "", listed, before, key, slowStarted, global.typeRoots); err != nil {
			return tscAnswer{}, err
		}
		return answer, nil
	}
	answer.Errors, err = tscDiagnostics(global.path, dir, append(args, "--pretty", "false", file)...)
	if err != nil {
		return tscAnswer{}, err
	}
	if err := tscCache.Store(key, answer); err != nil {
		return tscAnswer{}, err
	}
	if err := storeStatFingerprintIfStable(identity, []string{global.path}, "", listed, before, key, slowStarted, global.typeRoots); err != nil {
		return tscAnswer{}, err
	}
	return answer, nil
}

type tscFileStat struct {
	Path      string `json:"path"`
	Size      int64  `json:"size"`
	ModTimeNS int64  `json:"mtimeNs"`
}

type tscStatFingerprint struct {
	AnswerKey string        `json:"answerKey"`
	Answer    *tscAnswer    `json:"answer,omitempty"`
	Files     []tscFileStat `json:"files"`
	Dirs      []tscFileStat `json:"dirs"`
}

func statFingerprintKey(identity []string) string {
	parts := make([][]byte, len(identity))
	for i, part := range identity {
		parts[i] = []byte(part)
	}
	return "stat-" + toolcache.Key(parts...)
}

func statPath(path string) (tscFileStat, error) {
	info, err := os.Stat(path)
	if err != nil {
		return tscFileStat{}, fmt.Errorf("stat %s: %w", path, err)
	}
	return tscFileStat{Path: path, Size: info.Size(), ModTimeNS: info.ModTime().UnixNano()}, nil
}

func makeStatFingerprint(tscPaths []string, config string, listed []byte, answerKey string, watchedDirs ...string) (tscStatFingerprint, error) {
	fingerprint := tscStatFingerprint{AnswerKey: answerKey}
	files := map[string]bool{}
	directories := map[string]bool{}
	for _, path := range tscPaths {
		files[path] = true
	}
	scanner := bufio.NewScanner(bytes.NewReader(listed))
	for scanner.Scan() {
		path := strings.TrimSpace(scanner.Text())
		if path != "" {
			files[path] = true
		}
	}
	if err := scanner.Err(); err != nil {
		return tscStatFingerprint{}, fmt.Errorf("read the file list of tsc: %w", err)
	}
	root := ""
	if config != "" {
		configs, err := tsconfigChain(config)
		if err != nil {
			return tscStatFingerprint{}, err
		}
		for _, path := range configs {
			files[path] = true
		}
		root = filepath.Dir(config)
	}
	filePaths := make([]string, 0, len(files))
	for path := range files {
		filePaths = append(filePaths, path)
	}
	sort.Strings(filePaths)
	for _, path := range filePaths {
		stamp, err := statPath(path)
		if err != nil {
			return tscStatFingerprint{}, fmt.Errorf("stat a tsc input %s: %w", path, err)
		}
		fingerprint.Files = append(fingerprint.Files, stamp)
		addFingerprintDirs(filepath.Dir(path), root, directories)
	}
	for _, path := range watchedDirs {
		addFingerprintDirs(path, "", directories)
	}
	dirs := make([]string, 0, len(directories))
	for path := range directories {
		dirs = append(dirs, path)
	}
	sort.Strings(dirs)
	for _, path := range dirs {
		stamp, err := statPath(path)
		if err != nil {
			return tscStatFingerprint{}, fmt.Errorf("stat a tsc input directory %s: %w", path, err)
		}
		fingerprint.Dirs = append(fingerprint.Dirs, stamp)
	}
	return fingerprint, nil
}

func addFingerprintDirs(dir, root string, directories map[string]bool) {
	dir = filepath.Clean(dir)
	bound := dir
	if root != "" && core.WithinPath(dir, root) {
		bound = filepath.Clean(root)
	} else {
		for current := dir; ; current = filepath.Dir(current) {
			if filepath.Base(current) == "node_modules" {
				bound = current
			}
			if filepath.Dir(current) == current {
				break
			}
		}
	}
	for current := dir; ; current = filepath.Dir(current) {
		directories[current] = true
		if current == bound || filepath.Dir(current) == current {
			break
		}
	}
}

type tscStatLookup struct {
	answer tscAnswer
	status tscStatStatus
}

type tscStatStatus uint8

const (
	tscStatMiss tscStatStatus = iota
	tscStatStale
	tscStatHit
)

func statCachedAnswer(identity, tscPaths []string) (tscStatLookup, error) {
	var fingerprint tscStatFingerprint
	found, err := tscCache.Load(statFingerprintKey(identity), &fingerprint)
	if err != nil {
		return tscStatLookup{}, err
	}
	if !found {
		return tscStatLookup{status: tscStatMiss}, nil
	}
	stale := false
	for _, saved := range append(append([]tscFileStat{}, fingerprint.Files...), fingerprint.Dirs...) {
		current, err := statPath(saved.Path)
		if err != nil { //nolint:silent-error-handling // A stat failure invalidates the fingerprint and the slow path rechecks the input.
			// A stat failure invalidates the optimization; the slow path reports or rechecks it.
			stale = true
			break
		}
		if current.Size != saved.Size || current.ModTimeNS != saved.ModTimeNS {
			stale = true
			break
		}
	}
	if stale {
		for _, executable := range tscPaths {
			for _, saved := range fingerprint.Files {
				if saved.Path == executable {
					forgetToolVersion(executable)
					break
				}
			}
		}
		return tscStatLookup{status: tscStatStale}, nil
	}
	if fingerprint.Answer != nil {
		return tscStatLookup{answer: *fingerprint.Answer, status: tscStatHit}, nil
	}
	var answer tscAnswer
	answerFound, err := tscCache.Load(fingerprint.AnswerKey, &answer)
	if err != nil {
		return tscStatLookup{}, err
	}
	if !answerFound {
		return tscStatLookup{status: tscStatMiss}, nil
	}
	return tscStatLookup{answer: answer, status: tscStatHit}, nil
}

func forgetToolVersion(program string) {
	toolVersionsMu.Lock()
	delete(toolVersions, program)
	toolVersionsMu.Unlock()
}

func storeStatFingerprintIfStable(identity, tscPaths []string, config string, listed []byte, before tscStatFingerprint, answerKey string, slowStarted time.Time, watchedDirs ...string) error {
	after, err := makeStatFingerprint(tscPaths, config, listed, "", watchedDirs...)
	if err != nil { //nolint:silent-error-handling // An input changed or disappeared during tsc, so the optimization must not be saved.
		return nil
	}
	if !sameStatFingerprint(before, after) {
		return nil
	}
	cutoff := slowStarted.Add(-time.Second).UnixNano()
	for _, saved := range append(append([]tscFileStat{}, after.Files...), after.Dirs...) {
		if saved.ModTimeNS >= cutoff {
			return nil
		}
	}
	after.AnswerKey = answerKey
	return tscCache.Store(statFingerprintKey(identity), after)
}

func storeProjectStatFingerprintIfStable(identity, tscPaths []string, config string, listed []byte, answer tscAnswer, slowStarted time.Time) error {
	after, err := makeStatFingerprint(tscPaths, config, listed, "")
	if err != nil { //nolint:silent-error-handling // An input changed or disappeared during tsc, so the optimization must not be saved.
		return nil
	}
	cutoff := slowStarted.Add(-time.Second).UnixNano()
	for _, saved := range append(append([]tscFileStat{}, after.Files...), after.Dirs...) {
		if saved.ModTimeNS >= cutoff {
			return nil
		}
	}
	after.Answer = &answer
	return tscCache.Store(statFingerprintKey(identity), after)
}

func sameStatFingerprint(left, right tscStatFingerprint) bool {
	if len(left.Files) != len(right.Files) || len(left.Dirs) != len(right.Dirs) {
		return false
	}
	for i := range left.Files {
		if left.Files[i] != right.Files[i] {
			return false
		}
	}
	for i := range left.Dirs {
		if left.Dirs[i] != right.Dirs[i] {
			return false
		}
	}
	return true
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
		return "", fmt.Errorf("read the file list of tsc: %w", err)
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
	diagnostics, _, err := tscDiagnosticsWithFiles(tsc, dir, args...)
	return diagnostics, err
}

func tscDiagnosticsWithFiles(tsc, dir string, args ...string) ([]tscDiagnostic, []byte, error) {
	cmd := exec.Command(tsc, args...)
	cmd.Dir = dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	runErr := cmd.Run()
	var exit *exec.ExitError
	if runErr != nil && !errors.As(runErr, &exit) {
		return nil, nil, fmt.Errorf("run %s: %w", tsc, runErr)
	}
	diagnostics := []tscDiagnostic{}
	var listed []byte
	continued := map[int][]string{} // diagnostic → the lines continuing its message
	for line := range strings.SplitSeq(stdout.String(), "\n") {
		line = strings.TrimRight(line, "\r")
		if m := tscFileDiagnostic.FindStringSubmatch(line); m != nil {
			file := m[1]
			if !filepath.IsAbs(file) {
				file = filepath.Join(dir, file)
			}
			lineNo, lerr := strconv.Atoi(m[2])
			column, cerr := strconv.Atoi(m[3])
			if err := errors.Join(lerr, cerr); err != nil {
				return nil, nil, fmt.Errorf("read tsc output %q: %w", line, err)
			}
			diagnostics = append(diagnostics, tscDiagnostic{File: file, Line: lineNo, Column: column, Code: m[4], Message: m[5]})
			continue
		}
		if m := tscGlobalDiagnostic.FindStringSubmatch(line); m != nil {
			diagnostics = append(diagnostics, tscDiagnostic{Code: m[1], Message: m[2]})
			continue
		}
		if line == strings.TrimSpace(line) && filepath.IsAbs(line) {
			listed = append(listed, line+"\n"...)
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
		return nil, nil, fmt.Errorf("%s failed without reporting an error: %w: %s", tsc, runErr, headOf(stdout.String()+stderr.String()))
	}
	return diagnostics, listed, nil
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
		return nil, fmt.Errorf("read the configuration tsc shows: %w", err)
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
