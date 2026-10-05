package patterns

import (
	"go/ast"
	"go/token"
	"path"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewEnvKeyMissingFromDeployEnvRule())
	rules.Register(NewDockerfileHealthcheckLiteralPortRule())
	rules.Register(NewHostNetworkServiceBindsAllInterfacesRule())
}

// EnvKeyMissingFromDeployEnvRule detects an environment key the Go code
// reads that the deploy never puts into the server's env file:
//
//	printf "ANON_KEY=%s\nSERVICE_CLIENTS=%s\n" "$ANON_KEY" "$SERVICE_CLIENTS" > "$deploy_env"
//	// the code: os.Getenv("SERVICE_CLIENT_WRITES"), os.Getenv("CHAIN_RPC_PROVIDER")
//
// The server's env file comes from what the repository writes into it: a
// heredoc template (cat > .env << EOF) and the key lists a deploy sends
// (printf "KEY=%s\n..." > "$env_file"), plus the environment a compose file
// or a Dockerfile sets. A key the code reads with os.Getenv and none of them
// writes is empty on the server, and the integration it configures stays off
// there without an error. A key is reported when the project shows that it
// is needed: the env template of the repository (.env.example) lists it and
// does not call it optional or defaulted, or the deploy writes its siblings
// (SERVICE_CLIENTS next to SERVICE_CLIENT_WRITES); a key the example marks
// REQUIRED is reported too when the server template leaves it empty and the
// deploy that carries other keys does not carry it. Keys with a default in
// the code (getEnv("KEY", "x"), envDefault) and keys only tests read are not
// needed. A project whose deploy writes no env file is left alone.
type EnvKeyMissingFromDeployEnvRule struct {
	*rules.BaseRule
	// findings holds, per file path, the lines and keys to report.
	findings map[string][]envKeyFinding
}

type envKeyFinding struct {
	line   int
	key    string
	reason string
}

// NewEnvKeyMissingFromDeployEnvRule creates the rule
func NewEnvKeyMissingFromDeployEnvRule() *EnvKeyMissingFromDeployEnvRule {
	r := &EnvKeyMissingFromDeployEnvRule{BaseRule: rules.NewBaseRule(
		"env-key-missing-from-deploy-env",
		"patterns",
		"Detects an environment key the Go code reads and the env template lists that no deploy writer of the server's env file writes — the setting is empty on the server",
		core.SeverityMedium,
	)}
	r.ResetState()
	return r
}

// ResetState drops the root's findings.
func (r *EnvKeyMissingFromDeployEnvRule) ResetState() {
	r.findings = make(map[string][]envKeyFinding)
}

var (
	// envFileWriteTarget is an output redirection to a file whose name
	// speaks of an env file: > "$deploy_env", >> .env.prod, > "$ROOT/.env".
	envFileWriteTarget = regexp.MustCompile(`>>?\s*"?([^\s;|&"<>]+)"?`)
	envWordInName      = regexp.MustCompile(`(?i)(?:^|[^a-z])env(?:[^a-z]|$)`)
	printfFormat       = regexp.MustCompile(`\bprintf\s+(?:--\s+)?(?:"([^"]*)"|'([^']*)')`)
	echoAssignment     = regexp.MustCompile(`\becho\s+(?:-e\s+)?["']?([A-Z][A-Z0-9_]*)=`)
	formatKey          = regexp.MustCompile(`(?:^|\\n)([A-Z][A-Z0-9_]*)=`)
	heredocTeeTarget   = regexp.MustCompile(`\btee\s+(?:-\w+\s+)*"?([^\s"<>;|&-][^\s"<>;|&]*)"?`)
	heredocCatCommand  = regexp.MustCompile(`\bcat\b`)
	envAssignmentLine  = regexp.MustCompile(`^\s*(?:export\s+)?([A-Z][A-Z0-9_]*)=(.*)$`)
	envExampleRequired = regexp.MustCompile(`(?i)\brequired\b|обязател`)
	envExampleOptional = regexp.MustCompile(`(?i)optional|default|по умолчанию|необязат|опционал|пусто|empty|only (?:for|when|if)|только (?:для|при|если)|\bif set\b|\bunset\b|если`)
	composeEnvEntry    = regexp.MustCompile(`^\s*-\s*["']?([A-Za-z_][A-Za-z0-9_]*)=|^\s+([A-Za-z_][A-Za-z0-9_]*):\s`)
)

// envWriter is one place of the repository that writes keys into an env
// file of the server.
type envWriter struct {
	file string
	line int
	// keys maps a written key to whether its value is empty.
	keys map[string]bool
	// template is a heredoc filled in by hand on the server; a deploy writer
	// (printf, echo) carries values from the deploying machine.
	template bool
}

// envExampleKey is a key of the env template with its comment.
type envExampleKey struct {
	required, optional bool
}

// UseProjectFiles collects the writers, the reads and the env template of
// the root and computes the findings.
func (r *EnvKeyMissingFromDeployEnvRule) UseProjectFiles(files []*core.FileContext) {
	r.ResetState()
	var writers []envWriter
	provided := make(map[string]bool)
	reads := make(map[string]bool)
	example := make(map[string]envExampleKey)
	for _, ctx := range files {
		switch {
		case ctx.IsEnvTemplate():
			readEnvExample(ctx.Lines, example)
		case productionGoFile(ctx):
			for key := range goEnvReads(ctx.GoAST) {
				reads[key] = true
			}
		case ctx.IsShellFile() || ctx.IsMakefile():
			writers = append(writers, shellEnvWriters(ctx)...)
		case ctx.IsComposeFile():
			for _, key := range composeEnvKeys(ctx.Lines) {
				provided[key] = true
			}
		case ctx.IsDockerfile():
			for _, key := range dockerfileEnvKeys(ctx.Lines) {
				provided[key] = true
			}
		}
	}
	if len(writers) == 0 {
		return
	}
	filled := make(map[string]bool) // written with a value or by a deploy writer
	hasDeployWriter := false
	for _, w := range writers {
		hasDeployWriter = hasDeployWriter || !w.template
		for key, empty := range w.keys {
			provided[key] = true
			if !w.template || !empty {
				filled[key] = true
			}
		}
	}
	report := reportWriter(writers)
	keys := make([]string, 0, len(reads))
	for key := range reads {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		reason := missingEnvKeyReason(key, provided, filled, hasDeployWriter, example)
		if reason == "" {
			continue
		}
		r.findings[report.file] = append(r.findings[report.file], envKeyFinding{line: report.line, key: key, reason: reason})
	}
}

// missingEnvKeyReason tells why a key the code reads is needed on the server
// and missing there, "" when it is not.
func missingEnvKeyReason(key string, provided, filled map[string]bool, hasDeployWriter bool, example map[string]envExampleKey) string {
	ex, listed := example[key]
	if provided[key] {
		if hasDeployWriter && !filled[key] && listed && ex.required && !ex.optional {
			return "the env template marks it required, the server template leaves it empty, and the deploy does not carry it"
		}
		return ""
	}
	if listed && !ex.optional {
		return "the env template lists it, and nothing the deploy writes sets it"
	}
	if sibling := envKeySibling(key, provided); sibling != "" && !listed {
		return "the deploy writes " + sibling + " next to it, and not this key"
	}
	return ""
}

// envKeySibling returns a written key that shares the key's prefix of two
// words or more (SERVICE_CLIENT_ for SERVICE_CLIENT_WRITES).
func envKeySibling(key string, provided map[string]bool) string {
	cut := strings.LastIndex(key, "_")
	if cut <= 0 || !strings.Contains(key[:cut], "_") {
		return ""
	}
	prefix := key[:cut]
	var siblings []string
	for other := range provided {
		if other != key && (strings.HasPrefix(other, prefix+"_") || other == prefix+"S") {
			siblings = append(siblings, other)
		}
	}
	if len(siblings) == 0 {
		return ""
	}
	sort.Strings(siblings)
	return siblings[0]
}

// reportWriter picks the writer the findings go to: the deploy writer that
// carries the most keys, else the template that lists the most.
func reportWriter(writers []envWriter) envWriter {
	best := writers[0]
	for _, w := range writers[1:] {
		switch {
		case best.template && !w.template:
			best = w
		case best.template == w.template && len(w.keys) > len(best.keys):
			best = w
		}
	}
	return best
}

// AnalyzeFile reports the findings that belong to the file.
func (r *EnvKeyMissingFromDeployEnvRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	found := r.findings[ctx.RelPath]
	if len(found) == 0 {
		return nil
	}
	src, ok := readShell(ctx)
	if !ok {
		return nil
	}
	var out []*core.Violation
	for _, f := range found {
		out = appendReport(out, src.report(r, f.line,
			"The code reads "+f.key+": "+f.reason+" — the server has it only if someone adds it by hand",
			"Write "+f.key+" into the server's env file with the deploy, or give it a default in the code and mark it optional in the env template"))
	}
	return out
}

// readEnvExample records the keys of an env template with their comments:
// the one after the value and the comment lines right above.
func readEnvExample(lines []string, into map[string]envExampleKey) {
	var above []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			above = append(above, trimmed)
			continue
		}
		m := envAssignmentLine.FindStringSubmatch(line)
		if m == nil {
			above = nil
			continue
		}
		comment := strings.Join(above, " ")
		if i := strings.Index(m[2], "#"); i >= 0 {
			comment += " " + m[2][i:]
		}
		above = nil
		into[m[1]] = envExampleKey{
			required: envExampleRequired.MatchString(comment),
			optional: envExampleOptional.MatchString(comment),
		}
	}
}

// goEnvReads returns the keys a Go file reads without a default: the literal
// of os.Getenv, os.LookupEnv and syscall.Getenv, the only argument of a
// helper whose name speaks of env (mustEnv("KEY")), and an env struct tag
// without a default. A read the code lets be empty is not counted: one
// handed to a fallback helper with a literal (firstNonEmpty(os.Getenv("KEY"),
// "https://..."), cmp.Or), a flag compared with a literal (== "true"), and a
// value used only when set (if v := os.Getenv("KEY"); v != "" {...}).
func goEnvReads(file *ast.File) map[string]bool {
	keys := make(map[string]bool)
	defaulted := make(map[*ast.CallExpr]bool)
	ast.Inspect(file, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.BinaryExpr:
			markComparedRead(n, defaulted)
		case *ast.IfStmt:
			markGuardedRead(n, defaulted)
		case *ast.CallExpr:
			markDefaultedReads(n, defaulted)
			if key, ok := envReadCall(n); ok && !defaulted[n] {
				keys[key] = true
			}
		case *ast.Field:
			if key, ok := envStructTag(n); ok {
				keys[key] = true
			}
		}
		return true
	})
	return keys
}

// markComparedRead marks a read compared with a literal: os.Getenv("KEY") ==
// "true" is a flag that is off while the key is empty.
func markComparedRead(expr *ast.BinaryExpr, defaulted map[*ast.CallExpr]bool) {
	if expr.Op != token.EQL && expr.Op != token.NEQ {
		return
	}
	for _, pair := range [][2]ast.Expr{{expr.X, expr.Y}, {expr.Y, expr.X}} {
		call, ok := pair[0].(*ast.CallExpr)
		if _, lit := pair[1].(*ast.BasicLit); !ok || !lit {
			continue
		}
		if _, isRead := envReadCall(call); isRead {
			defaulted[call] = true
		}
	}
}

// markGuardedRead marks a read whose value the if statement uses only when
// it is set (v != ""), or replaces when it is empty (v == "" { v = ... }).
func markGuardedRead(stmt *ast.IfStmt, defaulted map[*ast.CallExpr]bool) {
	assign, ok := stmt.Init.(*ast.AssignStmt)
	if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
		return
	}
	name, ok := assign.Lhs[0].(*ast.Ident)
	call, isCall := assign.Rhs[0].(*ast.CallExpr)
	if !ok || !isCall {
		return
	}
	if _, isRead := envReadCall(call); !isRead {
		return
	}
	cond, ok := stmt.Cond.(*ast.BinaryExpr)
	if !ok || !comparesWithEmpty(cond, name.Name) {
		return
	}
	if cond.Op == token.NEQ || assignsTo(stmt.Body, name.Name) {
		defaulted[call] = true
	}
}

// comparesWithEmpty reports name == "" or name != "".
func comparesWithEmpty(cond *ast.BinaryExpr, name string) bool {
	if cond.Op != token.EQL && cond.Op != token.NEQ {
		return false
	}
	id, ok := cond.X.(*ast.Ident)
	lit, isLit := cond.Y.(*ast.BasicLit)
	return ok && isLit && id.Name == name && (lit.Value == `""` || lit.Value == "``")
}

// assignsTo reports an assignment to the name in the block.
func assignsTo(block *ast.BlockStmt, name string) bool {
	found := false
	ast.Inspect(block, func(n ast.Node) bool {
		if assign, ok := n.(*ast.AssignStmt); ok {
			for _, lhs := range assign.Lhs {
				if id, ok := lhs.(*ast.Ident); ok && id.Name == name {
					found = true
				}
			}
		}
		return !found
	})
	return found
}

// markDefaultedReads marks the env reads among the arguments of a fallback
// helper (cmp.Or, firstNonEmpty, withDefault) when another argument is a
// non-empty literal: the call falls back to it.
func markDefaultedReads(call *ast.CallExpr, defaulted map[*ast.CallExpr]bool) {
	var name string
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		name = fun.Name
	case *ast.SelectorExpr:
		name = fun.Sel.Name
	}
	if !fallbackHelperName.MatchString(name) {
		return
	}
	hasLiteral := false
	for _, arg := range call.Args {
		if lit, ok := arg.(*ast.BasicLit); ok && lit.Value != `""` && lit.Value != "``" {
			hasLiteral = true
		}
	}
	if !hasLiteral {
		return
	}
	for _, arg := range call.Args {
		if inner, ok := arg.(*ast.CallExpr); ok {
			if _, isRead := envReadCall(inner); isRead {
				defaulted[inner] = true
			}
		}
	}
}

var (
	envKeyLiteral      = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
	fallbackHelperName = regexp.MustCompile(`(?i)^or$|default|fallback|coalesce|nonempty|orelse`)
)

// envReadCall returns the key a call reads when it has no default.
func envReadCall(call *ast.CallExpr) (string, bool) {
	if len(call.Args) == 0 {
		return "", false
	}
	lit, ok := call.Args[0].(*ast.BasicLit)
	if !ok {
		return "", false
	}
	key, ok := goStringLiteral(lit)
	if !ok || !envKeyLiteral.MatchString(key) {
		return "", false
	}
	switch fun := call.Fun.(type) {
	case *ast.SelectorExpr:
		if pkg, ok := fun.X.(*ast.Ident); ok && (pkg.Name == "os" || pkg.Name == "syscall") {
			if fun.Sel.Name == "Getenv" || fun.Sel.Name == "LookupEnv" {
				return key, true
			}
			return "", false
		}
		return key, len(call.Args) == 1 && envGetterName(fun.Sel.Name)
	case *ast.Ident:
		return key, len(call.Args) == 1 && envGetterName(fun.Name)
	}
	return "", false
}

// envGetterName reports a helper that reads an env key: mustEnv,
// requireEnv, getEnv — not setEnv or unsetEnv.
func envGetterName(name string) bool {
	lower := strings.ToLower(name)
	return strings.Contains(lower, "env") && !strings.Contains(lower, "set")
}

// envStructTag returns the key of an env:"KEY" or envconfig:"KEY" tag
// without a default.
func envStructTag(field *ast.Field) (string, bool) {
	if field.Tag == nil {
		return "", false
	}
	raw, ok := goStringLiteral(field.Tag)
	if !ok {
		return "", false
	}
	tag := reflect.StructTag(raw)
	if _, ok := tag.Lookup("envDefault"); ok {
		return "", false
	}
	if _, ok := tag.Lookup("default"); ok {
		return "", false
	}
	for _, name := range []string{"env", "envconfig"} {
		value, ok := tag.Lookup(name)
		if !ok {
			continue
		}
		key, _, _ := strings.Cut(value, ",")
		if envKeyLiteral.MatchString(key) {
			return key, true
		}
	}
	return "", false
}

// shellEnvWriters returns the places of a script or a make file that write
// keys into an env file: heredoc templates and printf or echo lines
// redirected to a file named like an env file.
func shellEnvWriters(ctx *core.FileContext) []envWriter {
	var out []envWriter
	for _, doc := range heredocs(ctx.Lines) {
		if !envFileName(doc.target) {
			continue
		}
		w := envWriter{file: ctx.RelPath, line: doc.line, keys: make(map[string]bool), template: true}
		for _, line := range doc.body {
			if m := envAssignmentLine.FindStringSubmatch(line); m != nil {
				value := strings.TrimSpace(m[2])
				if i := strings.Index(value, "#"); i >= 0 {
					value = strings.TrimSpace(value[:i])
				}
				w.keys[m[1]] = value == "" || value == `""` || value == "''"
			}
		}
		if len(w.keys) > 0 {
			out = append(out, w)
		}
	}
	src, ok := readShell(ctx)
	if !ok {
		return out
	}
	for _, l := range src.lines {
		for _, seg := range flatSegments(l.text) {
			text := seg.trimmed()
			if !writesEnvFile(text) {
				continue
			}
			w := envWriter{file: ctx.RelPath, line: l.lineAt(seg.offset), keys: make(map[string]bool)}
			if m := printfFormat.FindStringSubmatch(text); m != nil {
				for _, k := range formatKey.FindAllStringSubmatch(m[1]+m[2], -1) {
					w.keys[k[1]] = false
				}
			} else if m := echoAssignment.FindStringSubmatch(text); m != nil {
				w.keys[m[1]] = false
			}
			if len(w.keys) > 0 {
				out = append(out, w)
			}
		}
	}
	return out
}

// writesEnvFile reports a command redirected to a file named like an env
// file: > "$deploy_env", >> .env.prod, > "$ENV_FILE"; the variables CI
// runners read back ($GITHUB_ENV) are not files of the server.
func writesEnvFile(command string) bool {
	for _, m := range envFileWriteTarget.FindAllStringSubmatch(command, -1) {
		target := m[1]
		if strings.Contains(target, "GITHUB_") {
			continue
		}
		if envWordInName.MatchString(path.Base(target)) {
			return true
		}
	}
	return false
}

// envFileName reports a path of an env file: .env, .env.<stage>, <name>.env
// — not the committed template.
func envFileName(target string) bool {
	base := path.Base(target)
	if strings.HasSuffix(base, ".example") || strings.HasSuffix(base, ".sample") || strings.HasSuffix(base, ".template") {
		return false
	}
	return base == ".env" || strings.HasPrefix(base, ".env.") || strings.HasSuffix(base, ".env")
}

// heredoc is the text a script feeds a command with << DELIM, with the file
// the command writes it to.
type heredoc struct {
	line   int // the line of the command
	target string
	body   []string
	// first is the line number of the first body line.
	first int
}

// heredocs returns the heredocs of a script that a command writes to a file:
// cat > file << EOF, tee file << EOF, cat << EOF > file.
func heredocs(lines []string) []heredoc {
	var out []heredoc
	for i := 0; i < len(lines); i++ {
		m := heredocStart.FindStringSubmatch(lines[i])
		if m == nil {
			continue
		}
		delim := m[1]
		doc := heredoc{line: i + 1, target: heredocTarget(lines[i]), first: i + 2}
		j := i + 1
		for ; j < len(lines) && strings.TrimSpace(lines[j]) != delim; j++ {
			doc.body = append(doc.body, lines[j])
		}
		out = append(out, doc)
		i = j
	}
	return out
}

// heredocTarget returns the file a heredoc command writes: the file of tee,
// or the redirection of cat; "" for any other command.
func heredocTarget(command string) string {
	if m := heredocTeeTarget.FindStringSubmatch(command); m != nil {
		return m[1]
	}
	if !heredocCatCommand.MatchString(command) {
		return ""
	}
	for _, m := range envFileWriteTarget.FindAllStringSubmatch(command, -1) {
		if m[1] != "/dev/null" {
			return m[1]
		}
	}
	return ""
}

// composeEnvKeys returns the keys the environment sections of a compose file
// set.
func composeEnvKeys(lines []string) []string {
	var keys []string
	for _, svc := range composeServices(lines) {
		for _, e := range svc.env {
			keys = append(keys, e.key)
		}
	}
	return keys
}

// dockerfileEnvKeys returns the keys the ENV instructions of a Dockerfile
// set.
func dockerfileEnvKeys(lines []string) []string {
	var keys []string
	for _, ins := range dockerInstructions(lines) {
		if ins.name != "ENV" {
			continue
		}
		for key := range dockerVariables(ins) {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys
}

// dockerInstruction is one instruction of a Dockerfile, its continuation
// lines joined.
type dockerInstruction struct {
	name string
	args string
	// lines are the physical lines the instruction spans, from the first.
	lines []int
	// texts are those lines.
	texts []string
}

var dockerInstructionStart = regexp.MustCompile(`^\s*([A-Za-z]+)\s+(.*)$`)

func dockerInstructions(lines []string) []dockerInstruction {
	var out []dockerInstruction
	for i := 0; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		m := dockerInstructionStart.FindStringSubmatch(lines[i])
		if m == nil {
			continue
		}
		ins := dockerInstruction{name: strings.ToUpper(m[1]), lines: []int{i + 1}, texts: []string{lines[i]}}
		first, more := strings.CutSuffix(strings.TrimRight(m[2], " \t"), "\\")
		var args strings.Builder
		args.WriteString(first)
		for more && i+1 < len(lines) {
			i++
			ins.lines = append(ins.lines, i+1)
			ins.texts = append(ins.texts, lines[i])
			var next string
			next, more = strings.CutSuffix(strings.TrimRight(lines[i], " \t"), "\\")
			args.WriteString(" " + strings.TrimSpace(next))
		}
		ins.args = args.String()
		out = append(out, ins)
	}
	return out
}

// DockerfileHealthcheckLiteralPortRule detects a HEALTHCHECK that spells the
// port the image declares as configurable:
//
//	ENV SERVER_PORT=8080
//	HEALTHCHECK CMD curl -f http://localhost:8080/api/health || exit 1
//
// The application listens on $SERVER_PORT; a deploy or a local run that
// sets another port leaves the check knocking on the old one, and the
// container stays unhealthy while it serves. The shell form of CMD expands
// the variable at run time: curl -f "http://localhost:${SERVER_PORT}/...".
type DockerfileHealthcheckLiteralPortRule struct {
	*rules.BaseRule
}

// NewDockerfileHealthcheckLiteralPortRule creates the rule
func NewDockerfileHealthcheckLiteralPortRule() *DockerfileHealthcheckLiteralPortRule {
	return &DockerfileHealthcheckLiteralPortRule{BaseRule: rules.NewBaseRule(
		"dockerfile-healthcheck-literal-port",
		"patterns",
		"Detects a Dockerfile HEALTHCHECK with a literal port equal to the default of an ENV/ARG *PORT the image declares — another port leaves the container unhealthy",
		core.SeverityMedium,
	)}
}

var (
	dockerPortName     = regexp.MustCompile(`(?i)(?:^|_)PORT$`)
	healthcheckAddress = regexp.MustCompile(`(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]):(\d+)\b`)
	dockerArgDefault   = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)=(\S+)`)
)

// AnalyzeFile reports the literal ports of the health checks of a Dockerfile.
func (r *DockerfileHealthcheckLiteralPortRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsDockerfile() {
		return nil
	}
	instructions := dockerInstructions(ctx.Lines)
	ports := make(map[string]string) // port value -> variable
	for _, ins := range instructions {
		for name, value := range dockerVariables(ins) {
			if dockerPortName.MatchString(name) {
				ports[value] = name
			}
		}
	}
	var out []*core.Violation
	for _, ins := range instructions {
		if ins.name != "HEALTHCHECK" {
			continue
		}
		for i, text := range ins.texts {
			for _, m := range healthcheckAddress.FindAllStringSubmatch(text, -1) {
				name, ok := ports[m[1]]
				if !ok {
					continue
				}
				line := ins.lines[i]
				if ctx.IsSuppressed(line, r.Name()) {
					continue
				}
				v := r.CreateViolation(ctx.RelPath, line,
					"The health check spells port "+m[1]+" while the image takes the port from "+name+" — with another port the container stays unhealthy")
				v.WithCode(strings.TrimSpace(text))
				v.WithSuggestion("Use the variable in the shell form of CMD: \"http://localhost:${" + name + "}/...\"")
				out = append(out, v)
			}
		}
	}
	return out
}

// dockerVariables returns the variables an ENV or ARG instruction sets with
// their values: ENV KEY=value KEY2=value, ENV KEY value, ARG KEY=default.
func dockerVariables(ins dockerInstruction) map[string]string {
	values := make(map[string]string)
	switch ins.name {
	case "ARG":
		if m := dockerArgDefault.FindStringSubmatch(strings.TrimSpace(ins.args)); m != nil {
			values[m[1]] = strings.Trim(m[2], `"'`)
		}
	case "ENV":
		fields := strings.Fields(ins.args)
		if len(fields) == 2 && !strings.Contains(fields[0], "=") {
			values[fields[0]] = strings.Trim(fields[1], `"'`)
			break
		}
		for _, f := range fields {
			if name, value, ok := strings.Cut(f, "="); ok {
				values[name] = strings.Trim(value, `"'`)
			}
		}
	}
	return values
}

// HostNetworkServiceBindsAllInterfacesRule detects a compose service on the
// host network that binds every interface while a reverse proxy on the same
// host fronts it:
//
//	services:
//	  app:
//	    network_mode: host
//	    environment:
//	      - SERVER_HOST=0.0.0.0
//
// With network_mode: host the container has the host's interfaces, so
// 0.0.0.0 publishes the application on the public address next to the proxy
// that was meant to be its only entrance: TLS, rate limits and access rules
// of the proxy are bypassed by going to the port directly. The proxy reaches
// the application on loopback (SERVER_HOST=127.0.0.1). A service on the
// bridge network has to bind 0.0.0.0 inside its own namespace and is left
// alone, and so is a host without a proxy that forwards to loopback.
type HostNetworkServiceBindsAllInterfacesRule struct {
	*rules.BaseRule
	// proxied is set when a file of the root forwards to a loopback address.
	proxied bool
}

// NewHostNetworkServiceBindsAllInterfacesRule creates the rule
func NewHostNetworkServiceBindsAllInterfacesRule() *HostNetworkServiceBindsAllInterfacesRule {
	return &HostNetworkServiceBindsAllInterfacesRule{BaseRule: rules.NewBaseRule(
		"host-network-service-binds-all-interfaces",
		"security",
		"Detects a compose service with network_mode: host that binds 0.0.0.0 while a reverse proxy on the host forwards to loopback — the application is reachable past the proxy",
		core.SeverityMedium,
	)}
}

var loopbackProxyPass = regexp.MustCompile(`\bproxy_pass\s+https?://(?:127\.0\.0\.1|localhost|\[::1\])\b`)

// UseProjectFiles looks for a proxy that forwards to loopback.
func (r *HostNetworkServiceBindsAllInterfacesRule) UseProjectFiles(files []*core.FileContext) {
	r.ResetState()
	for _, ctx := range files {
		if !strings.HasSuffix(ctx.Path, ".conf") && !ctx.IsShellFile() {
			continue
		}
		for _, line := range ctx.Lines {
			if loopbackProxyPass.MatchString(line) {
				r.proxied = true
				return
			}
		}
	}
}

// ResetState forgets the proxy.
func (r *HostNetworkServiceBindsAllInterfacesRule) ResetState() { r.proxied = false }

// AnalyzeFile reports the all-interface binds of host-network services in a
// compose file or in a compose file a script writes with a heredoc.
func (r *HostNetworkServiceBindsAllInterfacesRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !r.proxied {
		return nil
	}
	type composeText struct {
		lines []string
		first int // the file line of lines[0]
	}
	var texts []composeText
	switch {
	case ctx.IsComposeFile():
		texts = append(texts, composeText{lines: ctx.Lines, first: 1})
	case ctx.IsShellFile():
		for _, doc := range heredocs(ctx.Lines) {
			if core.IsComposeFileName(path.Base(doc.target)) {
				texts = append(texts, composeText{lines: doc.body, first: doc.first})
			}
		}
	default:
		return nil
	}
	var out []*core.Violation
	for _, text := range texts {
		for _, svc := range composeServices(text.lines) {
			if !svc.hostNetwork {
				continue
			}
			for _, e := range svc.env {
				if !allInterfacesBind(e.key, e.value) {
					continue
				}
				line := text.first + e.index
				if ctx.IsSuppressed(line, r.Name()) {
					continue
				}
				v := r.CreateViolation(ctx.RelPath, line,
					"Service "+svc.name+" runs on the host network and binds "+e.value+" — it listens on every interface of the host, past the reverse proxy")
				v.WithCode(strings.TrimSpace(text.lines[e.index]))
				v.WithSuggestion("Bind the loopback address the proxy forwards to: " + e.key + "=127.0.0.1")
				out = append(out, v)
			}
		}
	}
	return out
}

var bindKeyName = regexp.MustCompile(`(?i)(?:HOST|BIND|ADDR|ADDRESS|LISTEN)$`)

// allInterfacesBind reports a bind setting whose value is every interface:
// 0.0.0.0, 0.0.0.0:port, or :port for an address.
func allInterfacesBind(key, value string) bool {
	if !bindKeyName.MatchString(key) {
		return false
	}
	if value == "0.0.0.0" || strings.HasPrefix(value, "0.0.0.0:") {
		return true
	}
	_, err := strconv.Atoi(strings.TrimPrefix(value, ":"))
	return strings.HasPrefix(value, ":") && err == nil
}

// composeService is a service of a compose file read by its indentation.
type composeService struct {
	name        string
	hostNetwork bool
	env         []composeEnv
}

// composeEnv is an entry of a service's environment.
type composeEnv struct {
	key, value string
	index      int // the line in the text
}

var composeKeyLine = regexp.MustCompile(`^(\s*)([A-Za-z0-9_.-]+):\s*(.*)$`)

// composeServices reads the services of a compose file: their network mode
// and environment entries, in list (- KEY=value) or map (KEY: value) form.
func composeServices(lines []string) []composeService {
	var out []composeService
	servicesIndent, serviceIndent, envIndent := -1, -1, -1
	var cur *composeService
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		if servicesIndent >= 0 && indent <= servicesIndent {
			servicesIndent, serviceIndent, envIndent, cur = -1, -1, -1, nil
		}
		m := composeKeyLine.FindStringSubmatch(line)
		if servicesIndent < 0 {
			if m != nil && m[2] == "services" && m[3] == "" {
				servicesIndent = indent
			}
			continue
		}
		if serviceIndent < 0 || indent <= serviceIndent {
			if m != nil && m[3] == "" {
				serviceIndent = indent
				out = append(out, composeService{name: m[2]})
				cur = &out[len(out)-1]
				envIndent = -1
			}
			continue
		}
		if envIndent >= 0 && indent <= envIndent {
			envIndent = -1
		}
		if envIndent >= 0 {
			if e, ok := composeEnvLine(line, i); ok {
				cur.env = append(cur.env, e)
			}
			continue
		}
		if m == nil {
			continue
		}
		switch m[2] {
		case "network_mode":
			cur.hostNetwork = strings.Trim(m[3], `"'`) == "host"
		case "environment":
			envIndent = indent
		}
	}
	return out
}

// composeEnvLine reads one environment entry.
func composeEnvLine(line string, index int) (composeEnv, bool) {
	m := composeEnvEntry.FindStringSubmatch(line)
	if m == nil {
		return composeEnv{}, false
	}
	if m[1] != "" {
		_, value, _ := strings.Cut(strings.TrimSpace(line), "=")
		return composeEnv{key: m[1], value: strings.Trim(value, `"' `), index: index}, true
	}
	_, value, _ := strings.Cut(line, ":")
	return composeEnv{key: m[2], value: strings.Trim(strings.TrimSpace(value), `"'`), index: index}, true
}
