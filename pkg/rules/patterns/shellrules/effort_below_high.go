package shellrules

import (
	"fmt"
	"go/ast"
	"go/token"
	"regexp"
	"strconv"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
	"github.com/aiseeq/glint/pkg/rules/helpers"
	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patternkit"
	"mvdan.cc/sh/v3/syntax"
)

func init() { rules.Register(NewEffortBelowHighRule()) }

// EffortBelowHighRule finds reasoning effort below high in model invocations,
// provider SDK requests, model settings, and model-related flag defaults.
type EffortBelowHighRule struct{ *rules.BaseRule }

// NewEffortBelowHighRule creates the rule.
func NewEffortBelowHighRule() *EffortBelowHighRule {
	return &EffortBelowHighRule{BaseRule: rules.NewBaseRule(
		"effort-below-high", "patterns",
		"Detects model reasoning effort set to low, medium, minimal or none in Go, TypeScript, JavaScript, shell and Make files, including CLI flags, model settings and SDK requests; codex exec without an explicit effort or profile may run below the required high. Text, comments and tests' data are not settings",
		core.SeverityHigh,
	)}
}

// AnalyzeFile reports model settings below the required reasoning effort.
func (r *EffortBelowHighRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !modelCodeFile(ctx) || !effortRelevant(ctx.Content) {
		return nil
	}
	lines := modelCodeLines(ctx)
	modelFile := hasModelContext(lines)
	flagValues := effortFlagDefaults(ctx)
	var settingValues, codexFindings, cliValues map[int]string
	if ctx.IsShellFile() || ctx.IsMakefile() {
		settingValues, codexFindings = shellFindings(ctx)
		if !modelFile {
			settingValues = map[int]string{}
		}
	} else {
		settingValues = settingFindings(ctx, modelFile)
		if ctx.IsGoFile() {
			codexFindings, cliValues = goLaunchFindings(ctx)
		} else {
			codexFindings, cliValues = jsLaunchFindings(lines)
		}
	}

	return analyzeModelCodeLinesFromLines(ctx, r, lines, func(line int, code string) *core.Violation {
		value, message := settingValues[line], ""
		if value == "" {
			value = flagValues[line]
		}
		if value == "" {
			value = cliValues[line]
		}
		if codexMessage := codexFindings[line]; codexMessage != "" {
			message = codexMessage
		}
		if value == "" && message == "" {
			return nil
		}
		if message == "" {
			message = fmt.Sprintf("Model reasoning effort %q is below the required high", value)
		}
		v := r.CreateViolation(ctx.RelPath, line, message)
		v.WithCode(ctx.GetLine(line))
		v.WithSuggestion("Set the model reasoning effort explicitly to high or higher")
		return v
	})
}

var (
	// All supported values are matched as complete tokens by the setting
	// helpers, so lowEffort and low_budget remain variables/other values.
	effortValuePattern        = regexp.MustCompile(`(?i)^(low|medium|minimal|none)$`)
	providerContextPattern    = regexp.MustCompile(`(?i)\b(?:claude|codex|opencode|anthropic|openai|reasoning)\b`)
	modelFamilyContextPattern = regexp.MustCompile(`(?i)(?:^|[^A-Za-z0-9_.])` + strings.Replace(modelFamily.String()[len(`(?i)^`):], `(?:$|[-.:_\d\[])`, `(?:$|[^A-Za-z0-9_])`, 1))
	effortCallPattern         = regexp.MustCompile(`(?i)\b(?:StringVarP?|StringP)\s*\(`)
	jsNullishPattern          = regexp.MustCompile("\\?\\?\\s*[\"'`](low|medium|minimal|none)[\"'`]")
	jsTypeDeclPattern         = regexp.MustCompile(`(?i)^\s*(?:export\s+)?(?:type|interface)\b`)
	jsArgvEffortPattern       = regexp.MustCompile(`(?i)\b(?:args|argv|options)\s*[:=]\s*\[[^\]]*['"]--effort['"][^\]]*['"](low|medium|minimal|none)['"]`)
)

// effortRelevant cheaply rejects files with no effort or codex references.
func effortRelevant(content []byte) bool {
	return containsFold(string(content), "effort") || containsFold(string(content), "codex")
}

// lineRelevant cheaply rejects lines before rule-specific parsing.
func lineRelevant(s string) bool {
	return containsFold(s, "effort") || containsFold(s, "codex")
}

// containsFold checks for an ASCII keyword without allocating a lowercased copy.
func containsFold(s, keyword string) bool {
	if len(keyword) == 0 || len(s) < len(keyword) {
		return len(keyword) == 0
	}
	for i := 0; i <= len(s)-len(keyword); i++ {
		matched := true
		for j := range keyword {
			a, b := s[i+j], keyword[j]
			if a >= 'A' && a <= 'Z' {
				a += 'a' - 'A'
			}
			if a != b {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	return false
}

// hasModelContext finds a model/provider marker anywhere in the source file.
func hasModelContext(lines []string) bool {
	for _, line := range lines {
		if !lineRelevant(line) && !modelContextHint(line) {
			continue
		}
		if providerContextPattern.MatchString(line) || modelFamilyContextPattern.MatchString(line) {
			return true
		}
	}
	return false
}

// modelContextHint cheaply identifies lines worth checking for model markers.
func modelContextHint(line string) bool {
	for _, hint := range []string{"claude", "opencode", "anthropic", "openai", "reasoning", "sonnet", "haiku", "opus", "fable", "gpt", "chatgpt", "gemini", "gemma", "llama", "mistral", "mixtral", "codestral", "qwen", "deepseek", "grok", "kimi", "glm", "luna", "sol", "o1", "o2", "o3", "o4", "o5", "o6", "o7", "o8", "o9"} {
		if containsFold(line, hint) {
			return true
		}
	}
	return false
}

// effortFlagDefaults reads defaults from effort-named command flags.
func effortFlagDefaults(ctx *core.FileContext) map[int]string {
	defaults := map[int]string{}
	if ctx.IsGoFile() && ctx.GoAST != nil {
		ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			name := ""
			switch f := call.Fun.(type) {
			case *ast.Ident:
				name = f.Name
			case *ast.SelectorExpr:
				name = f.Sel.Name
			}
			flagString := false
			if name == "String" {
				if selector, ok := call.Fun.(*ast.SelectorExpr); ok {
					if pkg, ok := selector.X.(*ast.Ident); ok && pkg.Name == "flag" {
						flagString = true
					}
				}
			}
			if (!effortCallPattern.MatchString(name+"(") && !flagString) || len(call.Args) == 0 {
				return true
			}
			nameIndex, valueIndex, valid := effortFlagArgIndexes(name)
			if !valid {
				return true
			}
			if nameIndex >= len(call.Args) || valueIndex >= len(call.Args) {
				return true
			}
			flag, _ := call.Args[nameIndex].(*ast.BasicLit)
			if flag == nil || flag.Kind != token.STRING {
				return true
			}
			flagName, err := strconv.Unquote(flag.Value)
			if err != nil || !strings.Contains(strings.ToLower(flagName), "effort") {
				return true
			}
			v, _ := call.Args[valueIndex].(*ast.BasicLit)
			if v != nil && v.Kind == token.STRING {
				s, e := strconv.Unquote(v.Value)
				if e == nil && effortValuePattern.MatchString(s) {
					defaults[ctx.GoFileSet.Position(v.Pos()).Line] = strings.ToLower(s)
				}
			}
			return true
		})
	}
	return defaults
}

// literalEffort returns a supported below-high literal value.
func literalEffort(s string) string {
	token, _ := unquoteToken(s)
	if effortValuePattern.MatchString(token) {
		return strings.ToLower(token)
	}
	return ""
}

// effortFlagArgIndexes returns the flag-name and default-value positions.
func effortFlagArgIndexes(name string) (int, int, bool) {
	switch strings.ToLower(name) {
	case "stringvar":
		return 1, 2, true
	case "stringvarp":
		return 1, 3, true
	case "stringp":
		return 0, 2, true
	case "string":
		return 0, 1, true
	default:
		return 0, 0, false
	}
}

// unquoteToken removes matching single, double, or backtick delimiters.
func unquoteToken(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if len(s) < 2 || !strings.ContainsRune("'\"`", rune(s[0])) || s[len(s)-1] != s[0] {
		return s, false
	}
	if s[0] == '"' {
		if decoded, err := strconv.Unquote(s); err == nil {
			return decoded, true
		}
	}
	return strings.ReplaceAll(strings.ReplaceAll(s[1:len(s)-1], `\'`, `'`), `\\`, `\`), true
}

// effortArgumentValue reads a literal --effort=value or --effort value pair.
func effortArgumentValue(arg, next string, nextLiteral bool) string {
	if value, ok := strings.CutPrefix(arg, "--effort="); ok {
		return literalEffort(value)
	}
	if arg == "--effort" && nextLiteral {
		return literalEffort(next)
	}
	return ""
}

// codexEffortMessage formats a low value or a codex invocation with no setting.
func codexEffortMessage(value string, explicit bool) string {
	if value != "" {
		return fmt.Sprintf("Model reasoning effort %q is below the required high", value)
	}
	if !explicit {
		return "codex exec without explicit effort; required effort is at least high"
	}
	return ""
}

// settingFindings dispatches model-setting analysis to the source language.
func settingFindings(ctx *core.FileContext, modelFile bool) map[int]string {
	if ctx.IsGoFile() {
		if modelFile {
			return goSettingFindings(ctx)
		}
		return map[int]string{}
	}
	if ctx.IsTypeScriptFile() || ctx.IsJavaScriptFile() {
		if !modelFile {
			return map[int]string{}
		}
		return jsSettingFindings(ctx)
	}
	return map[int]string{}
}

// goLaunchFindings inspects only Go AST process launches and their literal arguments.
func goLaunchFindings(ctx *core.FileContext) (map[int]string, map[int]string) {
	codex, cli := map[int]string{}, map[int]string{}
	if ctx.GoAST == nil || ctx.GoFileSet == nil {
		return codex, cli
	}
	ast.Inspect(ctx.GoAST, func(n ast.Node) bool {
		c, ok := n.(*ast.CallExpr)
		if ok {
			goLaunchCallFindings(ctx, c, codex, cli)
		}
		return true
	})
	return codex, cli
}

func goLaunchCallFindings(ctx *core.FileContext, call *ast.CallExpr, codex, cli map[int]string) {
	name := goCallName(call.Fun)
	if !strings.Contains(name, "Command") {
		return
	}
	values, literals := goCallArguments(call.Args)
	line := ctx.GoFileSet.Position(call.Pos()).Line
	if goCodexLaunchFinding(values, literals, line, codex) {
		return
	}
	goCLIlaunchFinding(values, literals, name, line, cli)
}

func goCallName(fun ast.Expr) string {
	switch f := fun.(type) {
	case *ast.SelectorExpr:
		return f.Sel.Name
	case *ast.Ident:
		return f.Name
	default:
		return ""
	}
}

func goCallArguments(args []ast.Expr) ([]string, []bool) {
	values, literals := make([]string, len(args)), make([]bool, len(args))
	for i, arg := range args {
		literal := arg
		if binary, ok := arg.(*ast.BinaryExpr); ok && binary.Op == token.ADD {
			literal = binary.X
		}
		basic, ok := literal.(*ast.BasicLit)
		if !ok || basic.Kind != token.STRING {
			continue
		}
		if value, err := strconv.Unquote(basic.Value); err == nil {
			values[i], literals[i] = value, true
		}
	}
	return values, literals
}

func goCodexLaunchFinding(values []string, literals []bool, line int, codex map[int]string) bool {
	start := -1
	for i, value := range values {
		if !literals[i] || (value != "codex" && value != "codex.exe") {
			continue
		}
		idx, sub := codexSubcommand(values, literals, i+1)
		if idx >= 0 && (sub == "exec" || sub == "e") {
			start = i + 1
			break
		}
	}
	if start < 0 {
		return false
	}
	if hasArg(values[start:], literals[start:], "--help") || hasArg(values[start:], literals[start:], "-h") {
		return true
	}
	value, explicit := shellCodexOptions(values, literals, start)
	if message := codexEffortMessage(value, explicit); message != "" {
		codex[line] = message
	}
	return false
}

func goCLIlaunchFinding(values []string, literals []bool, name string, line int, cli map[int]string) {
	commandIndex := 0
	if name == "CommandContext" {
		commandIndex = 1
	}
	if commandIndex >= len(values) || !literals[commandIndex] || !goCLICommand(values[commandIndex]) {
		return
	}
	for i, arg := range values {
		if !literals[i] {
			continue
		}
		var next string
		nextLiteral := i+1 < len(values) && literals[i+1]
		if nextLiteral {
			next = values[i+1]
		}
		if value := effortArgumentValue(arg, next, nextLiteral); value != "" {
			cli[line] = value
		}
	}
}

func goCLICommand(command string) bool {
	lower := strings.ToLower(command)
	return strings.EqualFold(command, "claude") || strings.EqualFold(command, "opencode") || strings.Contains(lower, "anthropic") || strings.Contains(lower, "openai")
}

var (
	jsEffortAssignForm = regexp.MustCompile(`(?i)\b([\w$]*effort[\w$]*)(?:\s*:\s*string)?\s*(?::=|=|\?=|\?\?)\s*["'` + "`" + `]?(low|medium|minimal|none)(?:[^A-Za-z0-9_$]|$)`)
	jsEffortObjectForm = regexp.MustCompile(`(?i)(?:^\s*|[,{]\s*)["']?([\w$]*effort[\w$]*)["']?\s*:\s*["'` + "`" + `]?(low|medium|minimal|none)(?:[^A-Za-z0-9_$]|$)`)
)

// jsSettingFindings reads setting forms from masked JavaScript and TypeScript.
func jsSettingFindings(ctx *core.FileContext) map[int]string {
	out := map[int]string{}
	code := helpers.FileJSCode(ctx)
	raw := ctx.Lines
	typeBody := jsTypeBodyLines(code)
	for i, line := range raw {
		if i >= len(code) || !lineRelevant(line) || typeBody[i] || jsTypeDeclPattern.MatchString(code[i]) {
			continue
		}
		masked := code[i]
		matches := jsEffortAssignForm.FindAllStringSubmatchIndex(line, -1)
		matches = append(matches, jsEffortObjectForm.FindAllStringSubmatchIndex(line, -1)...)
		for _, m := range matches {
			end := m[1]
			keyStart, keyEnd := m[2], m[3]
			key := strings.ToLower(line[keyStart:keyEnd])
			if !strings.Contains(key, "effort") {
				continue
			}
			if !jsSettingKeyInCode(line, masked, keyStart, keyEnd) {
				continue
			}
			value := line[m[4]:m[5]]
			// Type unions and comparisons are declarations/conditions, not settings.
			after := strings.TrimSpace(line[end:])
			if strings.HasPrefix(after, "|") || strings.HasPrefix(after, "==") || strings.HasPrefix(after, "!=") {
				continue
			}
			if effortValuePattern.MatchString(value) {
				out[i+1] = strings.ToLower(value)
			}
		}
		// Nullish fallback is a setting only when attached to an effort expression.
		if strings.Contains(masked, "??") {
			for _, m := range jsNullishPattern.FindAllStringSubmatch(line, -1) {
				if strings.Contains(strings.ToLower(masked), "effort") && effortValuePattern.MatchString(m[1]) {
					out[i+1] = strings.ToLower(m[1])
				}
			}
		}
	}
	return out
}

// jsSettingKeyInCode distinguishes a quoted property key from text in a string.
func jsSettingKeyInCode(raw, code string, start, end int) bool {
	if start > 0 && (raw[start-1] == '\'' || raw[start-1] == '"') {
		colon := end + 1
		for colon < len(code) && (code[colon] == ' ' || code[colon] == '\t') {
			colon++
		}
		return colon < len(code) && code[colon] == ':'
	}
	return strings.Contains(strings.ToLower(code[start:end]), "effort")
}

// jsTypeBodyLines marks TypeScript interface and type literal bodies in one pass.
func jsTypeBodyLines(code []string) []bool {
	marked := make([]bool, len(code))
	depth, pending := 0, false
	for i, line := range code {
		marked[i] = depth > 0
		if jsTypeDeclPattern.MatchString(line) {
			trim := strings.TrimSpace(line)
			pending = strings.Contains(trim, "interface") || strings.Contains(trim, "{") || strings.HasSuffix(trim, "=")
		}
		opens, closes := strings.Count(line, "{"), strings.Count(line, "}")
		if pending && opens == 0 && !strings.HasSuffix(strings.TrimSpace(line), "=") {
			pending = false
		}
		if pending && opens > 0 {
			depth, pending = opens-closes, false
		} else if depth > 0 {
			depth += opens - closes
		}
		if depth <= 0 {
			depth = 0
		}
	}
	return marked
}

// goSettingFindings visits Go AST setting nodes without rescanning source text.
func goSettingFindings(ctx *core.FileContext) map[int]string {
	out := map[int]string{}
	file := ctx.GoAST
	if file == nil || ctx.GoFileSet == nil {
		return out
	}
	ast.Inspect(file, func(n ast.Node) bool {
		if n == nil {
			return false
		}
		line := ctx.GoFileSet.Position(n.Pos()).Line
		switch x := n.(type) {
		case *ast.KeyValueExpr:
			goSettingKeyValue(x, line, out)
		case *ast.AssignStmt:
			goSettingAssignment(x, line, out)
		case *ast.ValueSpec:
			goSettingValueSpec(x, line, out)
		}
		return true
	})
	return out
}

func goSettingLiteral(expr ast.Expr) string {
	literal, ok := expr.(*ast.BasicLit)
	if !ok || literal.Kind != token.STRING {
		return ""
	}
	value, err := strconv.Unquote(literal.Value)
	if err != nil { //nolint:error-masking,silent-error-handling // Parsed string literals are valid; malformed AST data is ignored.
		return ""
	}
	if effortValuePattern.MatchString(value) {
		return strings.ToLower(value)
	}
	return ""
}

func goSettingKeyValue(expr *ast.KeyValueExpr, line int, out map[int]string) {
	key := ""
	switch value := expr.Key.(type) {
	case *ast.Ident:
		key = value.Name
	case *ast.BasicLit:
		if value.Kind == token.STRING {
			if unquoted, err := strconv.Unquote(value.Value); err == nil {
				key = unquoted
			}
		}
	}
	if strings.Contains(strings.ToLower(key), "effort") {
		if value := goSettingLiteral(expr.Value); value != "" {
			out[line] = value
		}
	}
}

func goSettingAssignment(assign *ast.AssignStmt, line int, out map[int]string) {
	for i, lhs := range assign.Lhs {
		name := ""
		switch value := lhs.(type) {
		case *ast.Ident:
			name = value.Name
		case *ast.SelectorExpr:
			name = value.Sel.Name
		}
		if strings.Contains(strings.ToLower(name), "effort") && i < len(assign.Rhs) {
			if value := goSettingLiteral(assign.Rhs[i]); value != "" {
				out[line] = value
			}
		}
	}
}

func goSettingValueSpec(spec *ast.ValueSpec, line int, out map[int]string) {
	if typ, ok := spec.Type.(*ast.Ident); ok && strings.Contains(strings.ToLower(typ.Name), "effort") {
		return
	}
	for i, name := range spec.Names {
		if strings.Contains(strings.ToLower(name.Name), "effort") && i < len(spec.Values) {
			if value := goSettingLiteral(spec.Values[i]); value != "" {
				out[line] = value
			}
		}
	}
}

// shellFindings parses each logical shell unit once for assignments and model commands.
func shellFindings(ctx *core.FileContext) (map[int]string, map[int]string) {
	settings, codex := map[int]string{}, map[int]string{}
	src, ok := patternkit.ReadShell(ctx)
	if !ok {
		return settings, codex
	}
	if src.Make {
		settings = makeEffortFindings(ctx.Lines)
	}
	for _, unit := range src.Units() {
		file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(unit.Text), ctx.Path)
		if err != nil { //nolint:silent-error-handling // Parse each logical unit independently; a malformed one must not hide later lines.
			continue
		}
		analyzeShellUnit(file, unit, settings, codex)
	}
	return settings, codex
}

func makeEffortFindings(lines []string) map[int]string {
	settings := map[int]string{}
	for i, line := range lines {
		if strings.Contains(line, "\t") {
			continue
		}
		trim := strings.TrimSpace(line)
		key, rhs, found := strings.Cut(trim, "?=")
		if !found {
			key, rhs, found = strings.Cut(trim, ":=")
		}
		if !found {
			key, rhs, _ = strings.Cut(trim, "=")
		}
		if strings.Contains(strings.ToLower(key), "effort") {
			if value := literalEffort(strings.TrimSpace(rhs)); value != "" {
				settings[i+1] = value
			}
		}
	}
	return settings
}

func analyzeShellUnit(file *syntax.File, unit patternkit.ShellLine, settings, codex map[int]string) {
	heredocParams, outputParams := shellExcludedParams(file)
	syntax.Walk(file, func(n syntax.Node) bool {
		if n == nil {
			return false
		}
		switch node := n.(type) {
		case *syntax.ParamExp:
			analyzeShellParam(node, unit, heredocParams, outputParams, settings)
		case *syntax.Assign:
			analyzeShellAssign(node, unit, settings)
		case *syntax.CallExpr:
			analyzeShellCall(node, unit, settings, codex)
		}
		return true
	})
}

func shellExcludedParams(file *syntax.File) (map[int]bool, map[int]bool) {
	heredocParams, outputParams := map[int]bool{}, map[int]bool{}
	syntax.Walk(file, func(n syntax.Node) bool {
		if call, ok := n.(*syntax.CallExpr); ok && len(call.Args) > 0 {
			name, literal := wordValue(call.Args[0])
			if literal && (name == "echo" || name == "printf") {
				for _, arg := range call.Args[1:] {
					syntax.Walk(arg, func(part syntax.Node) bool {
						if param, ok := part.(*syntax.ParamExp); ok {
							outputParams[int(param.Pos().Offset())] = true
						}
						return true
					})
				}
			}
		}
		redirect, ok := n.(*syntax.Redirect)
		if !ok || redirect.Hdoc == nil {
			return true
		}
		syntax.Walk(redirect.Hdoc, func(part syntax.Node) bool {
			if param, ok := part.(*syntax.ParamExp); ok {
				heredocParams[int(param.Pos().Offset())] = true
			}
			return true
		})
		return true
	})
	return heredocParams, outputParams
}

func analyzeShellParam(param *syntax.ParamExp, unit patternkit.ShellLine, heredocParams, outputParams map[int]bool, settings map[int]string) {
	if heredocParams[int(param.Pos().Offset())] || outputParams[int(param.Pos().Offset())] || param.Param == nil || !strings.Contains(strings.ToLower(param.Param.Value), "effort") || !isDefaultExpansion(param) || param.Exp.Word == nil {
		return
	}
	if value, literal := wordValue(param.Exp.Word); literal {
		if low := literalEffort(value); low != "" {
			settings[unit.LineAt(int(param.Pos().Offset()))] = low
		}
	}
}

func analyzeShellAssign(assign *syntax.Assign, unit patternkit.ShellLine, settings map[int]string) {
	if assign.Name != nil && strings.Contains(strings.ToLower(assign.Name.Value), "effort") && assign.Value != nil {
		if value, literal := wordValue(assign.Value); literal {
			if low := literalEffort(value); low != "" {
				settings[unit.LineAt(int(assign.Pos().Offset()))] = low
			}
		}
	}
	if assign.Value == nil || assign.Name == nil || !strings.Contains(strings.ToLower(assign.Name.Value), "effort") {
		return
	}
	syntax.Walk(assign.Value, func(child syntax.Node) bool {
		param, ok := child.(*syntax.ParamExp)
		if ok && isDefaultExpansion(param) && param.Exp.Word != nil {
			if value, literal := wordValue(param.Exp.Word); literal {
				if low := literalEffort(value); low != "" {
					settings[unit.LineAt(int(param.Pos().Offset()))] = low
				}
			}
		}
		return true
	})
}

func analyzeShellCall(call *syntax.CallExpr, unit patternkit.ShellLine, settings, codex map[int]string) {
	words, literals := shellCallWords(call)
	command := effortShellCommandIndex(call)
	if command < 0 || command >= len(words) {
		return
	}
	line := unit.LineAt(int(call.Pos().Offset()))
	if words[command] == "claude" || words[command] == "opencode" {
		shellCLIArguments(call, command, words, literals, line, settings)
	}
	if words[command] == "codex" {
		shellCodexArguments(words, literals, command, line, codex)
	}
}

func shellCallWords(call *syntax.CallExpr) ([]string, []bool) {
	words, literals := make([]string, len(call.Args)), make([]bool, len(call.Args))
	for i, arg := range call.Args {
		words[i], literals[i] = wordValue(arg)
	}
	return words, literals
}

func shellCLIArguments(call *syntax.CallExpr, command int, words []string, literals []bool, line int, settings map[int]string) {
	for i := command + 1; i < len(words); i++ {
		if !literals[i] {
			continue
		}
		nextLiteral := i+1 < len(words) && literals[i+1]
		next := ""
		if nextLiteral {
			next = words[i+1]
		}
		if low := effortArgumentValue(words[i], next, nextLiteral); low != "" {
			settings[line] = low
		} else if words[i] == "--effort" && i+1 < len(words) {
			if low := shellWordFallback(call.Args[i+1]); low != "" {
				settings[line] = low
			}
		}
	}
}

func shellCodexArguments(words []string, literals []bool, command, line int, codex map[int]string) {
	idx, sub := codexSubcommand(words, literals, command+1)
	if idx < 0 || (sub != "exec" && sub != "e") || hasArg(words[command+1:], literals[command+1:], "--help") || hasArg(words[command+1:], literals[command+1:], "-h") {
		return
	}
	value, explicit := shellCodexOptions(words, literals, command+1)
	if message := codexEffortMessage(value, explicit); message != "" {
		codex[line] = message
	}
}

// shellWordFallback returns a low default nested in a shell parameter expansion.
func shellWordFallback(word *syntax.Word) string {
	value := ""
	syntax.Walk(word, func(node syntax.Node) bool {
		p, ok := node.(*syntax.ParamExp)
		if ok && isDefaultExpansion(p) && p.Exp.Word != nil {
			if raw, literal := wordValue(p.Exp.Word); literal {
				if low := literalEffort(raw); low != "" {
					value = low
				}
			}
		}
		return true
	})
	return value
}

// isDefaultExpansion accepts only shell default and assignment operators.
func isDefaultExpansion(p *syntax.ParamExp) bool {
	if p.Exp == nil {
		return false
	}
	switch p.Exp.Op {
	case syntax.DefaultUnset, syntax.DefaultUnsetOrNull, syntax.AssignUnset, syntax.AssignUnsetOrNull:
		return true
	default:
		return false
	}
}

// effortShellCommandIndex follows wrappers to the model executable.
func effortShellCommandIndex(c *syntax.CallExpr) int {
	i := 0
	for i < len(c.Args) {
		w, lit := wordValue(c.Args[i])
		if !lit {
			return -1
		}
		if w == "claude" || w == "codex" || w == "opencode" {
			return i
		}
		if !wrapperName(w) {
			return -1
		}
		i++
		i = skipWrapperOptions(c.Args, i, w)
		if w == "timeout" && i < len(c.Args) {
			i++
		}
		if w == "env" {
			i = skipEnvAssignments(c.Args, i)
		}
	}
	return -1
}

func skipWrapperOptions(args []*syntax.Word, i int, wrapper string) int {
	for i < len(args) {
		arg, literal := wordValue(args[i])
		if !literal || !strings.HasPrefix(arg, "-") {
			break
		}
		i++
		if wrapperOptionTakesValue(wrapper, arg) && i < len(args) {
			i++
		}
	}
	return i
}

func skipEnvAssignments(args []*syntax.Word, i int) int {
	for i < len(args) {
		arg, literal := wordValue(args[i])
		if !literal || !isAssignmentWord(arg) {
			break
		}
		i++
	}
	return i
}

// jsLaunchFindings inspects process launches and their literal command arguments.
func jsLaunchFindings(lines []string) (map[int]string, map[int]string) {
	codex, cli := map[int]string{}, map[int]string{}
	for i, line := range lines {
		if !lineRelevant(line) {
			continue
		}
		if m := jsArgvEffortPattern.FindStringSubmatch(line); m != nil && effortValuePattern.MatchString(m[1]) {
			cli[i+1] = strings.ToLower(m[1])
		}
	}
	joined := strings.Join(lines, "\n")
	lastOffset, line := 0, 1
	for _, loc := range processLaunch.FindAllStringIndex(joined, -1) {
		open := loc[1] - 1
		args, end := scanCallArgs(joined, open)
		if end < 0 || len(args) < 2 {
			continue
		}
		line += strings.Count(joined[lastOffset:loc[0]], "\n")
		lastOffset = loc[0]
		command, ok := jsStringValue(args[0])
		if !ok {
			continue
		}
		argv := []string{}
		literals := []bool{}
		for _, arg := range args[1:] {
			trim := strings.TrimSpace(arg)
			if strings.HasPrefix(trim, "[") {
				for _, token := range jsLiteralPattern.FindAllStringSubmatch(trim, -1) {
					value, _ := unquoteToken(token[0])
					argv = append(argv, value)
					literals = append(literals, true)
				}
			} else if value, literal := jsStringValue(trim); literal {
				argv = append(argv, value)
				literals = append(literals, true)
			} else {
				argv = append(argv, "")
				literals = append(literals, false)
			}
		}
		name := strings.ToLower(command)
		if name == "codex" || name == "codex.exe" {
			idx, sub := codexSubcommand(argv, literals, 0)
			if idx >= 0 && (sub == "exec" || sub == "e") && !hasArg(argv, literals, "--help") && !hasArg(argv, literals, "-h") {
				value, explicit := shellCodexOptions(argv, literals, 0)
				if message := codexEffortMessage(value, explicit); message != "" {
					codex[line] = message
				}
			}
		}
		if name == "claude" || name == "opencode" || strings.Contains(name, "anthropic") || strings.Contains(name, "openai") {
			for i, arg := range argv {
				var next string
				nextLiteral := i+1 < len(argv) && literals[i+1]
				if nextLiteral {
					next = argv[i+1]
				}
				if value := effortArgumentValue(arg, next, nextLiteral); value != "" {
					cli[line] = value
				}
			}
		}
	}
	return codex, cli
}

var jsLiteralPattern = regexp.MustCompile(`'(?:\\.|[^'\\])*'|"(?:\\.|[^"\\])*"|` + "`(?:\\\\.|[^`\\\\])*`")

// scanCallArgs splits one JavaScript call while respecting nested delimiters
// and quoted strings; it returns the closing parenthesis offset.
func scanCallArgs(source string, open int) ([]string, int) {
	args := []string{}
	start, depth := open+1, 0
	var quote byte
	for i := open + 1; i < len(source); i++ {
		c := source[i]
		if quote != 0 {
			switch c {
			case '\\':
				i++
			case quote:
				quote = 0
			}
			continue
		}
		switch c {
		case '\'', '"', '`':
			quote = c
			continue
		case '(', '[', '{':
			depth++
		case ')':
			if depth == 0 {
				args = append(args, strings.TrimSpace(source[start:i]))
				return args, i
			}
			depth--
		case ']', '}':
			depth--
		case ',':
			if depth == 0 {
				args = append(args, strings.TrimSpace(source[start:i]))
				start = i + 1
			}
		}
	}
	return nil, -1
}

// jsStringValue decodes one quoted JavaScript string literal.
func jsStringValue(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if len(s) < 2 || !strings.ContainsRune("'\"`", rune(s[0])) || s[len(s)-1] != s[0] {
		return "", false
	}
	value, quoted := unquoteToken(s)
	return value, quoted
}

// wrapperName reports shell utilities that can precede a model executable.
func wrapperName(s string) bool {
	switch s {
	case "sudo", "nice", "xargs", "timeout", "env", "nohup", "command", "exec":
		return true
	}
	return false
}

// wrapperOptionTakesValue reports wrapper options that consume the next word.
func wrapperOptionTakesValue(cmd, opt string) bool {
	switch cmd {
	case "timeout":
		return opt == "-k" || opt == "--kill-after" || opt == "-s" || opt == "--signal"
	case "sudo":
		return opt == "-u" || opt == "-g" || opt == "-h" || opt == "-p" || opt == "-C" || opt == "-D"
	case "nice":
		return opt == "-n"
	case "xargs":
		return opt == "-I" || opt == "-i" || opt == "-n" || opt == "-s" || opt == "-d" || opt == "-P" || opt == "-L" || opt == "-a"
	case "env":
		return opt == "-u" || opt == "--unset" || opt == "-C" || opt == "--chdir"
	}
	return false
}

// isAssignmentWord recognizes a shell-style NAME=value word.
func isAssignmentWord(s string) bool {
	p := strings.SplitN(s, "=", 2)
	return len(p) == 2 && p[0] != "" && !strings.ContainsAny(p[0], " /\t")
}

// codexSubcommand finds exec/e while skipping codex global options.
func codexSubcommand(w []string, lit []bool, start int) (int, string) {
	for i := start; i < len(w); i++ {
		if !lit[i] {
			return -1, ""
		}
		a := w[i]
		if a == "exec" || a == "e" {
			return i, a
		}
		if a == "--" {
			return -1, ""
		}
		if strings.HasPrefix(a, "-") {
			if (a == "-c" || a == "--config" || a == "-a" || a == "--ask-for-approval" || a == "--model" || a == "-m" || a == "-p" || a == "--profile") && i+1 < len(w) {
				i++
			}
			continue
		}
		return -1, ""
	}
	return -1, ""
}

// shellCodexOptions reports low effort and explicit profile/config options.
func shellCodexOptions(w []string, lit []bool, start int) (string, bool) {
	explicit := false
	for i := start; i < len(w); i++ {
		if !lit[i] {
			continue
		}
		a := w[i]
		if a == "-p" || a == "--profile" {
			explicit = true
			if i+1 < len(w) {
				i++
			}
			continue
		}
		if strings.HasPrefix(a, "--profile=") {
			explicit = true
			continue
		}
		if a == "-c" || a == "--config" {
			if i+1 < len(w) {
				if !lit[i+1] {
					explicit = true
					i++
					continue
				}
				v := w[i+1]
				if strings.HasPrefix(strings.ToLower(v), "model_reasoning_effort=") {
					explicit = true
					effort := strings.SplitN(v, "=", 2)[1]
					if effortValuePattern.MatchString(strings.Trim(effort, "\"'")) {
						return strings.ToLower(strings.Trim(effort, "\"'")), true
					}
				}
				i++
				continue
			}
			continue
		}
		if strings.HasPrefix(a, "-cmodel_reasoning_effort=") {
			v := strings.SplitN(a, "=", 2)[1]
			if effortValuePattern.MatchString(strings.Trim(v, "\"'")) {
				return strings.ToLower(strings.Trim(v, "\"'")), true
			}
			return "", true
		}
		if strings.HasPrefix(a, "--config=") || strings.HasPrefix(a, "-c=") {
			config := strings.SplitN(a, "=", 2)[1]
			if strings.HasPrefix(strings.ToLower(config), "model_reasoning_effort=") {
				v := strings.SplitN(config, "=", 2)[1]
				if low := literalEffort(v); low != "" {
					return low, true
				}
				return "", true
			}
		}
	}
	return "", explicit
}

// hasArg reports whether literal arguments contain a target token.
func hasArg(w []string, lit []bool, target string) bool {
	for i, s := range w {
		if i < len(lit) && lit[i] && s == target {
			return true
		}
	}
	return false
}
