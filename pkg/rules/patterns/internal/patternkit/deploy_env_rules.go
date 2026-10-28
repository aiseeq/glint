package patternkit

import (
	"go/ast"
	"go/token"
	"regexp"
)

var (
	// EnvFileWriteTarget is an output redirection to a file whose name
	// speaks of an env file: > "$deploy_env", >> .env.prod, > "$ROOT/.env".
	EnvFileWriteTarget = regexp.MustCompile(`>>?\s*"?([^\s;|&"<>]+)"?`)
	EnvWordInName      = regexp.MustCompile(`(?i)(?:^|[^a-z])env(?:[^a-z]|$)`)
	PrintfFormat       = regexp.MustCompile(`\bprintf\s+(?:--\s+)?(?:"([^"]*)"|'([^']*)')`)
	EchoAssignment     = regexp.MustCompile(`\becho\s+(?:-e\s+)?["']?([A-Z][A-Z0-9_]*)=`)
	FormatKey          = regexp.MustCompile(`(?:^|\\n)([A-Z][A-Z0-9_]*)=`)
	HeredocTeeTarget   = regexp.MustCompile(`\btee\s+(?:-\w+\s+)*"?([^\s"<>;|&-][^\s"<>;|&]*)"?`)
	HeredocCatCommand  = regexp.MustCompile(`\bcat\b`)
	EnvAssignmentLine  = regexp.MustCompile(`^\s*(?:export\s+)?([A-Z][A-Z0-9_]*)=(.*)$`)
	EnvExampleRequired = regexp.MustCompile(`(?i)\brequired\b|обязател`)
	EnvExampleOptional = regexp.MustCompile(`(?i)optional|default|по умолчанию|необязат|опционал|пусто|empty|only (?:for|when|if)|только (?:для|при|если)|\bif set\b|\bunset\b|если|\btests? only\b|\bCI only\b`)
	ComposeEnvEntry    = regexp.MustCompile(`^\s*-\s*["']?([A-Za-z_][A-Za-z0-9_]*)=|^\s+([A-Za-z_][A-Za-z0-9_]*):\s`)
)

// ComparesWithEmpty reports name == "" or name != "".
func ComparesWithEmpty(cond *ast.BinaryExpr, name string) bool {
	if cond.Op != token.EQL && cond.Op != token.NEQ {
		return false
	}
	id, ok := cond.X.(*ast.Ident)
	lit, isLit := cond.Y.(*ast.BasicLit)
	return ok && isLit && id.Name == name && (lit.Value == `""` || lit.Value == "``")
}
