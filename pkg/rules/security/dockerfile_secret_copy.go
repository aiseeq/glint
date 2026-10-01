package security

import (
	"path"
	"regexp"
	"strings"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules"
)

func init() {
	rules.Register(NewDockerfileCopiesSecretFileRule())
}

// DockerfileCopiesSecretFileRule detects a secret file copied into an image:
//
//	COPY --chown=app:app .env /app/.env
//	ADD config/server.key /etc/ssl/private/
//
// A COPY or ADD bakes the file into a layer: anyone who can pull the image
// reads it, and removing it in a later layer leaves it in the earlier one.
// Secrets belong in the runtime environment, a mounted file or a build
// secret (RUN --mount=type=secret). A secret file is .env and .env.<stage>
// (not its .example, .sample, .template or .dist), a private key or
// keystore (.pem, .key, .p12, .pfx, .jks, .keystore), an SSH identity
// (id_rsa, id_ed25519, ...), credentials files, .npmrc, .pypirc, .netrc and
// secrets.yaml/json. A copy from another build stage (--from) is not from
// the build context and is left alone.
type DockerfileCopiesSecretFileRule struct {
	*rules.BaseRule
}

// NewDockerfileCopiesSecretFileRule creates the rule
func NewDockerfileCopiesSecretFileRule() *DockerfileCopiesSecretFileRule {
	return &DockerfileCopiesSecretFileRule{BaseRule: rules.NewBaseRule(
		"dockerfile-copies-secret-file",
		"security",
		"Detects a Dockerfile COPY/ADD of a secret file (.env, a private key, an SSH identity, credentials) into the image, where every layer keeps it",
		core.SeverityHigh,
	)}
}

var (
	dockerCopyInstruction = regexp.MustCompile(`(?i)^\s*(COPY|ADD)\s+(.*)$`)
	dockerSecretFile      = regexp.MustCompile(`(?i)^(?:\.env(?:\.[\w-]+)?|.+\.(?:pem|key|p12|pfx|jks|keystore)|id_(?:rsa|dsa|ecdsa|ed25519)|credentials(?:\.\w+)?|\.npmrc|\.pypirc|\.netrc|secrets?\.(?:ya?ml|json))$`)
	dockerSecretTemplate  = regexp.MustCompile(`(?i)\.(?:example|sample|template|dist|tmpl)$`)
)

// AnalyzeFile reports the COPY and ADD instructions of a Dockerfile whose
// sources include a secret file.
func (r *DockerfileCopiesSecretFileRule) AnalyzeFile(ctx *core.FileContext) []*core.Violation {
	if !ctx.IsDockerfile() {
		return nil
	}
	var violations []*core.Violation
	lines := ctx.Lines
	for i := 0; i < len(lines); i++ {
		start := i
		instruction := strings.TrimSpace(lines[i])
		// A trailing backslash continues the instruction on the next line.
		for strings.HasSuffix(instruction, `\`) && i+1 < len(lines) {
			i++
			instruction = strings.TrimSuffix(instruction, `\`) + " " + strings.TrimSpace(lines[i])
		}
		match := dockerCopyInstruction.FindStringSubmatch(instruction)
		if match == nil {
			continue
		}
		file, ok := copiedSecretFile(strings.Fields(match[2]))
		if !ok {
			continue
		}
		line := start + 1
		if ctx.IsSuppressed(line, r.Name()) {
			continue
		}
		v := r.CreateViolation(ctx.RelPath, line,
			"Secret file "+file+" is copied into the image — every layer keeps it, and anyone who can pull the image reads it")
		v.WithCode(strings.TrimSpace(lines[start]))
		v.WithSuggestion("Pass the secret at run time (environment, mounted file) or as a build secret (RUN --mount=type=secret), and list the file in .dockerignore")
		v.WithContext("pattern", "dockerfile_copies_secret_file")
		violations = append(violations, v)
	}
	return violations
}

// copiedSecretFile returns the first secret source of COPY/ADD arguments: all
// but the last, after the flags. A copy from a build stage has no context
// sources.
func copiedSecretFile(args []string) (string, bool) {
	var sources []string
	for _, arg := range args {
		if strings.HasPrefix(arg, "--") {
			if strings.HasPrefix(arg, "--from=") {
				return "", false
			}
			continue
		}
		sources = append(sources, strings.Trim(arg, `"[],`))
	}
	if len(sources) < 2 {
		return "", false
	}
	for _, src := range sources[:len(sources)-1] {
		base := path.Base(src)
		if dockerSecretFile.MatchString(base) && !dockerSecretTemplate.MatchString(base) {
			return base, true
		}
	}
	return "", false
}
