package security

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aiseeq/glint/pkg/core"
)

// A secret file copied into an image becomes part of a layer: whoever can
// pull the image reads it, and deleting it in a later layer does not remove
// it. A template of the file, a copy from a build stage and ordinary sources
// are fine.
func TestDockerfileCopiesSecretFile(t *testing.T) {
	content := `FROM golang:1.24 AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY --chown=app:app .env /app/.env
ADD config/server.key /etc/ssl/private/
COPY .env.example /app/.env.example
COPY --from=build /out/app /app/app
copy deploy/id_rsa \
     /root/.ssh/id_rsa
COPY secrets.yaml /app/
RUN echo done
`
	assert.Equal(t, []int{4, 5, 8, 10}, textRuleLines(t, NewDockerfileCopiesSecretFileRule(), "deploy/Dockerfile", content))
	assert.Equal(t, []int{2}, textRuleLines(t, NewDockerfileCopiesSecretFileRule(), "api.dockerfile", "FROM alpine\nCOPY .env.production /app/\n"))
	assert.Empty(t, textRuleLines(t, NewDockerfileCopiesSecretFileRule(), "notes.md", "COPY .env /app/.env\n"))
}

// Dockerfiles are read by the walker under their conventional names.
func TestDockerfileNames(t *testing.T) {
	for name, want := range map[string]bool{
		"Dockerfile": true, "Dockerfile.prod": true, "api.dockerfile": true, "Containerfile": true,
		"dockerfile.md": false, "Dockerfiles.txt": false, "Dockerfile.dockerignore": false,
	} {
		ctx := core.NewFileContext("/src/"+name, "/src", nil, core.DefaultConfig())
		assert.Equal(t, want, ctx.IsDockerfile(), name)
	}
}
