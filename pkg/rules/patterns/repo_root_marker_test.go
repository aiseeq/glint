package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// The helpers find the repository root by a marker file: after the Makefile
// was removed, the walk up from the e2e helpers never stops and the script
// guard refuses to run. A marker that exists (VERSION), a probe of an
// optional file, and a walk to the nearest package.json are fine.
func TestRepoRootMarkerFileMissing(t *testing.T) {
	root, _ := rulestest.Module(t, map[string]string{
		"VERSION":               "1.0.0\n",
		"build.yaml":            "tasks: {}\n",
		"frontend/package.json": "{}\n",
		"frontend/e2e/utils/repo-root.ts": `import { existsSync } from 'fs'
import path from 'path'

function findRepoRoot(start: string): string {
  let dir = start
  for (let depth = 0; depth < 10; depth++) {
    if (existsSync(path.join(dir, 'VERSION')) && existsSync(path.join(dir, 'Makefile'))) {
      return dir
    }
    dir = path.dirname(dir)
  }
  throw new Error('repository root not found')
}

function findPackage(start: string): string {
  let dir = start
  while (dir !== '/') {
    if (existsSync(path.join(dir, 'package.json'))) return dir
    dir = path.dirname(dir)
  }
  throw new Error('no package.json')
}

export function loadEnv(rootDir: string) {
  if (existsSync(path.join(rootDir, '.env.local'))) {
    return path.join(rootDir, '.env.local')
  }
  return ''
}
`,
		"frontend/scripts/check-types.js": `const fs = require('fs')
const path = require('path')
const projectRoot = path.resolve(__dirname, '../..')
if (!fs.existsSync(path.join(projectRoot, 'Makefile'))) {
  fail('must run inside the repository')
}
if (!fs.existsSync(path.join(projectRoot, 'build.yaml'))) {
  fail('must run inside the repository')
}
`,
	})
	contexts, errs := core.NewWalker(root, core.DefaultConfig()).WalkSync()
	require.Empty(t, errs)
	var violations []*core.Violation
	for _, ctx := range contexts {
		violations = append(violations, NewRepoRootMarkerFileMissingRule().AnalyzeFile(ctx)...)
	}
	assert.Equal(t, []string{"frontend/e2e/utils/repo-root.ts:7", "frontend/scripts/check-types.js:4"}, foundLines(violations))
}
