package frontendrules

import (
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aiseeq/glint/pkg/rules/patterns/internal/patterntest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// An import of a file that is not there yet is TS2307; once the file is
// written, as a generator writes an ignored file, the next run reports
// nothing, whether the import is relative or goes through a path alias and
// whether the directory of the file was there before or not.
func TestTscStatCacheMissingModuleAppears(t *testing.T) {
	for _, tc := range []struct {
		name    string
		config  string
		files   map[string]string
		missing string
	}{
		{
			name:   "relative import, directory present",
			config: strictTSConfig,
			files: map[string]string{
				"src/main.ts":          "import type { Order } from \"../shared/types/generated\"\nexport const o: Order | null = null\n",
				"shared/types/kept.ts": "export const kept = 1\n",
			},
			missing: "shared/types/generated.ts",
		},
		{
			name:   "relative import, directory absent",
			config: strictTSConfig,
			files: map[string]string{
				"src/main.ts": "import type { Order } from \"../shared/types/generated\"\nexport const o: Order | null = null\n",
			},
			missing: "shared/types/generated.ts",
		},
		{
			name: "path alias",
			config: `{
  "compilerOptions": {"strict": true, "module": "esnext", "moduleResolution": "bundler", "noEmit": true, "paths": {"@gen/*": ["./gen/*"]}},
  "include": ["src"],
}
`,
			files: map[string]string{
				"src/main.ts": "import type { Order } from \"@gen/types\"\nexport const o: Order | null = null\n",
			},
			missing: "gen/types.ts",
		},
		{
			name:   "path alias, directory present",
			config: strings.Replace(strictTSConfig, `"noEmit": true}`, `"noEmit": true, "paths": {"@gen/*": ["./gen/*"]}}`, 1),
			files: map[string]string{
				"src/main.ts": "import type { Order } from \"@gen/types\"\nexport const o: Order | null = null\n",
				"gen/kept.ts": "export const kept = 1\n",
			},
			missing: "gen/types.ts",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files := map[string]string{"tsconfig.json": tc.config}
			maps.Copy(files, tc.files)
			root, local, _ := countedTscProject(t, files)
			ageTscInputs(t, root, local)
			first := runCountedTsc(t, root)
			require.NotEmpty(t, first)
			assert.Contains(t, strings.Join(first, "\n"), "TS2307")
			patterntest.WriteProjectFile(t, root, tc.missing, "export type Order = { id: string }\n")
			assert.Empty(t, runCountedTsc(t, root))
		})
	}
}

// A run that already reports nothing keeps the cache: the fix does not
// turn every project with a resolved import into a slow run.
func TestTscStatCacheMissingModuleResolvedKeepsCache(t *testing.T) {
	root, local, log := countedTscProject(t, map[string]string{
		"tsconfig.json":             strictTSConfig,
		"src/main.ts":               "import type { Order } from \"../shared/types/generated\"\nexport const o: Order | null = null\n",
		"shared/types/generated.ts": "export type Order = { id: string }\n",
	})
	ageTscInputs(t, root, local)
	require.Empty(t, runCountedTsc(t, root))
	before := tscRunCount(t, log)
	require.Empty(t, runCountedTsc(t, root))
	assert.Equal(t, before, tscRunCount(t, log))
	_, err := os.Stat(filepath.Join(root, "shared/types/generated.ts"))
	require.NoError(t, err)
}
