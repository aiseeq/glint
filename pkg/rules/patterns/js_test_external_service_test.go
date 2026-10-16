package patterns

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/core"
)

// jsLiveFindings runs the rule on one test file of a project with the given
// .env content ("" for none) and returns the lines it reports.
func jsLiveFindings(t *testing.T, rel, code, env string) []int {
	t.Helper()
	root := t.TempDir()
	if env != "" {
		require.NoError(t, os.WriteFile(filepath.Join(root, ".env"), []byte(env), 0o600))
	}
	ctx := core.NewFileContext(filepath.Join(root, rel), root, []byte(code), nil)
	var lines []int
	for _, v := range NewJSTestExternalServiceRule().AnalyzeFile(ctx) {
		lines = append(lines, v.Line)
	}
	return lines
}

// A jest suite ran npm audit, which asks the npm registry, on every run: the
// command sits in a method of a helper class of the test file.
func TestJSTestExternalServiceCommand(t *testing.T) {
	code := `import { exec, spawn } from 'child_process'
import { promisify } from 'util'
const execAsync = promisify(exec)

class Scanner {
  async audit() {
    await execAsync('npm audit --audit-level moderate --json', { cwd: root })
  }
}

test('audit', async () => { await new Scanner().audit() })
test('feed', () => { spawn('curl', ['-s', 'https://feed.vendor.io/x']) })
test('lint', async () => { await execAsync('npm run lint') })
test('local', () => { spawn('curl', ['http://localhost:8080/health']) })
`
	assert.Equal(t, []int{7, 12}, jsLiveFindings(t, "frontend/src/__tests__/security/scan.test.ts", code, ""))
}

// fetch, axios and a playwright request on a third-party address reach it;
// a local address, a relative path and a mocked transport do not.
func TestJSTestExternalServiceHTTP(t *testing.T) {
	code := `test('rates', async () => {
  const res = await fetch('https://api.ratesbank.io/v1/daily')
  const r2 = await axios.get('https://api.ratesbank.io/v1/x')
  await request.get('https://api.ratesbank.io/v1/y')
  await fetch('http://localhost:3000/api/rates')
  await fetch('/api/rates')
  await fetch('https://example.com/doc')
})
`
	assert.Equal(t, []int{2, 3, 4}, jsLiveFindings(t, "src/rates.test.ts", code, ""))

	for name, mock := range map[string]string{
		"msw":         "const server = setupServer(http.get('https://api.ratesbank.io/v1/daily', () => HttpResponse.json({})))\n",
		"nock":        "nock('https://api.ratesbank.io').get('/v1/daily').reply(200, {})\n",
		"jest spy":    "jest.spyOn(global, 'fetch').mockResolvedValue(new Response('{}'))\n",
		"jest module": "jest.mock('axios')\nglobal.fetch = jest.fn()\n",
	} {
		assert.Empty(t, jsLiveFindings(t, "src/rates.test.ts", mock+code, ""), name)
	}
	assert.Empty(t, jsLiveFindings(t, "src/scan.test.ts", "jest.mock('child_process')\ntest('a', async () => { await execAsync('npm audit') })\n", ""))
	assert.Empty(t, jsLiveFindings(t, "src/rates.ts", code, ""), "not a test file")
}

// A test that skips at once unless a dedicated env flag is set is an explicit
// opt-in, as in Go: the calls the gate covers are not reported. A flag the
// project's .env sets is open in every run and covers nothing.
func TestJSTestExternalServiceEnvFlag(t *testing.T) {
	call := "  await fetch('https://api.ratesbank.io/v1/daily')\n"
	gated := map[string]string{
		"vitest skipIf":    "describe.skipIf(!process.env.RATES_LIVE)('live', () => {\n test('x', async () => {\n" + call + " })\n})\n",
		"vitest runIf":     "describe.runIf(process.env.RATES_LIVE === '1')('live', () => {\n test('x', async () => {\n" + call + " })\n})\n",
		"ternary alias":    "const liveDescribe = process.env.RATES_LIVE ? describe : describe.skip\nliveDescribe('live', () => {\n test('x', async () => {\n" + call + " })\n})\n",
		"playwright skip":  "test('x', async () => {\n  test.skip(!process.env.RATES_LIVE, 'live only')\n" + call + "})\n",
		"early return":     "test('x', async () => {\n  if (!process.env.RATES_LIVE) {\n    return\n  }\n" + call + "})\n",
		"value comparison": "test('x', async () => {\n  test.skip(process.env.RATES_LIVE !== '1', 'live only')\n" + call + "})\n",
		"flag constant":    "const LIVE = process.env['RATES_LIVE'] === '1'\ntest.describe('live', () => {\n  test.skip(!LIVE,\n    'live only')\n  test('x', async ({ request }) => {\n" + call + "  })\n})\n",
		"bracket access":   "test('x', async () => {\n  test.skip(!process.env[\"RATES_LIVE\"], 'live only')\n" + call + "})\n",
	}
	for name, code := range gated {
		assert.Empty(t, jsLiveFindings(t, "src/rates.test.ts", code, ""), name)
		assert.Len(t, jsLiveFindings(t, "src/rates.test.ts", code, "RATES_LIVE=1\n"), 1, "%s: a flag the .env sets", name)
	}

	// The gate covers its own block: a test next to the gated one still runs.
	code := "test('gated', async () => {\n  test.skip(!process.env.RATES_LIVE, 'live')\n" + call + "})\ntest('open', async () => {\n" + call + "})\n"
	assert.Equal(t, []int{6}, jsLiveFindings(t, "src/rates.test.ts", code, ""))
	// A skip when a variable is set (CI) runs in every other environment.
	assert.Len(t, jsLiveFindings(t, "src/rates.test.ts", "test('x', async () => {\n  if (process.env.CI) return\n"+call+"})\n", ""), 1)
}
