package patterns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aiseeq/glint/pkg/rules/rulestest"
)

// A client that sends every method through one request function and repeats
// it after a 5xx or a dropped connection: a POST the server already executed
// behind a gateway timeout is sent a second time.
const retryNonIdempotentRecursiveSource = `export class ApiClient {
  private baseUrl = '/api'

  async request(path: string, method: string, body?: unknown, attempt = 0): Promise<unknown> {
    const maxRetries = 3
    try {
      const response = await fetch(this.baseUrl + path, {
        method,
        body: body ? JSON.stringify(body) : undefined,
      })
      if (!response.ok) throw new HttpError(response.status)
      return await response.json()
    } catch (error) {
      const status = error instanceof HttpError ? error.status : 0
      const text = String(error).toLowerCase()
      const shouldRetry =
        status === 502 || status === 503 || status === 504 ||
        text.includes('timeout') ||
        text.includes('network')

      if (shouldRetry && attempt < maxRetries) {
        await new Promise((resolve) => setTimeout(resolve, 500))
        return this.request(path, method, body, attempt + 1)
      }
      throw error
    }
  }
}
`

func TestHTTPClientRetriesNonIdempotent_Recursive(t *testing.T) {
	ctx := rulestest.TextFile(t, "lib/api-client.ts", retryNonIdempotentRecursiveSource)
	violations := NewHTTPClientRetriesNonIdempotentRule().AnalyzeFile(ctx)
	require.Len(t, violations, 1)
	assert.Equal(t, 17, violations[0].Line, "reported where the decision names the transient failure")
	assert.Contains(t, violations[0].Message, "request")
}

func TestHTTPClientRetriesNonIdempotent_NestedDecision(t *testing.T) {
	code := `export abstract class BaseService {
  protected async call(endpoint: string, httpMethod: string, retryCount = 0): Promise<unknown> {
    const controller = new AbortController()
    try {
      const res = await this.fetcher(endpoint, { method: httpMethod, signal: controller.signal })
      return res.json()
    } catch (error: unknown) {
      if (error instanceof Error && retryCount < 2) {
        const msg = error.message.toLowerCase()
        const isTransient = error.name === 'AbortError' ||
          msg.includes('network') ||
          msg.includes('503')

        if (isTransient) {
          return this.call(endpoint, httpMethod, retryCount + 1)
        }
      }
      throw error
    }
  }
}
`
	ctx := rulestest.TextFile(t, "lib/base-service.ts", code)
	violations := NewHTTPClientRetriesNonIdempotentRule().AnalyzeFile(ctx)
	require.Len(t, violations, 1)
	assert.Equal(t, 10, violations[0].Line)
}

func TestHTTPClientRetriesNonIdempotent_Loop(t *testing.T) {
	code := `export async function send(url: string, init: RequestInit): Promise<Response> {
  for (let attempt = 0; attempt < 3; attempt++) {
    const res = await fetch(url, { ...init, method: init.method })
    if (res.status >= 500) {
      await sleep(200 * attempt)
      continue
    }
    return res
  }
  throw new Error('gave up')
}
`
	ctx := rulestest.TextFile(t, "lib/send.ts", code)
	violations := NewHTTPClientRetriesNonIdempotentRule().AnalyzeFile(ctx)
	require.Len(t, violations, 1)
	assert.Equal(t, 4, violations[0].Line)
}

func TestHTTPClientRetriesNonIdempotent_Silent(t *testing.T) {
	tests := []struct {
		name string
		code string
	}{
		{
			// Post-fix shape: the decision asks whether the method is safe to repeat.
			name: "decision checks the method",
			code: `const IDEMPOTENT = new Set(['GET', 'HEAD', 'OPTIONS'])
export function isIdempotent(method: string): boolean { return IDEMPOTENT.has(method.toUpperCase()) }

export class ApiClient {
  async request(path: string, method: string, attempt = 0): Promise<unknown> {
    try {
      const response = await fetch(path, { method })
      return await response.json()
    } catch (error) {
      const status = error instanceof HttpError ? error.status : 0
      const transient = isIdempotent(method) && (status === 502 || status === 503)
      if (transient && attempt < 3) {
        return this.request(path, method, attempt + 1)
      }
      throw error
    }
  }
}
`,
		},
		{
			name: "early exit for unsafe methods",
			code: `export async function request(path: string, method: string, attempt = 0): Promise<Response> {
  try {
    return await fetch(path, { method })
  } catch (error) {
    if (method !== 'GET') throw error
    if (String(error).includes('network') && attempt < 3) {
      return request(path, method, attempt + 1)
    }
    throw error
  }
}
`,
		},
		{
			// No method anywhere: every request is a GET.
			name: "read-only helper",
			code: `export async function getJSON(url: string, attempt = 0): Promise<unknown> {
  try {
    const res = await fetch(url)
    return await res.json()
  } catch (error) {
    if (String(error).includes('timeout') && attempt < 3) {
      return getJSON(url, attempt + 1)
    }
    throw error
  }
}
`,
		},
		{
			// The request never reached the handler: the repeat is safe whatever the method.
			name: "retry on a refused token only",
			code: `export async function request(path: string, method: string, retryCount = 0): Promise<Response> {
  const res = await fetch(path, { method })
  if (res.status === 403 && res.headers.get('x-csrf') === 'missing' && retryCount < 1) {
    return request(path, method, retryCount + 1)
  }
  return res
}
`,
		},
		{
			// The attempt number only appears in the log line, nothing is sent again.
			name: "attempt in a log message",
			code: `export async function request(path: string, method: string, attempt: number): Promise<Response> {
  try {
    return await fetch(path, { method })
  } catch (error) {
    if (String(error).includes('network')) {
      logger.warn(` + "`" + `failed attempt ${attempt + 1}` + "`" + `)
    }
    throw error
  }
}
`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := rulestest.TextFile(t, "lib/client.ts", tt.code)
			assert.Empty(t, NewHTTPClientRetriesNonIdempotentRule().AnalyzeFile(ctx))
		})
	}
}
