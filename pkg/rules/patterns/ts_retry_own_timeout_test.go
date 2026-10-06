package patterns

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// A request aborted by its own timer fails like a dropped connection: a
// retry on transport failures that does not ask whether the abort was its own
// waits the whole timeout again on every attempt.
func TestRetryAfterOwnTimeout(t *testing.T) {
	rule := retryAfterOwnTimeoutRule()
	source := `class Api {
  async makeRequest<T>(endpoint: string, method = 'GET', retryCount = 0): Promise<T> {
    const controller = new AbortController()
    const timeoutId = setTimeout(() => {
      controller.abort()
    }, 30000)
    try {
      const response = await fetchOrTransportError(this.fetchFunction, endpoint, { method, signal: controller.signal })
      clearTimeout(timeoutId)
      return await response.json()
    } catch (error: unknown) {
      clearTimeout(timeoutId)
      const status = error instanceof ApiError ? error.status : 0
      const isTransient = isIdempotentMethod(method) &&
        (isTransportError(error) || status === 502 || status === 503)
      if (isTransient && retryCount < 3) {
        return this.makeRequest<T>(endpoint, method, retryCount + 1)
      }
      throw error
    }
  }
}
`
	assert.Equal(t, []string{"src/api.ts:15"}, linesOf(t, rule, "src/api.ts", source))

	checked := strings.Replace(source, "const isTransient = isIdempotentMethod(method) &&",
		"const timedOut = controller.signal.aborted\n      const isTransient = isIdempotentMethod(method) && !timedOut &&", 1)
	assert.Empty(t, linesOf(t, rule, "src/api.ts", checked))

	once := strings.Replace(source, "return this.makeRequest<T>(endpoint, method, retryCount + 1)", "logger.warn('transient')", 1)
	assert.Empty(t, linesOf(t, rule, "src/api.ts", once))
}
