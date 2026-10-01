package patterns

import (
	"testing"

	"github.com/aiseeq/glint/pkg/core"
)

// The service reserves options "for later" and drops them; a security page
// passes a confirmation header that never reaches the server.
func TestTSParamIgnoredByMethod(t *testing.T) {
	service := core.NewFileContext("web/shared/lib/user-service.ts", ".", []byte(
		"export class UserService extends BaseApiService {\n"+ // 1
			"  async get(url: string, _options?: RequestInit, timeoutMs?: number): Promise<unknown> {\n"+ // 2
			"    return this.makeRequest(url, 'GET', {}, timeoutMs)\n"+ // 3
			"  }\n"+ // 4
			"  async post(url: string, data?: unknown, _options?: RequestInit, timeoutMs?: number): Promise<unknown> {\n"+ // 5
			"    return this.makeRequest(url, 'POST', data, timeoutMs)\n"+ // 6
			"  }\n"+ // 7
			"  async remove(url: string, _options?: RequestInit): Promise<unknown> {\n"+ // 8
			"    return this.makeRequest(url, 'DELETE')\n"+ // 9
			"  }\n"+ // 10
			"  render(_props: Record<string, number>, mode: string) {\n"+ // 11
			"    return mode\n"+ // 12
			"  }\n"+ // 13
			"  private sign(_payload: string) { return '' }\n"+ // 14
			"}\n"), nil)
	page := core.NewFileContext("web/app/src/security/page.tsx", ".", []byte(
		"await api.post('/security/action', body, { headers: { 'X-Confirm': code } })\n"+
			"await api.get('/me', undefined, 5000)\n"+
			"await api.remove('/session')\n"+
			"widget.render(props, 'full')\n"+
			"svc.sign(payload)\n"), nil)

	rule := NewTSParamIgnoredRule()
	rule.UseProjectFiles([]*core.FileContext{service, page})
	assertLines(t, rule.AnalyzeFile(service), []int{5, 11})
	assertLines(t, rule.AnalyzeFile(page), nil)
}
